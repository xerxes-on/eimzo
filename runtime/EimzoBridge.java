import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import uz.eimzo.pkcs12.reader.PKCS12Reader;
import uz.yt.cams.us.common.pki.DocumentSigner;
import uz.yt.pkix.jcajce.cms.YTSimpleSignerInfoVerifierBuilder;
import uz.yt.pkix.jcajce.provider.YTProvider;

/** One-shot local bridge. Secrets arrive only through stdin, never arguments or files. */
public final class EimzoBridge {
    private static final int LIMIT = 4194304;

    public static void main(String[] args) {
        ObjectMapper mapper = new ObjectMapper();
        char[] password = null;
        byte[] pfx = null;
        byte[] content = null;
        String phase = "INVALID_INPUT";
        int exitCode = 0;
        try {
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = System.in.read(buffer)) != -1) {
                if (input.size() + read > 12582912) throw new IllegalArgumentException();
                input.write(buffer, 0, read);
            }
            Arrays.fill(buffer, (byte) 0);
            JsonNode request = mapper.readTree(input.toByteArray());
            pfx = Base64.getDecoder().decode(request.required("pfx").asText());
            content = Base64.getDecoder().decode(request.required("content").asText());
            password = request.required("password").asText().toCharArray();
            boolean detached = request.path("detached").asBoolean(false);
            if (pfx.length == 0 || pfx.length > LIMIT || content.length > LIMIT || password.length == 0) {
                throw new IllegalArgumentException();
            }
            BouncyCastleProvider provider = new BouncyCastleProvider();
            YTProvider.configure(provider);
            Security.addProvider(provider);
            phase = "KEY_LOAD_FAILED";
            KeyStore store = loadKeyStore(pfx, password, provider);
            List<String> aliases = new ArrayList<String>();
            Enumeration<String> entries = store.aliases();
            while (entries.hasMoreElements()) {
                String alias = entries.nextElement();
                if (store.isKeyEntry(alias)) aliases.add(alias);
            }
            phase = "CERTIFICATE_SELECTION_FAILED";
            String selected = request.path("alias").asText("");
            if (selected.isEmpty() && aliases.size() == 1) selected = aliases.get(0);
            if (!aliases.contains(selected)) throw new IllegalArgumentException();
            PrivateKey key = (PrivateKey) store.getKey(selected, password);
            Certificate[] certificates = store.getCertificateChain(selected);
            if (certificates == null || certificates.length == 0) throw new IllegalArgumentException();
            X509Certificate[] chain = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);
            phase = "CERTIFICATE_EXPIRED_OR_NOT_YET_VALID";
            chain[0].checkValidity();
            phase = "SIGNING_FAILED";
            byte[] signature = sign(provider, chain, key, content, detached);
            phase = "SIGNATURE_VERIFICATION_FAILED";
            CMSSignedData signed = detached
                ? new CMSSignedData(new CMSProcessableByteArray(content), signature)
                : new CMSSignedData(signature);
            if (!Arrays.equals(content, (byte[]) signed.getSignedContent().getContent())
                    || signed.getSignerInfos().size() != 1) throw new IllegalStateException();
            for (Object item : signed.getSignerInfos().getSigners()) {
                SignerInformation signer = (SignerInformation) item;
                if (!signer.verify(new YTSimpleSignerInfoVerifierBuilder().setProvider(provider).build(chain[0]))) {
                    throw new IllegalStateException();
                }
            }
            ObjectNode result = mapper.createObjectNode();
            result.put("pkcs7_64", Base64.getEncoder().encodeToString(signature));
            result.put("verified", true);
            result.put("algorithm", key.getAlgorithm());
            result.put("certificate_sha256", Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded())));
            System.out.println(mapper.writeValueAsString(result));
        } catch (Exception | LinkageError failure) {
            // Never print provider exceptions: they may contain certificate aliases or key material.
            System.out.println("{\"error\":\"" + phase + "\"}");
            exitCode = 2;
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (pfx != null) Arrays.fill(pfx, (byte) 0);
            if (content != null) Arrays.fill(content, (byte) 0);
        }
        System.exit(exitCode);
    }

    private static KeyStore loadKeyStore(byte[] pfx, char[] password, BouncyCastleProvider provider) throws Exception {
        // Modern standard PFX encryption may require the JDK loader; national keys require YT.
        KeyStore[] loaders = {KeyStore.getInstance("PKCS12"), KeyStore.getInstance("PKCS12", provider)};
        for (KeyStore store : loaders) {
            try {
                store.load(new ByteArrayInputStream(pfx), password);
                Enumeration<String> entries = store.aliases();
                while (entries.hasMoreElements()) {
                    String alias = entries.nextElement();
                    // Loading metadata alone is insufficient: the loader must decode the actual key.
                    if (store.isKeyEntry(alias)) store.getKey(alias, password);
                }
                return store;
            } catch (Exception unsupportedEncoding) {
                // Continue to the next container reader using the same password and signing provider.
            }
        }
        return new PKCS12Reader(provider).convert(new ByteArrayInputStream(pfx), password);
    }

    private static byte[] sign(BouncyCastleProvider provider, X509Certificate[] chain, PrivateKey key,
            byte[] content, boolean detached) throws Exception {
        if (!"RSA".equalsIgnoreCase(key.getAlgorithm())) {
            return new DocumentSigner(provider, chain, key).getPkcs7(content, !detached);
        }
        // The vendor's default signature-name table covers national algorithms, not RSA.
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(provider).build()).build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(key), chain[0]));
        generator.addCertificates(new JcaCertStore(Arrays.asList(chain)));
        return generator.generate(new CMSProcessableByteArray(content), !detached).getEncoded();
    }
}
