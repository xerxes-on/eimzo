# xerxes/eimzo

Reusable PHP 8.2+ package for **headless E-IMZO certificate signing on Linux**. No Laravel, banking panel, browser or running desktop app is required by the native backend.

The package contains PHP code, a small Java bridge and a pinned runtime installer. The installer downloads the official E-IMZO 6.4.7 provider files; vendor JARs are not distributed in this repository. Java runs briefly for each signing operation and then exits. No signing server or listening port is created.

## Install

Install from [Packagist](https://packagist.org/packages/xerxes/eimzo):

```sh
composer require xerxes/eimzo:^0.1
```

Install PHP's Sodium extension and a Java JDK (Java 17 recommended for Linux). Runtime setup needs `bash`, `curl`, `sha256sum`, `tar`, and `javac`:

```sh
# Debian/Ubuntu; use your deployment's normal package provisioning.
sudo apt-get install openjdk-17-jdk-headless curl ca-certificates
bash vendor/xerxes/eimzo/runtime/install.sh /absolute/application/storage/eimzo-runtime
```

Use a destination writable by the deployment user. Keep the installed runtime read-only for the application user. The installer refuses an existing destination and verifies the official archive's pinned SHA-256 before extracting it. Install future versions into a new directory, test, then change configuration. Runtime binaries are external vendor dependencies, not covered by this repository's MIT license; see [THIRD_PARTY.md](THIRD_PARTY.md).

### Downloading from Uzbekistan for a server abroad

The official archive download succeeded from a machine in Uzbekistan, while GitHub-hosted runners timed out connecting to `dls.soliq.uz`. Regional or cloud-IP filtering is suspected, but an Uzbekistan-only policy has not been confirmed. If your server cannot connect, use a machine in Uzbekistan with working access to download the archive, then transfer it to your server:

```sh
# On the machine in Uzbekistan:
curl --fail --location --proto '=https' --connect-timeout 30 --max-time 180 \
  https://dls.soliq.uz/v6.4.7/E-IMZO-v6.4.7.tar.gz \
  -o E-IMZO-v6.4.7.tar.gz
scp E-IMZO-v6.4.7.tar.gz deploy@your-server:/secure/official/

# On your server, after installing the prerequisites above:
bash vendor/xerxes/eimzo/runtime/install.sh \
  /absolute/application/storage/eimzo-runtime \
  /secure/official/E-IMZO-v6.4.7.tar.gz
```

Replace the example host and paths with your deployment values; create the transfer destination first. The installer applies the same mandatory pinned checksum verification to a local archive. Your signing server does not need to be in Uzbekistan: signing runs fully offline after provider installation.

## Certificate and password

Keep these in your application's protected environment or secret manager:

```dotenv
EIMZO_VAULT_KEY=base64-of-32-random-bytes
EIMZO_KEY_PASSWORD=your-certificate-password
EIMZO_NATIVE_RUNTIME=/absolute/application/storage/eimzo-runtime
```

The vault master key is a separate deployment secret. Generate it once using `base64_encode(random_bytes(32))`, store it securely and back it up separately from the encrypted certificate files. Never commit real values. This package does not load `.env` itself; use your framework's configuration loader or export the variables securely.

```php
use Xerxes\Eimzo\CertificateVault;
use Xerxes\Eimzo\NativeSigner;
use Xerxes\Eimzo\Password;

$vault = new CertificateVault(
    '/absolute/application/storage/private/eimzo',
    getenv('EIMZO_VAULT_KEY') ?: '',
);

// One-time provisioning; refuses to overwrite an existing identity.
$pfx = file_get_contents('/secure/certificate.pfx');
$vault->store('company', $pfx);
sodium_memzero($pfx);

$signer = new NativeSigner(
    vault: $vault,
    password: Password::fromEnvironment(),
    runtimeDirectory: getenv('EIMZO_NATIVE_RUNTIME') ?: '',
);
$pkcs7 = $signer->sign('company', $documentBytes); // Base64 PKCS#7/CMS, attached.
$detached = $signer->sign('company', $documentBytes, detached: true);
```

For frameworks with cached configuration, pass `new Password($configuredSecret)` instead of reading the environment at runtime. `NativeSigner` and `OpenSslSigner` implement `Xerxes\Eimzo\Signer`.

The native signer decrypts the vault in memory and sends the PFX, password and content to the JVM through stdin. Secrets do not appear in command arguments or temporary files. The process does not inherit application secrets or JVM injection environment variables. Input, output, heap and execution time are bounded. Each generated signature is cryptographically verified against its certificate and input before it is returned. Multiple private-key entries require an explicit `alias` constructor argument.

Only file-based certificates are covered by this backend. USB tokens, smartcards and remote HSMs need their own integration. Certificate validity dates are checked; trust chains, revocation, timestamping and relying-party acceptance are separate concerns. An E-IMZO signature is not automatically a banking-panel signature.

## Other backends

`OpenSslSigner($vault, $password)` supports OpenSSL-compatible PKCS#12 files and returns base64 DER CMS. It works with the synthetic RSA fixtures. The tested O'zDSt certificate could not be opened by OpenSSL; use `NativeSigner` for that certificate. There is no silent backend fallback.

`DesktopClient` remains available for integrations with an already running E-IMZO desktop app:

```php
$desktop = new Xerxes\Eimzo\DesktopClient();
$version = $desktop->version();
$certificates = $desktop->certificates();
$pkcs7 = $desktop->sign($disk, $path, $name, $alias, $documentBytes);
```

Desktop signing uses `pfx.load_key`, `pkcs7.create_pkcs7`, and `pfx.unload_key`, with password prompting handled by that app. The default socket is `ws://127.0.0.1:64646/service/cryptapi`. Only numeric loopback addresses are accepted. Desktop and native provider backends are independent; the native backend needs no socket.

## Storage and operational security

- Vault encryption: XChaCha20-Poly1305, random nonce, certificate identity authenticated with the ciphertext.
- Absolute private storage path, no symbolic links, directory `0700`, files `0600`; trusted parent directories are required.
- Maximum certificate and content size: 4 MiB each. Imports never overwrite; rotate by importing a new identity.
- Keep vaults outside the web root and public disks. Restrict environment/config-cache permissions. Do not log tokens, PFX bytes, passwords, signing content or returned signatures.
- The optional OpenSSL backend uses private temporary content/output files and reports cleanup failures; private keys stay in memory. Abrupt process termination can interrupt filesystem cleanup.
- Native signing uses a pinned vendor provider API rather than an official headless SDK. Re-test provider upgrades. The Composer audit does not audit vendor JARs.

## Verification

The native backend was tested in Linux Docker with Java 8 and Java 17 using an authorized real `OZDST-1092-2009-2` certificate. Attached and detached diagnostic signatures verified successfully, with networking disabled and no desktop application. No real certificate, signature fixture, password or identity metadata is included in the repository. No bank/payment request was involved.

```sh
composer install
composer check
composer audit
```

Automatic CI runs Composer validation, formatting, static analysis, PHP tests and dependency audits on PHP 8.2–8.4. It excludes native provider installation and signing tests because the official download host is unreachable from the tested GitHub runners. A green CI run therefore does not establish native provider compatibility.

Default tests use synthetic certificate data only. Optional native integration tests use a generated RSA certificate when `EIMZO_NATIVE_RUNTIME` points to an installed provider. Run these locally before releasing changes to the Java bridge, provider installer or native signer.

To run the full native test suite in Linux Docker without downloading the provider during the build:

```sh
cp /secure/official/E-IMZO-v6.4.7.tar.gz ./runtime/E-IMZO-v6.4.7.tar.gz
docker build -t eimzo-test .
docker run --rm --network none eimzo-test
```

This is the official software archive, not your certificate. It is checksum-verified and excluded from the source repository. Keep images containing vendor libraries private unless their distribution is permitted by the vendor.

References: [official E-IMZO downloads](https://e-imzo.soliq.uz/download/), [E-IMZO integration documentation](https://github.com/qo0p/e-imzo-doc), [PHP CMS signing](https://www.php.net/manual/en/function.openssl-cms-sign.php).
