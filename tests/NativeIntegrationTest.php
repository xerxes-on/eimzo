<?php

declare(strict_types=1);

namespace Xerxes\Eimzo\Tests;

use PHPUnit\Framework\TestCase;
use Xerxes\Eimzo\CertificateVault;
use Xerxes\Eimzo\NativeSigner;
use Xerxes\Eimzo\Password;

final class NativeIntegrationTest extends TestCase
{
    public function testNativeRsaSignatureVerifiesIndependentlyWithOpenSsl(): void
    {
        $runtime = getenv('EIMZO_NATIVE_RUNTIME');
        if (!$runtime) {
            self::markTestSkipped('Set EIMZO_NATIVE_RUNTIME for the optional provider integration test.');
        }
        $directory = realpath(sys_get_temp_dir()).'/eimzo-native-rsa-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        try {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            $csr = openssl_csr_new(['commonName' => 'Synthetic native integration test'], $key);
            $certificate = openssl_csr_sign($csr, null, $key, 1);
            openssl_pkcs12_export($certificate, $pfx, $key, 'synthetic-password', ['friendly_name' => 'synthetic']);
            $vault = new CertificateVault($directory.'/vault', base64_encode(random_bytes(32)));
            $vault->store('synthetic', $pfx);
            $signer = new NativeSigner($vault, new Password('synthetic-password'), $runtime);
            $signature = $signer->sign('synthetic', "binary\0message");
            file_put_contents($directory.'/signature', base64_decode($signature, true));
            self::assertTrue(openssl_cms_verify(
                $directory.'/signature',
                OPENSSL_CMS_NOVERIFY | OPENSSL_CMS_BINARY,
                null,
                [],
                null,
                $directory.'/verified',
                null,
                null,
                OPENSSL_ENCODING_DER
            ));
            self::assertSame("binary\0message", file_get_contents($directory.'/verified'));
            self::assertNotEmpty($signer->sign('synthetic', "binary\0message", true));
        } finally {
            foreach (glob($directory.'/vault/*') ?: [] as $file) {
                unlink($file);
            }
            if (is_dir($directory.'/vault')) {
                rmdir($directory.'/vault');
            }
            foreach (glob($directory.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($directory);
        }
    }
}
