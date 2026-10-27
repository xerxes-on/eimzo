<?php

declare(strict_types=1);

namespace Xerxes\Eimzo\Tests;

use PHPUnit\Framework\TestCase;
use Xerxes\Eimzo\CertificateVault;
use Xerxes\Eimzo\DesktopClient;
use Xerxes\Eimzo\EimzoException;
use Xerxes\Eimzo\OpenSslSigner;
use Xerxes\Eimzo\Password;
use Xerxes\Eimzo\Rpc;

final class EimzoTest extends TestCase
{
    private string $directory;
    private string $key;

    protected function setUp(): void
    {
        $this->directory = realpath(sys_get_temp_dir()).'/eimzo-test-'.bin2hex(random_bytes(8));
        $this->key = base64_encode(random_bytes(32));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory.'/*') ?: [] as $file) {
            unlink($file);
        }
        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }
    }

    public function testVaultEncryptsAuthenticatesAndUsesPrivatePermissions(): void
    {
        $vault = new CertificateVault($this->directory, $this->key);
        $vault->store('main', 'synthetic-certificate-bytes');
        $blob = file_get_contents($this->directory.'/main.vault');
        self::assertStringNotContainsString('synthetic-certificate-bytes', $blob);
        self::assertSame('synthetic-certificate-bytes', $vault->read('main'));
        self::assertSame(0700, fileperms($this->directory) & 0777);
        self::assertSame(0600, fileperms($this->directory.'/main.vault') & 0777);
        $blob[strlen($blob) - 1] = chr(ord($blob[strlen($blob) - 1]) ^ 1);
        file_put_contents($this->directory.'/main.vault', $blob);
        $this->expectException(EimzoException::class);
        $vault->read('main');
    }

    public function testVaultRejectsWrongMasterKey(): void
    {
        (new CertificateVault($this->directory, $this->key))->store('main', 'pfx');
        $this->expectException(EimzoException::class);
        (new CertificateVault($this->directory, base64_encode(random_bytes(32))))->read('main');
    }

    public function testVaultBindsIdentityToCiphertext(): void
    {
        $vault = new CertificateVault($this->directory, $this->key);
        $vault->store('one', 'pfx');
        rename($this->directory.'/one.vault', $this->directory.'/two.vault');
        $this->expectException(EimzoException::class);
        $vault->read('two');
    }

    public function testImportCannotOverwriteAnExistingIdentity(): void
    {
        $vault = new CertificateVault($this->directory, $this->key);
        $vault->store('one', 'first');
        try {
            $vault->store('one', 'second');
            self::fail();
        } catch (EimzoException) {
        }
        self::assertSame('first', $vault->read('one'));
        self::assertSame([], glob($this->directory.'/.*.tmp'));
    }

    public function testTraversalAndLinksAreRejected(): void
    {
        $vault = new CertificateVault($this->directory, $this->key);
        try {
            $vault->store('../escaped', 'pfx');
            self::fail();
        } catch (EimzoException) {
        }
        $vault->store('one', 'pfx');
        symlink($this->directory.'/one.vault', $this->directory.'/two.vault');
        $this->expectException(EimzoException::class);
        $vault->read('two');
    }

    public function testUnsafePermissionsFailClosed(): void
    {
        $vault = new CertificateVault($this->directory, $this->key);
        $vault->store('one', 'pfx');
        chmod($this->directory.'/one.vault', 0644);
        $this->expectException(EimzoException::class);
        $vault->read('one');
    }

    public function testPasswordDoesNotLeakThroughDebugOrSerialization(): void
    {
        putenv('TEST_EIMZO_PASSWORD=test-secret');
        try {
            $password = Password::fromEnvironment('TEST_EIMZO_PASSWORD');
            self::assertSame('test-secret', $password->reveal());
            self::assertStringNotContainsString('test-secret', print_r($password, true));
            $this->expectException(EimzoException::class);
            serialize($password);
        } finally {
            putenv('TEST_EIMZO_PASSWORD');
        }
    }

    public function testDesktopUsesDocumentedArgumentsAndUnloadsKey(): void
    {
        $calls = [];
        $rpc = $this->createMock(Rpc::class);
        $rpc->expects(self::exactly(3))->method('call')->willReturnCallback(function ($request) use (&$calls) {
            $calls[] = $request;
            return match ($request['name']) {
                'load_key' => ['success' => true, 'keyId' => 'test-id'],
                'create_pkcs7' => ['success' => true, 'pkcs7_64' => 'signature'],
                'unload_key' => ['success' => true],
            };
        });
        self::assertSame('signature', (new DesktopClient($rpc))->sign('disk', '', 'name', 'alias', "abc\0", true));
        self::assertSame([base64_encode("abc\0"), 'test-id', 'yes'], $calls[1]['arguments']);
        self::assertSame(['test-id'], $calls[2]['arguments']);
    }

    public function testDesktopUnloadsKeyWhenSigningFails(): void
    {
        $rpc = $this->createMock(Rpc::class);
        $calls = [];
        $rpc->method('call')->willReturnCallback(function ($request) use (&$calls) {
            $calls[] = $request['name'];
            if ($request['name'] === 'create_pkcs7') {
                throw new EimzoException('cancelled');
            }
            return ['success' => true, 'keyId' => 'id'];
        });
        try {
            (new DesktopClient($rpc))->sign('disk', '', 'name', 'alias', 'text');
            self::fail();
        } catch (EimzoException) {
            self::assertSame(['load_key', 'create_pkcs7', 'unload_key'], $calls);
        }
    }

    public function testOpenSslSignsSyntheticCertificateAndCleansTemporaryFiles(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL not installed.');
        }
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'Offline test only'], $private);
        $cert = openssl_csr_sign($csr, null, $private, 1);
        openssl_pkcs12_export($cert, $pfx, $private, 'test-password');
        $vault = new CertificateVault($this->directory, $this->key);
        $vault->store('test', $pfx);
        $before = glob(realpath(sys_get_temp_dir()).'/eimzo-*');
        $signature = (new OpenSslSigner($vault, new Password('test-password')))->sign('test', 'offline payload');
        self::assertSame($before, glob(realpath(sys_get_temp_dir()).'/eimzo-*'));
        file_put_contents($this->directory.'/signed.der', base64_decode($signature, true));
        self::assertTrue(openssl_cms_verify(
            $this->directory.'/signed.der',
            OPENSSL_CMS_NOVERIFY | OPENSSL_CMS_BINARY,
            null,
            [],
            null,
            $this->directory.'/verified',
            null,
            null,
            OPENSSL_ENCODING_DER
        ));
        self::assertSame('offline payload', file_get_contents($this->directory.'/verified'));
        try {
            (new OpenSslSigner($vault, new Password('wrong')))->sign('test', 'data');
            self::fail();
        } catch (EimzoException) {
            self::assertSame($before, glob(realpath(sys_get_temp_dir()).'/eimzo-*'));
        }
    }
}
