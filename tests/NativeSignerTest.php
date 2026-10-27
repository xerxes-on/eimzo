<?php

declare(strict_types=1);

namespace Xerxes\Eimzo\Tests;

use PHPUnit\Framework\TestCase;
use Xerxes\Eimzo\CertificateVault;
use Xerxes\Eimzo\EimzoException;
use Xerxes\Eimzo\NativeSigner;
use Xerxes\Eimzo\Password;

final class NativeSignerTest extends TestCase
{
    private string $directory;
    private CertificateVault $vault;

    protected function setUp(): void
    {
        $this->directory = realpath(sys_get_temp_dir()).'/native-test-'.bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        mkdir($this->directory.'/lib', 0700);
        touch($this->directory.'/EimzoBridge.class');
        $this->vault = new CertificateVault($this->directory.'/vault', base64_encode(random_bytes(32)));
        $this->vault->store('test', 'synthetic-pfx');
    }

    protected function tearDown(): void
    {
        unlink($this->directory.'/vault/test.vault');
        rmdir($this->directory.'/vault');
        rmdir($this->directory.'/lib');
        foreach (glob($this->directory.'/*') as $file) {
            unlink($file);
        }
        rmdir($this->directory);
    }

    public function testSecretsUseStdinAndParentEnvironmentIsRemoved(): void
    {
        $binary = $this->fakeJava(<<<'PHP'
$request = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
$ok = $request['password'] === 'test-password' && base64_decode($request['pfx']) === 'synthetic-pfx'
    && base64_decode($request['content']) === 'payload' && $request['detached'] === true
    && getenv('NATIVE_TEST_SECRET') === false && !str_contains(implode(' ', $argv), 'test-password');
echo json_encode($ok ? ['verified' => true, 'pkcs7_64' => base64_encode('cms')] : ['error' => 'INVALID_INPUT']);
PHP);
        putenv('NATIVE_TEST_SECRET=do-not-inherit');
        try {
            $signer = new NativeSigner($this->vault, new Password('test-password'), $this->directory, $binary);
            self::assertSame(base64_encode('cms'), $signer->sign('test', 'payload', true));
        } finally {
            putenv('NATIVE_TEST_SECRET');
        }
    }

    public function testFailedVerificationIsRejectedWithoutProviderOutput(): void
    {
        $binary = $this->fakeJava('fwrite(STDERR, "private-provider-output"); echo json_encode(["verified" => false, "pkcs7_64" => "Y21z"]);');
        try {
            (new NativeSigner($this->vault, new Password('password'), $this->directory, $binary))->sign('test', 'payload');
            self::fail();
        } catch (EimzoException $e) {
            self::assertStringNotContainsString('private-provider-output', $e->getMessage());
            self::assertNull($e->getPrevious());
        }
    }

    public function testDeadlineStopsStuckProviderProcess(): void
    {
        $binary = $this->fakeJava('stream_get_contents(STDIN); sleep(5);');
        $start = microtime(true);
        try {
            (new NativeSigner($this->vault, new Password('password'), $this->directory, $binary, timeout: 0.1))->sign('test', 'payload');
            self::fail();
        } catch (EimzoException $e) {
            self::assertStringContainsString('timed out', $e->getMessage());
            self::assertLessThan(1.5, microtime(true) - $start);
        }
    }

    private function fakeJava(string $code): string
    {
        $file = $this->directory.'/java';
        file_put_contents($file, '#!'.PHP_BINARY."\n<?php\n".$code);
        chmod($file, 0700);
        return $file;
    }

    public function testNoisyChildIsStoppedAndOutputIsAbsentFromExceptionTrace(): void
    {
        $marker = 'sensitive-provider-output';
        $binary = $this->fakeJava('stream_get_contents(STDIN); while (true) { fwrite(STDOUT, str_repeat("'.$marker.'", 4096)); }');
        $previous = ini_set('zend.exception_ignore_args', '0');
        $start = microtime(true);
        try {
            (new NativeSigner($this->vault, new Password('password'), $this->directory, $binary, timeout: 3))->sign('test', 'payload');
            self::fail();
        } catch (EimzoException $e) {
            self::assertStringContainsString('size limit', $e->getMessage());
            self::assertStringNotContainsString($marker, print_r($e->getTrace(), true));
            self::assertLessThan(2.5, microtime(true) - $start);
            self::assertNull($e->getPrevious());
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function testDisabledProcessCreationIsSanitized(): void
    {
        $fixture = $this->directory.'/construction.php';
        $code = '<?php require '.var_export(__DIR__.'/../vendor/autoload.php', true).';' . <<<'PHP'
$directory = __DIR__;
$vault = new Xerxes\Eimzo\CertificateVault($directory.'/construction-vault', base64_encode(str_repeat('a', 32)));
$vault->store('test', 'synthetic-pfx');
try {
    (new Xerxes\Eimzo\NativeSigner($vault, new Xerxes\Eimzo\Password('construction-secret'), $directory, PHP_BINARY))->sign('test', 'payload');
    echo json_encode(['thrown' => false]);
} catch (Throwable $error) {
    echo json_encode(['thrown' => true, 'type' => get_class($error), 'leaked' => str_contains(print_r($error->getTrace(), true), 'construction-secret')]);
} finally {
    unlink($directory.'/construction-vault/test.vault');
    rmdir($directory.'/construction-vault');
}
PHP;
        file_put_contents($fixture, $code);
        $process = new \Symfony\Component\Process\Process([PHP_BINARY, '-d', 'disable_functions=proc_open', '-d', 'zend.exception_ignore_args=0', $fixture]);
        $process->mustRun();
        $result = json_decode($process->getOutput(), true, 16, JSON_THROW_ON_ERROR);
        self::assertSame(['thrown' => true, 'type' => EimzoException::class, 'leaked' => false], $result);
    }
}
