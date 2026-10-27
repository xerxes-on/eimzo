<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;
use Symfony\Component\Process\Process;
use Throwable;

/** Headless, one-shot JVM using the pinned official E-IMZO cryptographic provider. */
final readonly class NativeSigner implements Signer
{
    public function __construct(
        private CertificateVault $vault,
        private Password $password,
        private string $runtimeDirectory,
        private string $javaBinary = '/usr/bin/java',
        private float $timeout = 30,
        private ?string $alias = null,
    ) {
        if (!str_starts_with($runtimeDirectory, '/') || str_contains($runtimeDirectory, PATH_SEPARATOR)
            || !is_file($runtimeDirectory.'/EimzoBridge.class') || !is_dir($runtimeDirectory.'/lib')) {
            throw new EimzoException('Install the native provider runtime and configure its absolute directory.');
        }
        if (!str_starts_with($javaBinary, '/') || !is_executable($javaBinary) || !is_finite($timeout) || $timeout <= 0) {
            throw new EimzoException('Configure an executable Java path and a positive timeout.');
        }
    }

    public function sign(string $identity, #[SensitiveParameter] string $content, bool $detached = false): string
    {
        if (strlen($content) > 4_194_304) {
            throw new EimzoException('Signing content exceeds the size limit.');
        }
        $pfx = $this->vault->read($identity);
        try {
            $input = json_encode(['pfx' => base64_encode($pfx), 'password' => $this->password->reveal(),
                'content' => base64_encode($content), 'detached' => $detached, 'alias' => $this->alias], JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new EimzoException('Cannot encode signing input. The password and alias must be valid UTF-8.');
        } finally {
            sodium_memzero($pfx);
        }
        $process = null;
        $output = '';
        $received = 0;
        $overflow = false;
        try {
            // Do not inherit application secrets or JVM injection variables into the child process.
            $names = array_unique(array_merge(array_keys(getenv()), array_keys($_ENV), array_keys($_SERVER)));
            $environment = array_fill_keys($names, false);
            $environment['LANG'] = 'C.UTF-8';
            $process = new Process(
                [$this->javaBinary, '-Djava.awt.headless=true', '-Xmx256m', '-cp',
                $this->runtimeDirectory.PATH_SEPARATOR.$this->runtimeDirectory.'/lib/*', 'EimzoBridge'],
                null,
                $environment,
                $input,
                $this->timeout
            );
            // Symfony's default output buffers spill to disk; collect only bounded in-memory output.
            $process->disableOutput();
            $process->run(function (string $type, #[SensitiveParameter] string $chunk) use (&$output, &$received, &$overflow): void {
                if ($overflow) {
                    return;
                } // Cleanup can drain pending output through this callback again.
                $received += strlen($chunk);
                if ($received > 12_582_912) {
                    $overflow = true;
                    throw new EimzoException('Native signer response exceeds the size limit.');
                }
                if ($type === Process::OUT) {
                    $output .= $chunk;
                }
            });
            $result = json_decode($output, true, 16, JSON_THROW_ON_ERROR);
            if (!$process->isSuccessful() || !is_array($result) || ($result['verified'] ?? false) !== true
                || !is_string($result['pkcs7_64'] ?? null) || $result['pkcs7_64'] === ''
                || base64_decode($result['pkcs7_64'], true) === false) {
                $code = is_array($result) ? ($result['error'] ?? '') : '';
                $reason = match ($code) {
                    'KEY_LOAD_FAILED' => 'Cannot unlock the certificate with this password and provider.',
                    'CERTIFICATE_SELECTION_FAILED' => 'Select an unambiguous private-key alias.',
                    'CERTIFICATE_EXPIRED_OR_NOT_YET_VALID' => 'The certificate is outside its validity period.',
                    default => 'Native signing or signature verification failed.',
                };
                throw new EimzoException($reason);
            }
            return $result['pkcs7_64'];
        } catch (EimzoException $e) {
            // Drop callback frames containing provider output, even when exception arguments are enabled.
            throw new EimzoException($e->getMessage());
        } catch (Throwable) {
            throw new EimzoException('Native signing failed or timed out. Check Java and the installed provider runtime.');
        } finally {
            try {
                if ($process !== null) {
                    $process->stop(0);
                }
            } catch (Throwable) {
                throw new EimzoException('Native signer process cleanup failed. Inspect the signing worker before retrying.');
            } finally {
                sodium_memzero($input);
                if ($process !== null) {
                    try {
                        $process->setInput(null);
                    } catch (Throwable) {
                        throw new EimzoException('Native signer input cleanup failed. Inspect the signing worker before retrying.');
                    }
                }
            }
        }
    }

    public function __debugInfo(): array
    {
        return ['signer' => 'native-eimzo', 'credentials' => '[redacted]'];
    }
}
