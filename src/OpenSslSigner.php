<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;

/** Optional CMS backend for OpenSSL-compatible PKCS#12 keys. */
final readonly class OpenSslSigner implements Signer
{
    public function __construct(private CertificateVault $vault, private Password $password)
    {
    }

    /** Returns base64 DER CMS. Unsupported certificate algorithms fail without a fallback. */
    public function sign(string $identity, #[SensitiveParameter] string $content, bool $detached = false): string
    {
        if (!extension_loaded('openssl')) {
            throw new EimzoException('The OpenSSL extension is required.');
        }
        if (strlen($content) > 4_194_304) {
            throw new EimzoException('Signing content exceeds the size limit.');
        }
        $pfx = $this->vault->read($identity);
        $password = $this->password->reveal();
        $certs = [];
        $directory = null;
        try {
            if (!@openssl_pkcs12_read($pfx, $certs, $password)) {
                throw new EimzoException('Cannot open PKCS#12: password, format or algorithm is unsupported. Use the E-IMZO runtime for native keys.');
            }
            $info = openssl_x509_parse($certs['cert']);
            if (!$info || ($info['validFrom_time_t'] ?? PHP_INT_MAX) > time() || ($info['validTo_time_t'] ?? 0) <= time()) {
                throw new EimzoException('The certificate is outside its validity period.');
            }
            $directory = realpath(sys_get_temp_dir()).'/eimzo-'.bin2hex(random_bytes(16));
            if (!@mkdir($directory, 0700)) {
                $directory = null;
                throw new EimzoException('Cannot create private signing workspace.');
            }
            $this->write($directory.'/input', $content);
            $this->write($directory.'/output', '');
            $chain = null;
            if (!empty($certs['extracerts'])) {
                $chain = $directory.'/chain';
                $this->write($chain, implode("\n", $certs['extracerts']));
            }
            $flags = OPENSSL_CMS_BINARY | ($detached ? OPENSSL_CMS_DETACHED : 0);
            if (!@openssl_cms_sign($directory.'/input', $directory.'/output', $certs['cert'], $certs['pkey'], [], $flags, OPENSSL_ENCODING_DER, $chain)) {
                throw new EimzoException('OpenSSL cannot sign with this certificate and algorithm.');
            }
            $signature = file_get_contents($directory.'/output');
            if ($signature === false || $signature === '') {
                throw new EimzoException('No signature was produced.');
            }
            return base64_encode($signature);
        } finally {
            sodium_memzero($pfx);
            sodium_memzero($password);
            if (isset($certs['pkey'])) {
                sodium_memzero($certs['pkey']);
            }
            while (openssl_error_string() !== false) { /* Clear details that could escape through unrelated logging. */
            }
            if ($directory !== null) {
                $failed = false;
                foreach (['input', 'output', 'chain'] as $file) {
                    $path = $directory.'/'.$file;
                    if (file_exists($path) && !@unlink($path)) {
                        $failed = true;
                    }
                }
                if (!@rmdir($directory)) {
                    $failed = true;
                }
                if ($failed) {
                    throw new EimzoException('Signing workspace cleanup failed. Inspect private temporary storage before retrying.');
                }
            }
        }
    }

    private function write(string $path, #[SensitiveParameter] string $bytes): void
    {
        $handle = @fopen($path, 'xb');
        if (!$handle) {
            throw new EimzoException('Cannot create signing file.');
        }
        try {
            if (!chmod($path, 0600) || fwrite($handle, $bytes) !== strlen($bytes)) {
                throw new EimzoException('Cannot write signing file.');
            }
        } finally {
            fclose($handle);
        }
    }

    public function __debugInfo(): array
    {
        return ['signer' => 'openssl', 'credentials' => '[redacted]'];
    }
}
