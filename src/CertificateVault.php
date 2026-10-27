<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;

/** Local encrypted storage. Its parent directories must be owned by the deployment user. */
final class CertificateVault
{
    private const MAX_BYTES = 4_194_304;
    private const PREFIX = "EIMZO1\0";
    private string $key;
    private string $directory;

    public function __construct(string $directory, #[SensitiveParameter] string $base64Key)
    {
        $key = base64_decode($base64Key, true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new EimzoException('The vault key must be a base64-encoded 32-byte random key.');
        }
        $this->key = $key;
        if (!str_starts_with($directory, '/') || str_contains($directory, "\0")) {
            throw new EimzoException('Use an absolute private storage path.');
        }
        $directory = rtrim($directory, '/');
        // Refuse symbolic links in any existing path component, including parent directories.
        $path = '';
        foreach (explode('/', ltrim($directory, '/')) as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                throw new EimzoException('Invalid vault path.');
            }
            $path .= '/'.$part;
            if (is_link($path)) {
                throw new EimzoException('Vault paths must not contain symbolic links.');
            }
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new EimzoException('Cannot create the vault directory.');
        }
        clearstatcache(true, $directory);
        if ((fileperms($directory) & 0777) !== 0700 || !is_writable($directory)) {
            throw new EimzoException('The vault directory must be writable with permissions 0700.');
        }
        $this->directory = $directory;
    }

    /** Import PFX/P12 bytes without overwriting an existing identity. Password remains separate. */
    public function store(string $id, #[SensitiveParameter] string $pfx): void
    {
        $destination = $this->path($id);
        if ($pfx === '' || strlen($pfx) > self::MAX_BYTES) {
            throw new EimzoException('Certificate file is empty or too large.');
        }
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $encrypted = self::PREFIX.$nonce.sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($pfx, $id, $nonce, $this->key);
        // A private temp file + hard link publishes atomically and never overwrites a destination.
        $temporary = $this->directory.'/.'.bin2hex(random_bytes(16)).'.tmp';
        $handle = @fopen($temporary, 'x+b');
        if ($handle === false) {
            throw new EimzoException('Cannot create a vault file.');
        }
        try {
            if (!chmod($temporary, 0600) || fwrite($handle, $encrypted) !== strlen($encrypted) || !fflush($handle)) {
                throw new EimzoException('Cannot write the vault file.');
            }
            if (!@link($temporary, $destination)) {
                throw new EimzoException('Certificate identity already exists or cannot be stored.');
            }
        } finally {
            fclose($handle);
            if (!@unlink($temporary)) {
                throw new EimzoException('Vault temporary file cleanup failed. The identity may already be stored; inspect before retrying.');
            }
        }
    }

    /** Decrypted bytes remain in memory; do not log or serialize them. */
    public function read(string $id): string
    {
        $path = $this->path($id);
        clearstatcache(true, $path);
        if (is_link($path) || !is_file($path) || (fileperms($path) & 0777) !== 0600) {
            throw new EimzoException('Certificate is missing or its permissions are unsafe.');
        }
        $blob = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 128);
        if (!is_string($blob) || strlen($blob) > self::MAX_BYTES + 47 || !str_starts_with($blob, self::PREFIX)) {
            throw new EimzoException('Invalid encrypted certificate.');
        }
        $offset = strlen(self::PREFIX);
        $nonceSize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        if (strlen($blob) < $offset + $nonceSize + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            throw new EimzoException('Invalid encrypted certificate.');
        }
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($blob, $offset + $nonceSize), $id, substr($blob, $offset, $nonceSize), $this->key);
        if ($plain === false) {
            throw new EimzoException('Certificate authentication failed.');
        }
        return $plain;
    }

    private function path(string $id): string
    {
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D', $id)) {
            throw new EimzoException('Invalid certificate identity.');
        }
        return $this->directory.'/'.$id.'.vault';
    }

    public function __debugInfo(): array
    {
        return ['vault' => '[redacted]'];
    }
    public function __serialize(): array
    {
        throw new EimzoException('Vaults must not be serialized.');
    }
    public function __destruct()
    {
        $key = $this->key;
        unset($this->key);
        sodium_memzero($key);
    }
}
