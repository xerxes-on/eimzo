<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;

final readonly class DesktopClient
{
    public function __construct(private Rpc $rpc = new WebSocketRpc())
    {
    }

    public function version(): array
    {
        return $this->rpc->call(['name' => 'version']);
    }
    public function certificates(): array
    {
        return $this->rpc->call(['plugin' => 'pfx', 'name' => 'list_all_certificates'])['certificates'] ?? [];
    }

    /** Certificate must already be provisioned on the E-IMZO host. Password entry is handled there. */
    public function sign(string $disk, string $path, string $name, string $alias, #[SensitiveParameter] string $content, bool $detached = false): string
    {
        if (strlen($content) > 4_194_304) {
            throw new EimzoException('Signing content exceeds the size limit.');
        }
        $key = $this->rpc->call(['plugin' => 'pfx', 'name' => 'load_key', 'arguments' => [$disk, $path, $name, $alias]]);
        $id = $key['keyId'] ?? null;
        if (!is_string($id) || $id === '') {
            throw new EimzoException('E-IMZO did not return a key identifier.');
        }
        try {
            $result = $this->rpc->call(['plugin' => 'pkcs7', 'name' => 'create_pkcs7',
                'arguments' => [base64_encode($content), $id, $detached ? 'yes' : 'no']]);
            if (!is_string($result['pkcs7_64'] ?? null) || $result['pkcs7_64'] === '') {
                throw new EimzoException('E-IMZO did not return a signature.');
            }
            return $result['pkcs7_64'];
        } finally {
            $this->rpc->call(['plugin' => 'pfx', 'name' => 'unload_key', 'arguments' => [$id]]);
        }
    }
}
