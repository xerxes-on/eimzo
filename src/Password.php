<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;

final readonly class Password
{
    public function __construct(#[SensitiveParameter] private string $value)
    {
        if ($value === '') {
            throw new EimzoException('The certificate password is missing.');
        }
    }

    public static function fromEnvironment(string $name = 'EIMZO_KEY_PASSWORD'): self
    {
        $value = getenv($name);
        return new self(is_string($value) ? $value : '');
    }

    public function reveal(): string
    {
        return $this->value;
    }
    public function __debugInfo(): array
    {
        return ['password' => '[redacted]'];
    }
    public function __serialize(): array
    {
        throw new EimzoException('Passwords must not be serialized.');
    }
}
