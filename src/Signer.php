<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

interface Signer
{
    /** Return base64-encoded CMS/PKCS#7 for the given vault identity. */
    public function sign(string $identity, #[\SensitiveParameter] string $content, bool $detached = false): string;
}
