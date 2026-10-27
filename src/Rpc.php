<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

interface Rpc
{
    public function call(array $request): array;
}
