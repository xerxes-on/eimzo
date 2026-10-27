<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;

/** @internal Bounded non-blocking pipes; no shell, inherited environment, or disk buffers. */
final class NativeProcess
{
    public function run(array $command, #[SensitiveParameter] string $input, float $timeout): array
    {
        if (!function_exists('proc_open')) {
            throw new EimzoException('Process execution is unavailable.');
        }
        $process = null;
        $pipes = [];
        $output = '';
        $received = 0;
        $offset = 0;
        $exitCode = -1;
        $deadline = hrtime(true) + $timeout * 1_000_000_000;
        try {
            $process = @proc_open(
                $command,
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                null,
                ['LANG' => 'C.UTF-8'],
                ['bypass_shell' => true]
            );
            if (!is_resource($process)) {
                throw new EimzoException('Cannot start the native signing process.');
            }
            foreach ($pipes as $pipe) {
                stream_set_blocking($pipe, false);
            }
            do {
                if (hrtime(true) >= $deadline) {
                    throw new EimzoException('Native signing timed out.');
                }
                $status = proc_get_status($process);
                if (!$status['running'] && $status['exitcode'] >= 0) {
                    $exitCode = $status['exitcode'];
                }
                if (isset($pipes[0]) && ($offset >= strlen($input) || !$status['running'])) {
                    fclose($pipes[0]);
                    unset($pipes[0]);
                }
                $read = [];
                foreach ([1, 2] as $index) {
                    if (isset($pipes[$index])) {
                        if (feof($pipes[$index])) {
                            fclose($pipes[$index]);
                            unset($pipes[$index]);
                        } else {
                            $read[$index] = $pipes[$index];
                        }
                    }
                }
                $write = isset($pipes[0]) ? [$pipes[0]] : [];
                if ($read === [] && $write === []) {
                    if (!$status['running']) {
                        break;
                    }
                    usleep(1000);
                    continue;
                }
                $except = [];
                if (@stream_select($read, $write, $except, 0, 10000) === false) {
                    throw new EimzoException('Native signing pipe failed.');
                }
                if ($write !== []) {
                    $written = @fwrite($pipes[0], substr($input, $offset, 8192));
                    if ($written === false) {
                        throw new EimzoException('Native signing input failed.');
                    }
                    $offset += $written;
                }
                foreach ($read as $index => $pipe) {
                    // Read at most one chunk per pipe before checking the deadline again.
                    $chunk = fread($pipe, 8192);
                    if ($chunk === false) {
                        throw new EimzoException('Native signing output failed.');
                    }
                    $received += strlen($chunk);
                    if ($received > 12_582_912) {
                        throw new EimzoException('Native signer response exceeds the size limit.');
                    }
                    if ($index === 1) {
                        $output .= $chunk;
                    }
                }
            } while (true);
            return ['exitCode' => $exitCode, 'output' => $output];
        } finally {
            sodium_memzero($input);
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }
            if (is_resource($process)) {
                $status = proc_get_status($process);
                if ($status['running'] && !proc_terminate($process, 9)) {
                    throw new EimzoException('Native signer process cleanup failed. Inspect the signing worker before retrying.');
                }
                proc_close($process);
            }
        }
    }
}
