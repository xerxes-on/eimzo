<?php

declare(strict_types=1);

namespace Xerxes\Eimzo;

use SensitiveParameter;
use Throwable;
use WebSocket\Client as Socket;
use WebSocket\Message\Text;
use WebSocket\Middleware\CloseHandler;
use WebSocket\Middleware\PingResponder;

final readonly class WebSocketRpc implements Rpc
{
    public function __construct(private string $url = 'ws://127.0.0.1:64646/service/cryptapi', private float $timeout = 60)
    {
        $parts = parse_url($url);
        if (!$parts || ($parts['scheme'] ?? '') !== 'ws' || !in_array($parts['host'] ?? '', ['127.0.0.1', '[::1]'], true)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !is_finite($timeout) || $timeout <= 0) {
            throw new EimzoException('E-IMZO must use a numeric loopback WebSocket URL and positive timeout. Use an SSH tunnel for a separate host.');
        }
    }

    public function call(#[SensitiveParameter] array $request): array
    {
        $client = null;
        try {
            $client = (new Socket($this->url))->setTimeout($this->timeout)->addHeader('Origin', 'http://localhost')
                ->addMiddleware(new CloseHandler())->addMiddleware(new PingResponder());
            $client->text(json_encode($request, JSON_THROW_ON_ERROR));
            $message = $client->receive();
            if (!$message instanceof Text || strlen($message->getContent()) > 8_388_608) {
                throw new EimzoException('Invalid response.');
            }
            $data = json_decode($message->getContent(), true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($data) || ($data['success'] ?? false) !== true) {
                throw new EimzoException('Unsuccessful response.');
            }
            return $data;
        } catch (Throwable) {
            throw new EimzoException('E-IMZO request failed. Check the runtime and any local password prompt.');
        } finally {
            if ($client !== null) {
                try {
                    $client->disconnect();
                } catch (Throwable) {
                    throw new EimzoException('E-IMZO connection cleanup failed. Check the runtime before repeating the operation.');
                }
            }
        }
    }
}
