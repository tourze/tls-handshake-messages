<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Protocol;

use Tourze\TLSHandshakeMessages\Message\HandshakeMessageInterface;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 测试专用的握手消息实现
 *
 * @internal
 */
final class TestHandshakeMessage implements HandshakeMessageInterface
{
    private string $encodeReturn;

    private HandshakeMessageType $type;

    public function __construct(string $encodeReturn, HandshakeMessageType $type)
    {
        $this->encodeReturn = $encodeReturn;
        $this->type = $type;
    }

    public function getType(): HandshakeMessageType
    {
        return $this->type;
    }

    public function encode(): string
    {
        return $this->encodeReturn;
    }

    public static function decode(string $data): static
    {
        return new self('decoded_data', HandshakeMessageType::CERTIFICATE);
    }

    public function getLength(): int
    {
        return strlen($this->encodeReturn);
    }

    public function isValid(): bool
    {
        return true;
    }
}
