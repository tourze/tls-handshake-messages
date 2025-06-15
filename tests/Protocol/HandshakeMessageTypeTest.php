<?php

namespace Tourze\TLSHandshakeMessages\Tests\Protocol;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

class HandshakeMessageTypeTest extends TestCase
{
    public function testMessageTypeEnumValues(): void
    {
        $this->assertEquals(0, HandshakeMessageType::HELLO_REQUEST->value);
        $this->assertEquals(1, HandshakeMessageType::CLIENT_HELLO->value);
        $this->assertEquals(2, HandshakeMessageType::SERVER_HELLO->value);
        $this->assertEquals(4, HandshakeMessageType::NEW_SESSION_TICKET->value);
        $this->assertEquals(8, HandshakeMessageType::ENCRYPTED_EXTENSIONS->value);
        $this->assertEquals(11, HandshakeMessageType::CERTIFICATE->value);
        $this->assertEquals(12, HandshakeMessageType::SERVER_KEY_EXCHANGE->value);
        $this->assertEquals(13, HandshakeMessageType::CERTIFICATE_REQUEST->value);
        $this->assertEquals(14, HandshakeMessageType::SERVER_HELLO_DONE->value);
        $this->assertEquals(15, HandshakeMessageType::CERTIFICATE_VERIFY->value);
        $this->assertEquals(16, HandshakeMessageType::CLIENT_KEY_EXCHANGE->value);
        $this->assertEquals(20, HandshakeMessageType::FINISHED->value);
    }

    public function testGetMessageTypeName(): void
    {
        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::CLIENT_HELLO->getName());
        $this->assertEquals('SERVER_HELLO', HandshakeMessageType::SERVER_HELLO->getName());
        $this->assertEquals('FINISHED', HandshakeMessageType::FINISHED->getName());

        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::getMessageTypeName(1));
        $this->assertEquals('Unknown', HandshakeMessageType::getMessageTypeName(99)); // 不存在的类型
    }

    public function testTryFrom(): void
    {
        $this->assertInstanceOf(HandshakeMessageType::class, HandshakeMessageType::tryFrom(1));
        $this->assertEquals(HandshakeMessageType::CLIENT_HELLO, HandshakeMessageType::tryFrom(1));
        $this->assertNull(HandshakeMessageType::tryFrom(99)); // 不存在的类型
    }
}
