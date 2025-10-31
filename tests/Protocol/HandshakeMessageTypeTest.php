<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * @internal
 */
#[CoversClass(HandshakeMessageType::class)]
final class HandshakeMessageTypeTest extends AbstractEnumTestCase
{
    public function testGetMessageTypeName(): void
    {
        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::CLIENT_HELLO->getName());
        $this->assertEquals('SERVER_HELLO', HandshakeMessageType::SERVER_HELLO->getName());
        $this->assertEquals('FINISHED', HandshakeMessageType::FINISHED->getName());

        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::getMessageTypeName(1));
        $this->assertEquals('Unknown', HandshakeMessageType::getMessageTypeName(99)); // 不存在的类型
    }

    /**
     * 测试 toArray 方法
     */
    public function testToArray(): void
    {
        $array = HandshakeMessageType::CLIENT_HELLO->toArray();

        // 测试返回值结构
        $this->assertIsArray($array);
        $this->assertArrayHasKey('value', $array);
        $this->assertArrayHasKey('label', $array);

        // 测试具体值
        $this->assertEquals(1, $array['value']);
        $this->assertEquals('客户端Hello', $array['label']);

        // 测试其他枚举值
        $serverHelloArray = HandshakeMessageType::SERVER_HELLO->toArray();
        $this->assertEquals(2, $serverHelloArray['value']);
        $this->assertEquals('服务器Hello', $serverHelloArray['label']);

        $finishedArray = HandshakeMessageType::FINISHED->toArray();
        $this->assertEquals(20, $finishedArray['value']);
        $this->assertEquals('完成', $finishedArray['label']);

        // 测试所有枚举值都有正确的结构
        $allTypes = [
            HandshakeMessageType::HELLO_REQUEST,
            HandshakeMessageType::CLIENT_HELLO,
            HandshakeMessageType::SERVER_HELLO,
            HandshakeMessageType::NEW_SESSION_TICKET,
            HandshakeMessageType::ENCRYPTED_EXTENSIONS,
            HandshakeMessageType::CERTIFICATE,
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CERTIFICATE_REQUEST,
            HandshakeMessageType::SERVER_HELLO_DONE,
            HandshakeMessageType::CERTIFICATE_VERIFY,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
            HandshakeMessageType::FINISHED,
        ];

        foreach ($allTypes as $type) {
            $typeArray = $type->toArray();
            $this->assertArrayHasKey('value', $typeArray);
            $this->assertArrayHasKey('label', $typeArray);
            $this->assertEquals($type->value, $typeArray['value']);
            $this->assertEquals($type->getLabel(), $typeArray['label']);
        }
    }

    /**
     * 测试 toSelectItem 方法
     */
}
