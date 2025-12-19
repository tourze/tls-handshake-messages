<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Tourze\TLSHandshakeMessages\Message\AbstractHandshakeMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * AbstractHandshakeMessage测试类
 *
 * @internal
 */
#[CoversClass(AbstractHandshakeMessage::class)]
final class AbstractHandshakeMessageTest extends TestCase
{
    private AbstractHandshakeMessage $message;

    protected function setUp(): void
    {
        parent::setUp();

        // 使用匿名类替代独立的测试支持文件
        $this->message = new class extends AbstractHandshakeMessage {
            private string $testData = 'test_message_data';

            public function getType(): HandshakeMessageType
            {
                return HandshakeMessageType::CLIENT_HELLO;
            }

            public function encode(): string
            {
                return $this->testData;
            }

            public static function decode(string $data): static
            {
                $instance = new self();
                $instance->testData = $data;

                return $instance;
            }
        };
    }

    /**
     * 使用反射调用 protected 方法
     */
    private function invokeProtectedMethod(string $methodName, mixed ...$args): mixed
    {
        $reflection = new ReflectionMethod($this->message, $methodName);
        $reflection->setAccessible(true);

        return $reflection->invoke($this->message, ...$args);
    }

    /**
     * 使用反射调用 protected static 方法
     */
    private function invokeProtectedStaticMethod(string $methodName, mixed ...$args): mixed
    {
        $reflection = new ReflectionMethod(AbstractHandshakeMessage::class, $methodName);
        $reflection->setAccessible(true);

        return $reflection->invoke(null, ...$args);
    }

    /**
     * 测试获取消息长度
     */
    public function testGetLength(): void
    {
        $this->assertEquals(17, $this->message->getLength());
    }

    /**
     * 测试消息验证
     */
    public function testIsValid(): void
    {
        $this->assertTrue($this->message->isValid());
    }

    /**
     * 测试编码8位无符号整数
     */
    public function testEncodeUint8(): void
    {
        $this->assertEquals(pack('C', 0), $this->invokeProtectedMethod('encodeUint8', 0));
        $this->assertEquals(pack('C', 127), $this->invokeProtectedMethod('encodeUint8', 127));
        $this->assertEquals(pack('C', 255), $this->invokeProtectedMethod('encodeUint8', 255));
    }

    /**
     * 测试编码16位无符号整数
     */
    public function testEncodeUint16(): void
    {
        $this->assertEquals(pack('n', 0), $this->invokeProtectedMethod('encodeUint16', 0));
        $this->assertEquals(pack('n', 256), $this->invokeProtectedMethod('encodeUint16', 256));
        $this->assertEquals(pack('n', 65535), $this->invokeProtectedMethod('encodeUint16', 65535));
    }

    /**
     * 测试编码32位无符号整数
     */
    public function testEncodeUint32(): void
    {
        $this->assertEquals(pack('N', 0), $this->invokeProtectedMethod('encodeUint32', 0));
        $this->assertEquals(pack('N', 65536), $this->invokeProtectedMethod('encodeUint32', 65536));
        $this->assertEquals(pack('N', 4294967295), $this->invokeProtectedMethod('encodeUint32', 4294967295));
    }

    /**
     * 测试解码8位无符号整数
     */
    public function testDecodeUint8(): void
    {
        $this->assertEquals(0, $this->invokeProtectedStaticMethod('decodeUint8', pack('C', 0)));
        $this->assertEquals(127, $this->invokeProtectedStaticMethod('decodeUint8', pack('C', 127)));
        $this->assertEquals(255, $this->invokeProtectedStaticMethod('decodeUint8', pack('C', 255)));

        // 测试带偏移量
        $data = pack('C*', 10, 20, 30);
        $this->assertEquals(20, $this->invokeProtectedStaticMethod('decodeUint8', $data, 1));
        $this->assertEquals(30, $this->invokeProtectedStaticMethod('decodeUint8', $data, 2));
    }

    /**
     * 测试解码16位无符号整数
     */
    public function testDecodeUint16(): void
    {
        $this->assertEquals(0, $this->invokeProtectedStaticMethod('decodeUint16', pack('n', 0)));
        $this->assertEquals(256, $this->invokeProtectedStaticMethod('decodeUint16', pack('n', 256)));
        $this->assertEquals(65535, $this->invokeProtectedStaticMethod('decodeUint16', pack('n', 65535)));

        // 测试带偏移量
        $data = pack('n*', 100, 200, 300);
        $this->assertEquals(200, $this->invokeProtectedStaticMethod('decodeUint16', $data, 2));
        $this->assertEquals(300, $this->invokeProtectedStaticMethod('decodeUint16', $data, 4));
    }

    /**
     * 测试解码32位无符号整数
     */
    public function testDecodeUint32(): void
    {
        $this->assertEquals(0, $this->invokeProtectedStaticMethod('decodeUint32', pack('N', 0)));
        $this->assertEquals(65536, $this->invokeProtectedStaticMethod('decodeUint32', pack('N', 65536)));
        $this->assertEquals(4294967295, $this->invokeProtectedStaticMethod('decodeUint32', pack('N', 4294967295)));

        // 测试带偏移量
        $data = pack('N*', 100000, 200000, 300000);
        $this->assertEquals(200000, $this->invokeProtectedStaticMethod('decodeUint32', $data, 4));
        $this->assertEquals(300000, $this->invokeProtectedStaticMethod('decodeUint32', $data, 8));
    }
}
