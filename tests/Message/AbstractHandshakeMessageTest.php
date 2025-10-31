<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
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

            // 公开protected方法用于测试
            public function publicEncodeUint8(int $value): string
            {
                return $this->encodeUint8($value);
            }

            public function publicEncodeUint16(int $value): string
            {
                return $this->encodeUint16($value);
            }

            public function publicEncodeUint32(int $value): string
            {
                return $this->encodeUint32($value);
            }

            public static function publicDecodeUint8(string $data, int $offset = 0): int
            {
                return self::decodeUint8($data, $offset);
            }

            public static function publicDecodeUint16(string $data, int $offset = 0): int
            {
                return self::decodeUint16($data, $offset);
            }

            public static function publicDecodeUint32(string $data, int $offset = 0): int
            {
                return self::decodeUint32($data, $offset);
            }
        };
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
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('C', 0), $this->message->publicEncodeUint8(0));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('C', 127), $this->message->publicEncodeUint8(127));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('C', 255), $this->message->publicEncodeUint8(255));
    }

    /**
     * 测试编码16位无符号整数
     */
    public function testEncodeUint16(): void
    {
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('n', 0), $this->message->publicEncodeUint16(0));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('n', 256), $this->message->publicEncodeUint16(256));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('n', 65535), $this->message->publicEncodeUint16(65535));
    }

    /**
     * 测试编码32位无符号整数
     */
    public function testEncodeUint32(): void
    {
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('N', 0), $this->message->publicEncodeUint32(0));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('N', 65536), $this->message->publicEncodeUint32(65536));
        // @phpstan-ignore-next-line - Anonymous class method access
        $this->assertEquals(pack('N', 4294967295), $this->message->publicEncodeUint32(4294967295));
    }

    /**
     * 测试解码8位无符号整数
     */
    public function testDecodeUint8(): void
    {
        $messageClass = $this->message::class;
        $this->assertEquals(0, $messageClass::publicDecodeUint8(pack('C', 0)));
        $this->assertEquals(127, $messageClass::publicDecodeUint8(pack('C', 127)));
        $this->assertEquals(255, $messageClass::publicDecodeUint8(pack('C', 255)));

        // 测试带偏移量
        $data = pack('C*', 10, 20, 30);
        $this->assertEquals(20, $messageClass::publicDecodeUint8($data, 1));
        $this->assertEquals(30, $messageClass::publicDecodeUint8($data, 2));
    }

    /**
     * 测试解码16位无符号整数
     */
    public function testDecodeUint16(): void
    {
        $messageClass = $this->message::class;
        $this->assertEquals(0, $messageClass::publicDecodeUint16(pack('n', 0)));
        $this->assertEquals(256, $messageClass::publicDecodeUint16(pack('n', 256)));
        $this->assertEquals(65535, $messageClass::publicDecodeUint16(pack('n', 65535)));

        // 测试带偏移量
        $data = pack('n*', 100, 200, 300);
        $this->assertEquals(200, $messageClass::publicDecodeUint16($data, 2));
        $this->assertEquals(300, $messageClass::publicDecodeUint16($data, 4));
    }

    /**
     * 测试解码32位无符号整数
     */
    public function testDecodeUint32(): void
    {
        $messageClass = $this->message::class;
        $this->assertEquals(0, $messageClass::publicDecodeUint32(pack('N', 0)));
        $this->assertEquals(65536, $messageClass::publicDecodeUint32(pack('N', 65536)));
        $this->assertEquals(4294967295, $messageClass::publicDecodeUint32(pack('N', 4294967295)));

        // 测试带偏移量
        $data = pack('N*', 100000, 200000, 300000);
        $this->assertEquals(200000, $messageClass::publicDecodeUint32($data, 4));
        $this->assertEquals(300000, $messageClass::publicDecodeUint32($data, 8));
    }
}
