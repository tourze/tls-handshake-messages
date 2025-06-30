<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Unit\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\AbstractHandshakeMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * AbstractHandshakeMessage测试类
 */
class AbstractHandshakeMessageTest extends TestCase
{
    private ConcreteHandshakeMessage $message;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->message = new ConcreteHandshakeMessage();
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
        $this->assertEquals(pack('C', 0), $this->message->publicEncodeUint8(0));
        $this->assertEquals(pack('C', 127), $this->message->publicEncodeUint8(127));
        $this->assertEquals(pack('C', 255), $this->message->publicEncodeUint8(255));
    }

    /**
     * 测试编码16位无符号整数
     */
    public function testEncodeUint16(): void
    {
        $this->assertEquals(pack('n', 0), $this->message->publicEncodeUint16(0));
        $this->assertEquals(pack('n', 256), $this->message->publicEncodeUint16(256));
        $this->assertEquals(pack('n', 65535), $this->message->publicEncodeUint16(65535));
    }

    /**
     * 测试编码32位无符号整数
     */
    public function testEncodeUint32(): void
    {
        $this->assertEquals(pack('N', 0), $this->message->publicEncodeUint32(0));
        $this->assertEquals(pack('N', 65536), $this->message->publicEncodeUint32(65536));
        $this->assertEquals(pack('N', 4294967295), $this->message->publicEncodeUint32(4294967295));
    }

    /**
     * 测试解码8位无符号整数
     */
    public function testDecodeUint8(): void
    {
        $this->assertEquals(0, ConcreteHandshakeMessage::publicDecodeUint8(pack('C', 0)));
        $this->assertEquals(127, ConcreteHandshakeMessage::publicDecodeUint8(pack('C', 127)));
        $this->assertEquals(255, ConcreteHandshakeMessage::publicDecodeUint8(pack('C', 255)));
        
        // 测试带偏移量
        $data = pack('C*', 10, 20, 30);
        $this->assertEquals(20, ConcreteHandshakeMessage::publicDecodeUint8($data, 1));
        $this->assertEquals(30, ConcreteHandshakeMessage::publicDecodeUint8($data, 2));
    }

    /**
     * 测试解码16位无符号整数
     */
    public function testDecodeUint16(): void
    {
        $this->assertEquals(0, ConcreteHandshakeMessage::publicDecodeUint16(pack('n', 0)));
        $this->assertEquals(256, ConcreteHandshakeMessage::publicDecodeUint16(pack('n', 256)));
        $this->assertEquals(65535, ConcreteHandshakeMessage::publicDecodeUint16(pack('n', 65535)));
        
        // 测试带偏移量
        $data = pack('n*', 100, 200, 300);
        $this->assertEquals(200, ConcreteHandshakeMessage::publicDecodeUint16($data, 2));
        $this->assertEquals(300, ConcreteHandshakeMessage::publicDecodeUint16($data, 4));
    }

    /**
     * 测试解码32位无符号整数
     */
    public function testDecodeUint32(): void
    {
        $this->assertEquals(0, ConcreteHandshakeMessage::publicDecodeUint32(pack('N', 0)));
        $this->assertEquals(65536, ConcreteHandshakeMessage::publicDecodeUint32(pack('N', 65536)));
        $this->assertEquals(4294967295, ConcreteHandshakeMessage::publicDecodeUint32(pack('N', 4294967295)));
        
        // 测试带偏移量
        $data = pack('N*', 100000, 200000, 300000);
        $this->assertEquals(200000, ConcreteHandshakeMessage::publicDecodeUint32($data, 4));
        $this->assertEquals(300000, ConcreteHandshakeMessage::publicDecodeUint32($data, 8));
    }
}

/**
 * 用于测试的具体实现类
 */
class ConcreteHandshakeMessage extends AbstractHandshakeMessage
{
    public function getType(): HandshakeMessageType
    {
        return HandshakeMessageType::CLIENT_HELLO;
    }
    
    public function encode(): string
    {
        return 'test_encoded_data';
    }
    
    public static function decode(string $data): static
    {
        return new static();
    }
    
    // 暴露protected方法以便测试
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
}