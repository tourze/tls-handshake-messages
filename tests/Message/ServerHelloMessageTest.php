<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Message\ServerHelloMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ServerHelloMessage测试类
 *
 * @internal
 */
#[CoversClass(ServerHelloMessage::class)]
final class ServerHelloMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ServerHelloMessage();
        $this->assertEquals(HandshakeMessageType::SERVER_HELLO, $message->getType());
    }

    /**
     * 测试默认值
     */
    public function testDefaultValues(): void
    {
        $message = new ServerHelloMessage();

        $this->assertEquals(0x0303, $message->getVersion()); // TLS 1.2
        $this->assertEquals(32, strlen($message->getRandom()));
        $this->assertEquals('', $message->getSessionId());
        $this->assertEquals(0, $message->getCipherSuite());
        $this->assertEquals(0, $message->getCompressionMethod());
        $this->assertEmpty($message->getExtensions());
    }

    /**
     * 测试设置和获取版本
     */
    public function testVersionGetterSetter(): void
    {
        $message = new ServerHelloMessage();

        $message->setVersion(0x0304); // TLS 1.3
        $this->assertEquals(0x0304, $message->getVersion());
    }

    /**
     * 测试设置和获取随机数
     */
    public function testRandomGetterSetter(): void
    {
        $message = new ServerHelloMessage();

        $random = str_repeat('A', 32);
        $message->setRandom($random);
        $this->assertEquals($random, $message->getRandom());
    }

    /**
     * 测试设置无效随机数
     */
    public function testSetInvalidRandom(): void
    {
        $message = new ServerHelloMessage();

        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Random must be exactly 32 bytes');

        $message->setRandom('short');
    }

    /**
     * 测试设置和获取会话ID
     */
    public function testSessionIdGetterSetter(): void
    {
        $message = new ServerHelloMessage();

        $sessionId = str_repeat('B', 32);
        $message->setSessionId($sessionId);
        $this->assertEquals($sessionId, $message->getSessionId());
    }

    /**
     * 测试设置无效会话ID（太长）
     */
    public function testSetInvalidSessionId(): void
    {
        $message = new ServerHelloMessage();

        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Session ID must be 0-32 bytes');

        $message->setSessionId(str_repeat('C', 33));
    }

    /**
     * 测试设置和获取加密套件
     */
    public function testCipherSuiteGetterSetter(): void
    {
        $message = new ServerHelloMessage();

        $message->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $this->assertEquals(0x1301, $message->getCipherSuite());
    }

    /**
     * 测试设置和获取压缩方法
     */
    public function testCompressionMethodGetterSetter(): void
    {
        $message = new ServerHelloMessage();

        $message->setCompressionMethod(1);
        $this->assertEquals(1, $message->getCompressionMethod());
    }

    /**
     * 测试扩展操作
     */
    public function testExtensions(): void
    {
        $message = new ServerHelloMessage();

        // 测试默认值
        $this->assertEmpty($message->getExtensions());

        // 测试添加扩展
        $message->addExtension(0x000D, 'signature_algorithms');
        $this->assertCount(1, $message->getExtensions());
        $this->assertArrayHasKey(0x000D, $message->getExtensions());

        $message->addExtension(0x0023, 'session_ticket');
        $this->assertCount(2, $message->getExtensions());

        // 测试设置扩展
        $extensions = [
            0x0000 => 'server_name',
            0x000B => 'ec_point_formats',
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());
    }

    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $original = new ServerHelloMessage();
        $original->setVersion(0x0303);
        $original->setRandom(str_repeat('R', 32));
        $original->setSessionId('session123');
        $original->setCipherSuite(0x1301);
        $original->setCompressionMethod(0);
        $original->addExtension(0x000D, 'test_extension');

        // 编码
        $encoded = $original->encode();

        // 解码
        $decoded = ServerHelloMessage::decode($encoded);

        // 验证
        $this->assertEquals($original->getVersion(), $decoded->getVersion());
        $this->assertEquals($original->getRandom(), $decoded->getRandom());
        $this->assertEquals($original->getSessionId(), $decoded->getSessionId());
        $this->assertEquals($original->getCipherSuite(), $decoded->getCipherSuite());
        $this->assertEquals($original->getCompressionMethod(), $decoded->getCompressionMethod());
        $this->assertEquals($original->getExtensions(), $decoded->getExtensions());
    }

    /**
     * 测试解码无效消息类型
     */
    public function testDecodeInvalidMessageType(): void
    {
        $data = pack('C', 0xFF); // 无效的消息类型
        $data .= pack('C3', 0, 0, 0); // 长度

        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Invalid message type');

        ServerHelloMessage::decode($data);
    }

    /**
     * 测试解码不完整数据
     */
    public function testDecodeIncompleteData(): void
    {
        $data = pack('C', HandshakeMessageType::SERVER_HELLO->value);
        $data .= pack('C3', 0, 0, 100); // 声明100字节但实际数据不足
        $data .= 'incomplete';

        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Incomplete message data');

        ServerHelloMessage::decode($data);
    }

    /**
     * 测试消息验证
     */
    public function testIsValid(): void
    {
        $message = new ServerHelloMessage();

        // 使用默认值应该是有效的
        $this->assertTrue($message->isValid());

        // 设置有效值后仍然有效
        $message->setCipherSuite(0x1301);
        $this->assertTrue($message->isValid());
    }

    /**
     * 测试 addExtension 方法的专门测试
     */
    public function testAddExtension(): void
    {
        $message = new ServerHelloMessage();

        // 测试默认状态（无扩展）
        $this->assertEmpty($message->getExtensions());
        $this->assertCount(0, $message->getExtensions());

        // 测试添加单个扩展
        $result = $message->addExtension(0x000D, 'signature_algorithms');

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 验证扩展已添加
        $extensions = $message->getExtensions();
        $this->assertCount(1, $extensions);
        $this->assertArrayHasKey(0x000D, $extensions);
        $this->assertEquals('signature_algorithms', $extensions[0x000D]);

        // 测试添加多个扩展
        $message->addExtension(0x0023, 'session_ticket')
            ->addExtension(0x000B, 'ec_point_formats')
            ->addExtension(0x0000, 'server_name')
        ;

        $extensions = $message->getExtensions();
        $this->assertCount(4, $extensions);
        $this->assertArrayHasKey(0x000D, $extensions);
        $this->assertArrayHasKey(0x0023, $extensions);
        $this->assertArrayHasKey(0x000B, $extensions);
        $this->assertArrayHasKey(0x0000, $extensions);

        $this->assertEquals('signature_algorithms', $extensions[0x000D]);
        $this->assertEquals('session_ticket', $extensions[0x0023]);
        $this->assertEquals('ec_point_formats', $extensions[0x000B]);
        $this->assertEquals('server_name', $extensions[0x0000]);

        // 测试覆盖已存在的扩展
        $message->addExtension(0x000D, 'updated_signature_algorithms');

        $extensions = $message->getExtensions();
        $this->assertCount(4, $extensions); // 数量不变
        $this->assertEquals('updated_signature_algorithms', $extensions[0x000D]); // 值已更新

        // 验证其他扩展未受影响
        $this->assertEquals('session_ticket', $extensions[0x0023]);
        $this->assertEquals('ec_point_formats', $extensions[0x000B]);
        $this->assertEquals('server_name', $extensions[0x0000]);
    }
}
