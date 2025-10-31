<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\NewSessionTicketMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * NewSessionTicket消息测试类 (TLS 1.3特有)
 *
 * @internal
 */
#[CoversClass(NewSessionTicketMessage::class)]
final class NewSessionTicketMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new NewSessionTicketMessage();
        $this->assertEquals(HandshakeMessageType::NEW_SESSION_TICKET, $message->getType());
    }

    /**
     * 测试票据生命周期设置和获取
     */
    public function testTicketLifetime(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认值
        $this->assertEquals(0, $message->getTicketLifetime());

        // 测试设置值
        $message->setTicketLifetime(86400); // 1天
        $this->assertEquals(86400, $message->getTicketLifetime());
    }

    /**
     * 测试票据年龄附加值设置和获取
     */
    public function testTicketAgeAdd(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认值
        $this->assertEquals(0, $message->getTicketAgeAdd());

        // 测试设置值
        $message->setTicketAgeAdd(12345);
        $this->assertEquals(12345, $message->getTicketAgeAdd());
    }

    /**
     * 测试票据随机数设置和获取
     */
    public function testTicketNonce(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认值
        $this->assertEquals('', $message->getTicketNonce());

        // 测试设置值
        $nonce = hex2bin('0102030405');
        $this->assertIsString($nonce);
        $message->setTicketNonce($nonce);
        $this->assertEquals($nonce, $message->getTicketNonce());
    }

    /**
     * 测试票据设置和获取
     */
    public function testTicket(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认值
        $this->assertEquals('', $message->getTicket());

        // 测试设置值
        $ticket = hex2bin('0102030405060708090a0b0c0d0e0f1011121314');
        $this->assertIsString($ticket);
        $message->setTicket($ticket);
        $this->assertEquals($ticket, $message->getTicket());
    }

    /**
     * 测试扩展操作
     */
    public function testExtensions(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认值
        $this->assertEmpty($message->getExtensions());

        // 测试设置扩展
        $extensionData = hex2bin('0001');
        $this->assertIsString($extensionData);
        $extensions = [
            0x0029 => $extensionData, // early_data扩展，数据0001
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());

        // 测试添加扩展
        $message = new NewSessionTicketMessage();
        $data = hex2bin('0001');
        $this->assertIsString($data);
        $message->addExtension(0x0029, $data);
        $this->assertCount(1, $message->getExtensions());
        $expectedData = hex2bin('0001');
        $this->assertIsString($expectedData);
        $this->assertEquals($expectedData, $message->getExtensions()[0x0029]);
    }

    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new NewSessionTicketMessage();

        // 设置字段
        $originalMessage->setTicketLifetime(86400); // 1天
        $originalMessage->setTicketAgeAdd(12345);
        $nonce = hex2bin('0102030405');
        $this->assertIsString($nonce);
        $originalMessage->setTicketNonce($nonce);
        $ticket = hex2bin('0102030405060708090a0b0c0d0e0f1011121314');
        $this->assertIsString($ticket);
        $originalMessage->setTicket($ticket);

        // 设置扩展
        $extensionData = hex2bin('0001');
        $this->assertIsString($extensionData);
        $originalMessage->addExtension(0x0029, $extensionData); // early_data扩展

        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedMessage = NewSessionTicketMessage::decode($encodedData);

        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getTicketLifetime(), $decodedMessage->getTicketLifetime());
        $this->assertEquals($originalMessage->getTicketAgeAdd(), $decodedMessage->getTicketAgeAdd());
        $this->assertEquals($originalMessage->getTicketNonce(), $decodedMessage->getTicketNonce());
        $this->assertEquals($originalMessage->getTicket(), $decodedMessage->getTicket());
        $this->assertEquals($originalMessage->getExtensions(), $decodedMessage->getExtensions());
    }

    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new NewSessionTicketMessage();

        // 没有票据是无效的
        $this->assertFalse($message->isValid());

        // 设置票据后是有效的
        $ticket = hex2bin('0102030405060708090a0b0c0d0e0f1011121314');
        $this->assertIsString($ticket);
        $message->setTicket($ticket);
        $this->assertTrue($message->isValid());
    }

    /**
     * 测试addExtension方法的专门测试
     */
    public function testAddExtension(): void
    {
        $message = new NewSessionTicketMessage();

        // 测试默认状态（无扩展）
        $this->assertEmpty($message->getExtensions());

        // 测试添加单个扩展
        $extensionType = 0x0029; // early_data扩展
        $extensionData = hex2bin('0001');
        $this->assertIsString($extensionData);
        $result = $message->addExtension($extensionType, $extensionData);

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 验证扩展已添加
        $extensions = $message->getExtensions();
        $this->assertCount(1, $extensions);
        $this->assertArrayHasKey($extensionType, $extensions);
        $this->assertEquals($extensionData, $extensions[$extensionType]);

        // 测试添加多个扩展
        $extensionType2 = 0x002A; // supported_versions扩展
        $extensionData2 = hex2bin('0002');
        $this->assertIsString($extensionData2);
        $message->addExtension($extensionType2, $extensionData2);

        $extensions = $message->getExtensions();
        $this->assertCount(2, $extensions);
        $this->assertArrayHasKey($extensionType, $extensions);
        $this->assertArrayHasKey($extensionType2, $extensions);
        $this->assertEquals($extensionData, $extensions[$extensionType]);
        $this->assertEquals($extensionData2, $extensions[$extensionType2]);

        // 测试覆盖已存在的扩展
        $newExtensionData = hex2bin('0003');
        $this->assertIsString($newExtensionData);
        $message->addExtension($extensionType, $newExtensionData);

        $extensions = $message->getExtensions();
        $this->assertCount(2, $extensions); // 扩展数量不变
        $this->assertEquals($newExtensionData, $extensions[$extensionType]); // 数据被覆盖
        $this->assertEquals($extensionData2, $extensions[$extensionType2]); // 其他扩展不受影响
    }
}
