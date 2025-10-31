<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\EncryptedExtensionsMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * EncryptedExtensions消息测试类 (TLS 1.3特有)
 *
 * @internal
 */
#[CoversClass(EncryptedExtensionsMessage::class)]
final class EncryptedExtensionsMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new EncryptedExtensionsMessage();
        $this->assertEquals(HandshakeMessageType::ENCRYPTED_EXTENSIONS, $message->getType());
    }

    /**
     * 测试扩展操作
     */
    public function testExtensions(): void
    {
        $message = new EncryptedExtensionsMessage();

        // 测试默认值
        $this->assertEmpty($message->getExtensions());

        // 测试设置扩展
        $extensions = [
            0x0000 => false !== hex2bin('0001') ? hex2bin('0001') : '', // 扩展类型0，数据0001
            0x0001 => false !== hex2bin('0203') ? hex2bin('0203') : '',  // 扩展类型1，数据0203
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());

        // 测试添加扩展
        $message = new EncryptedExtensionsMessage();
        $message->addExtension(0x0010, false !== hex2bin('ffff') ? hex2bin('ffff') : '');
        $this->assertCount(1, $message->getExtensions());
        $this->assertEquals(false !== hex2bin('ffff') ? hex2bin('ffff') : '', $message->getExtensions()[0x0010]);
    }

    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new EncryptedExtensionsMessage();

        // 设置扩展
        $extensions = [
            0x0000 => false !== hex2bin('0001') ? hex2bin('0001') : '', // 扩展类型0，数据0001
            0x0001 => false !== hex2bin('0203') ? hex2bin('0203') : '',  // 扩展类型1，数据0203
        ];
        $originalMessage->setExtensions($extensions);

        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedMessage = EncryptedExtensionsMessage::decode($encodedData);

        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getExtensions(), $decodedMessage->getExtensions());
    }

    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new EncryptedExtensionsMessage();

        // 即使没有扩展，消息也是有效的
        $this->assertTrue($message->isValid());

        // 添加扩展后仍然有效
        $message->addExtension(0x0010, false !== hex2bin('ffff') ? hex2bin('ffff') : '');
        $this->assertTrue($message->isValid());
    }

    /**
     * 测试 addExtension 方法的完整功能
     */
    public function testAddExtension(): void
    {
        $message = new EncryptedExtensionsMessage();

        // 测试默认状态（无扩展）
        $this->assertEmpty($message->getExtensions());

        // 测试添加单个扩展
        $extensionType1 = 0x0000;
        $extensionData1 = false !== hex2bin('deadbeef') ? hex2bin('deadbeef') : '';
        $message->addExtension($extensionType1, $extensionData1);

        // 验证扩展已添加
        $extensions = $message->getExtensions();
        $this->assertCount(1, $extensions);
        $this->assertArrayHasKey($extensionType1, $extensions);
        $this->assertEquals($extensionData1, $extensions[$extensionType1]);

        // 测试添加多个扩展
        $extensionType2 = 0x0001;
        $extensionData2 = false !== hex2bin('cafebabe') ? hex2bin('cafebabe') : '';
        $message->addExtension($extensionType2, $extensionData2);

        $extensionType3 = 0x0010;
        $extensionData3 = false !== hex2bin('1234abcd') ? hex2bin('1234abcd') : '';
        $message->addExtension($extensionType3, $extensionData3);

        // 验证所有扩展都存在
        $extensions = $message->getExtensions();
        $this->assertCount(3, $extensions);
        $this->assertEquals($extensionData1, $extensions[$extensionType1]);
        $this->assertEquals($extensionData2, $extensions[$extensionType2]);
        $this->assertEquals($extensionData3, $extensions[$extensionType3]);

        // 测试覆盖已存在的扩展
        $newExtensionData1 = false !== hex2bin('feedface') ? hex2bin('feedface') : '';
        $message->addExtension($extensionType1, $newExtensionData1);

        // 验证扩展数量不变，但数据已更新
        $extensions = $message->getExtensions();
        $this->assertCount(3, $extensions);
        $this->assertEquals($newExtensionData1, $extensions[$extensionType1]);
        $this->assertEquals($extensionData2, $extensions[$extensionType2]);
        $this->assertEquals($extensionData3, $extensions[$extensionType3]);
    }
}
