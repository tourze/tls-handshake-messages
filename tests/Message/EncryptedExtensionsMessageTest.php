<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\EncryptedExtensionsMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * EncryptedExtensions消息测试类 (TLS 1.3特有)
 */
class EncryptedExtensionsMessageTest extends TestCase
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
            0x0000 => hex2bin('0001'), // 扩展类型0，数据0001
            0x0001 => hex2bin('0203')  // 扩展类型1，数据0203
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());
        
        // 测试添加扩展
        $message = new EncryptedExtensionsMessage();
        $message->addExtension(0x0010, hex2bin('ffff'));
        $this->assertCount(1, $message->getExtensions());
        $this->assertEquals(hex2bin('ffff'), $message->getExtensions()[0x0010]);
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new EncryptedExtensionsMessage();
        
        // 设置扩展
        $extensions = [
            0x0000 => hex2bin('0001'), // 扩展类型0，数据0001
            0x0001 => hex2bin('0203')  // 扩展类型1，数据0203
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
        $message->addExtension(0x0010, hex2bin('ffff'));
        $this->assertTrue($message->isValid());
    }
} 