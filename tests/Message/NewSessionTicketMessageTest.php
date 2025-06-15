<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\NewSessionTicketMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * NewSessionTicket消息测试类 (TLS 1.3特有)
 */
class NewSessionTicketMessageTest extends TestCase
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
        $extensions = [
            0x0029 => hex2bin('0001'), // early_data扩展，数据0001
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());
        
        // 测试添加扩展
        $message = new NewSessionTicketMessage();
        $message->addExtension(0x0029, hex2bin('0001'));
        $this->assertCount(1, $message->getExtensions());
        $this->assertEquals(hex2bin('0001'), $message->getExtensions()[0x0029]);
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
        $originalMessage->setTicketNonce(hex2bin('0102030405'));
        $originalMessage->setTicket(hex2bin('0102030405060708090a0b0c0d0e0f1011121314'));
        
        // 设置扩展
        $originalMessage->addExtension(0x0029, hex2bin('0001')); // early_data扩展
        
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
        $message->setTicket(hex2bin('0102030405060708090a0b0c0d0e0f1011121314'));
        $this->assertTrue($message->isValid());
    }
} 