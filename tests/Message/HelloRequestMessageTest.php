<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\HelloRequestMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * HelloRequest消息测试类
 */
class HelloRequestMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new HelloRequestMessage();
        $this->assertEquals(HandshakeMessageType::HELLO_REQUEST, $message->getType());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new HelloRequestMessage();
        
        // 编码
        $encodedData = $originalMessage->encode();
        
        // HelloRequest消息没有内容，所以编码后应该是空字符串
        $this->assertEquals('', $encodedData);
        
        // 解码
        $decodedMessage = HelloRequestMessage::decode($encodedData);
        
        // 确认消息类型一致
        $this->assertEquals($originalMessage->getType(), $decodedMessage->getType());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new HelloRequestMessage();
        
        // HelloRequest消息总是有效的
        $this->assertTrue($message->isValid());
    }
} 