<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ServerHelloDoneMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ServerHelloDone消息测试类
 */
class ServerHelloDoneMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ServerHelloDoneMessage();
        $this->assertEquals(HandshakeMessageType::SERVER_HELLO_DONE, $message->getType());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new ServerHelloDoneMessage();
        
        // 编码
        $encodedData = $originalMessage->encode();
        
        // ServerHelloDone消息没有内容，所以编码后应该是空字符串
        $this->assertEquals('', $encodedData);
        
        // 解码
        $decodedMessage = ServerHelloDoneMessage::decode($encodedData);
        
        // 确认消息类型一致
        $this->assertEquals($originalMessage->getType(), $decodedMessage->getType());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new ServerHelloDoneMessage();
        
        // ServerHelloDone消息总是有效的
        $this->assertTrue($message->isValid());
    }
}
