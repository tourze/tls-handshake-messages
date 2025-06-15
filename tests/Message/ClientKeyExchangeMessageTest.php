<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ClientKeyExchangeMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ClientKeyExchange消息测试类
 */
class ClientKeyExchangeMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ClientKeyExchangeMessage();
        $this->assertEquals(HandshakeMessageType::CLIENT_KEY_EXCHANGE, $message->getType());
    }
    
    /**
     * 测试加密预主密钥操作
     */
    public function testEncryptedPreMasterSecret(): void
    {
        $message = new ClientKeyExchangeMessage();
        
        // 测试默认值
        $this->assertEquals('', $message->getEncryptedPreMasterSecret());
        
        // 测试设置加密预主密钥
        $secret = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $message->setEncryptedPreMasterSecret($secret);
        $this->assertEquals($secret, $message->getEncryptedPreMasterSecret());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new ClientKeyExchangeMessage();
        
        // 设置加密预主密钥
        $secret = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $originalMessage->setEncryptedPreMasterSecret($secret);
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = ClientKeyExchangeMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getEncryptedPreMasterSecret(), $decodedMessage->getEncryptedPreMasterSecret());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new ClientKeyExchangeMessage();
        
        // 空的加密预主密钥是无效的
        $this->assertFalse($message->isValid());
        
        // 设置加密预主密钥后应该有效
        $message->setEncryptedPreMasterSecret(hex2bin('0102030405060708090a0b0c0d0e0f10'));
        $this->assertTrue($message->isValid());
    }
} 