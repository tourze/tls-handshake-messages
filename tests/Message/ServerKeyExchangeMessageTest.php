<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ServerKeyExchangeMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ServerKeyExchange消息测试类
 */
class ServerKeyExchangeMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ServerKeyExchangeMessage();
        $this->assertEquals(HandshakeMessageType::SERVER_KEY_EXCHANGE, $message->getType());
    }
    
    /**
     * 测试密钥交换参数操作
     */
    public function testKeyExchangeParams(): void
    {
        $message = new ServerKeyExchangeMessage();
        
        // 测试默认值
        $this->assertEquals('', $message->getKeyExchangeParams());
        
        // 测试设置密钥交换参数
        $params = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $message->setKeyExchangeParams($params);
        $this->assertEquals($params, $message->getKeyExchangeParams());
    }
    
    /**
     * 测试签名算法操作
     */
    public function testSignatureAlgorithm(): void
    {
        $message = new ServerKeyExchangeMessage();
        
        // 测试默认值
        $this->assertEquals(0, $message->getSignatureAlgorithm());
        
        // 测试设置签名算法
        $algorithm = 0x0403; // ecdsa_secp256r1_sha256
        $message->setSignatureAlgorithm($algorithm);
        $this->assertEquals($algorithm, $message->getSignatureAlgorithm());
    }
    
    /**
     * 测试签名数据操作
     */
    public function testSignature(): void
    {
        $message = new ServerKeyExchangeMessage();
        
        // 测试默认值
        $this->assertEquals('', $message->getSignature());
        
        // 测试设置签名
        $signature = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $message->setSignature($signature);
        $this->assertEquals($signature, $message->getSignature());
    }
    
    /**
     * 测试基本编码和解码
     */
    public function testBasicEncodeAndDecode(): void
    {
        $originalMessage = new ServerKeyExchangeMessage();
        
        // 设置密钥交换参数
        $keyExchangeParams = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $originalMessage->setKeyExchangeParams($keyExchangeParams);
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = ServerKeyExchangeMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getKeyExchangeParams(), $decodedMessage->getKeyExchangeParams());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new ServerKeyExchangeMessage();
        
        // 空的密钥交换参数是无效的
        $this->assertFalse($message->isValid());
        
        // 设置密钥交换参数后应该有效
        $message->setKeyExchangeParams(hex2bin('0102030405060708090a0b0c0d0e0f10'));
        $this->assertTrue($message->isValid());
    }
}
