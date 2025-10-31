<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ServerKeyExchangeMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ServerKeyExchange消息测试类
 *
 * @internal
 */
#[CoversClass(ServerKeyExchangeMessage::class)]
final class ServerKeyExchangeMessageTest extends TestCase
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
        $this->assertIsString($params);
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
        $this->assertIsString($signature);
        $message->setSignature($signature);
        $this->assertEquals($signature, $message->getSignature());
    }

    /**
     * 测试编码方法
     */
    public function testEncode(): void
    {
        // 测试只有密钥交换参数的编码
        $message = new ServerKeyExchangeMessage();
        $keyExchangeParams = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertIsString($keyExchangeParams);
        $message->setKeyExchangeParams($keyExchangeParams);

        $encodedData = $message->encode();
        $this->assertNotEmpty($encodedData);

        // 验证编码格式：消息类型(1字节) + 长度(3字节) + 密钥交换参数
        $this->assertEquals(HandshakeMessageType::SERVER_KEY_EXCHANGE->value, ord($encodedData[0]));

        // 解码长度字段
        $length = (ord($encodedData[1]) << 16) | (ord($encodedData[2]) << 8) | ord($encodedData[3]);
        $this->assertEquals(strlen($keyExchangeParams), $length);

        // 验证密钥交换参数
        $this->assertEquals($keyExchangeParams, substr($encodedData, 4, $length));

        // 测试包含签名的编码
        $messageWithSignature = new ServerKeyExchangeMessage();
        $messageWithSignature->setKeyExchangeParams($keyExchangeParams);
        $messageWithSignature->setSignatureAlgorithm(0x0403); // ecdsa_secp256r1_sha256
        $signature = hex2bin('abcdef0123456789');
        $this->assertIsString($signature);
        $messageWithSignature->setSignature($signature);

        $encodedWithSignature = $messageWithSignature->encode();
        $this->assertNotEmpty($encodedWithSignature);

        // 验证包含签名的编码长度更长
        $this->assertGreaterThan(strlen($encodedData), strlen($encodedWithSignature));

        // 测试空密钥交换参数的编码
        $emptyMessage = new ServerKeyExchangeMessage();
        $encodedEmpty = $emptyMessage->encode();
        $this->assertNotEmpty($encodedEmpty);

        // 验证空消息的最小长度：消息类型(1字节) + 长度(3字节) + 空内容
        $this->assertEquals(4, strlen($encodedEmpty));
        $this->assertEquals(0, (ord($encodedEmpty[1]) << 16) | (ord($encodedEmpty[2]) << 8) | ord($encodedEmpty[3]));
    }

    /**
     * 测试基本编码和解码
     */
    public function testBasicEncodeAndDecode(): void
    {
        $originalMessage = new ServerKeyExchangeMessage();

        // 设置密钥交换参数
        $keyExchangeParams = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertIsString($keyExchangeParams);
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
        $keyParams = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertIsString($keyParams);
        $message->setKeyExchangeParams($keyParams);
        $this->assertTrue($message->isValid());
    }
}
