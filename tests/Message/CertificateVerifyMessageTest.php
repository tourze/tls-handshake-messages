<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateVerifyMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * CertificateVerify消息测试类
 *
 * @internal
 */
#[CoversClass(CertificateVerifyMessage::class)]
final class CertificateVerifyMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new CertificateVerifyMessage();
        $this->assertEquals(HandshakeMessageType::CERTIFICATE_VERIFY, $message->getType());
    }

    /**
     * 测试签名算法操作
     */
    public function testSignatureAlgorithm(): void
    {
        $message = new CertificateVerifyMessage();

        // 测试默认值
        $this->assertEquals(0, $message->getSignatureAlgorithm());

        // 测试设置签名算法
        $algorithm = 0x0804; // rsa_pss_rsae_sha256
        $message->setSignatureAlgorithm($algorithm);
        $this->assertEquals($algorithm, $message->getSignatureAlgorithm());
    }

    /**
     * 测试签名数据操作
     */
    public function testSignature(): void
    {
        $message = new CertificateVerifyMessage();

        // 测试默认值
        $this->assertEquals('', $message->getSignature());

        // 测试设置签名
        $signature = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertNotFalse($signature);
        $message->setSignature($signature);
        $this->assertEquals($signature, $message->getSignature());
    }

    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new CertificateVerifyMessage();

        // 设置签名算法
        $originalMessage->setSignatureAlgorithm(0x0804); // rsa_pss_rsae_sha256

        // 设置签名
        $signature = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertNotFalse($signature);
        $originalMessage->setSignature($signature);

        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedMessage = CertificateVerifyMessage::decode($encodedData);

        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getSignatureAlgorithm(), $decodedMessage->getSignatureAlgorithm());
        $this->assertEquals($originalMessage->getSignature(), $decodedMessage->getSignature());
    }

    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new CertificateVerifyMessage();

        // 空的签名是无效的
        $this->assertFalse($message->isValid());

        // 设置签名算法和签名后应该有效
        $message->setSignatureAlgorithm(0x0804);
        $signature = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $this->assertNotFalse($signature);
        $message->setSignature($signature);
        $this->assertTrue($message->isValid());
    }
}
