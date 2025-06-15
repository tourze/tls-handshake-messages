<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateRequestMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * CertificateRequest消息测试类
 */
class CertificateRequestMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new CertificateRequestMessage();
        $this->assertEquals(HandshakeMessageType::CERTIFICATE_REQUEST, $message->getType());
    }
    
    /**
     * 测试证书类型操作
     */
    public function testCertificateTypes(): void
    {
        $message = new CertificateRequestMessage();
        
        // 测试默认值
        $this->assertEmpty($message->getCertificateTypes());
        
        // 测试设置证书类型
        $types = [1, 2]; // 1: rsa_sign, 2: dss_sign
        $message->setCertificateTypes($types);
        $this->assertEquals($types, $message->getCertificateTypes());
        
        // 测试添加证书类型
        $message = new CertificateRequestMessage();
        $message->addCertificateType(1);
        $this->assertCount(1, $message->getCertificateTypes());
        $this->assertEquals([1], $message->getCertificateTypes());
    }
    
    /**
     * 测试签名算法操作
     */
    public function testSignatureAlgorithms(): void
    {
        $message = new CertificateRequestMessage();
        
        // 测试默认值
        $this->assertEmpty($message->getSignatureAlgorithms());
        
        // 测试设置签名算法
        $algorithms = [
            0x0403, // ecdsa_secp256r1_sha256
            0x0804, // rsa_pss_rsae_sha256
        ];
        $message->setSignatureAlgorithms($algorithms);
        $this->assertEquals($algorithms, $message->getSignatureAlgorithms());
        
        // 测试添加签名算法
        $message = new CertificateRequestMessage();
        $message->addSignatureAlgorithm(0x0403);
        $this->assertCount(1, $message->getSignatureAlgorithms());
        $this->assertEquals([0x0403], $message->getSignatureAlgorithms());
    }
    
    /**
     * 测试可接受的CA名称操作
     */
    public function testCertificateAuthorities(): void
    {
        $message = new CertificateRequestMessage();
        
        // 测试默认值
        $this->assertEmpty($message->getCertificateAuthorities());
        
        // 测试设置CA名称
        $authorities = [
            'CN=Test CA 1',
            'CN=Test CA 2',
        ];
        $message->setCertificateAuthorities($authorities);
        $this->assertEquals($authorities, $message->getCertificateAuthorities());
        
        // 测试添加CA名称
        $message = new CertificateRequestMessage();
        $message->addCertificateAuthority('CN=Test CA');
        $this->assertCount(1, $message->getCertificateAuthorities());
        $this->assertEquals(['CN=Test CA'], $message->getCertificateAuthorities());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new CertificateRequestMessage();
        
        // 设置证书类型
        $originalMessage->setCertificateTypes([1, 2]); // rsa_sign, dss_sign
        
        // 设置签名算法
        $originalMessage->setSignatureAlgorithms([0x0403, 0x0804]);
        
        // 设置CA名称
        $originalMessage->setCertificateAuthorities(['CN=Test CA 1', 'CN=Test CA 2']);
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = CertificateRequestMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getCertificateTypes(), $decodedMessage->getCertificateTypes());
        $this->assertEquals($originalMessage->getSignatureAlgorithms(), $decodedMessage->getSignatureAlgorithms());
        $this->assertEquals($originalMessage->getCertificateAuthorities(), $decodedMessage->getCertificateAuthorities());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new CertificateRequestMessage();
        
        // 空的消息是无效的
        $this->assertFalse($message->isValid());
        
        // 至少要有一个证书类型才有效
        $message->addCertificateType(1);
        $this->assertTrue($message->isValid());
    }
}
