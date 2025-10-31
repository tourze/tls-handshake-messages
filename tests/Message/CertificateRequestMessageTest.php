<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateRequestMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * CertificateRequest消息测试类
 *
 * @internal
 */
#[CoversClass(CertificateRequestMessage::class)]
final class CertificateRequestMessageTest extends TestCase
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

    /**
     * 测试 addCertificateAuthority 方法
     */
    public function testAddCertificateAuthority(): void
    {
        $message = new CertificateRequestMessage();

        // 测试默认状态
        $this->assertEmpty($message->getCertificateAuthorities());

        // 测试添加第一个 CA
        $ca1 = 'CN=Test CA 1,O=Test Organization';
        $result = $message->addCertificateAuthority($ca1);

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 测试 CA 是否被添加
        $this->assertCount(1, $message->getCertificateAuthorities());
        $this->assertEquals([$ca1], $message->getCertificateAuthorities());

        // 测试添加第二个 CA
        $ca2 = 'CN=Test CA 2,O=Another Organization';
        $message->addCertificateAuthority($ca2);

        $this->assertCount(2, $message->getCertificateAuthorities());
        $this->assertEquals([$ca1, $ca2], $message->getCertificateAuthorities());
    }

    /**
     * 测试 addCertificateType 方法
     */
    public function testAddCertificateType(): void
    {
        $message = new CertificateRequestMessage();

        // 测试默认状态
        $this->assertEmpty($message->getCertificateTypes());

        // 测试添加第一个证书类型
        $type1 = 1; // rsa_sign
        $result = $message->addCertificateType($type1);

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 测试证书类型是否被添加
        $this->assertCount(1, $message->getCertificateTypes());
        $this->assertEquals([$type1], $message->getCertificateTypes());

        // 测试添加第二个证书类型
        $type2 = 2; // dss_sign
        $message->addCertificateType($type2);

        $this->assertCount(2, $message->getCertificateTypes());
        $this->assertEquals([$type1, $type2], $message->getCertificateTypes());

        // 测试添加重复类型
        $message->addCertificateType($type1);
        $this->assertCount(3, $message->getCertificateTypes());
        $this->assertEquals([$type1, $type2, $type1], $message->getCertificateTypes());
    }

    /**
     * 测试 addSignatureAlgorithm 方法
     */
    public function testAddSignatureAlgorithm(): void
    {
        $message = new CertificateRequestMessage();

        // 测试默认状态
        $this->assertEmpty($message->getSignatureAlgorithms());

        // 测试添加第一个签名算法
        $algo1 = 0x0403; // ecdsa_secp256r1_sha256
        $result = $message->addSignatureAlgorithm($algo1);

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 测试签名算法是否被添加
        $this->assertCount(1, $message->getSignatureAlgorithms());
        $this->assertEquals([$algo1], $message->getSignatureAlgorithms());

        // 测试添加第二个签名算法
        $algo2 = 0x0804; // rsa_pss_rsae_sha256
        $message->addSignatureAlgorithm($algo2);

        $this->assertCount(2, $message->getSignatureAlgorithms());
        $this->assertEquals([$algo1, $algo2], $message->getSignatureAlgorithms());

        // 测试添加不同格式的算法
        $algo3 = 0x0201; // rsa_pkcs1_sha1
        $message->addSignatureAlgorithm($algo3);

        $this->assertCount(3, $message->getSignatureAlgorithms());
        $this->assertEquals([$algo1, $algo2, $algo3], $message->getSignatureAlgorithms());
    }
}
