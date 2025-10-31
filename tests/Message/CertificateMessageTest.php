<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * Certificate消息测试类
 *
 * @internal
 */
#[CoversClass(CertificateMessage::class)]
final class CertificateMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new CertificateMessage();
        $this->assertEquals(HandshakeMessageType::CERTIFICATE, $message->getType());
    }

    /**
     * 测试证书链操作
     */
    public function testCertificateChain(): void
    {
        $message = new CertificateMessage();

        // 测试默认值
        $this->assertEmpty($message->getCertificateChain());

        // 测试添加证书
        $cert1 = str_repeat('A', 50); // 模拟证书数据
        $cert2 = str_repeat('B', 60); // 模拟证书数据

        $message->addCertificate($cert1);
        $this->assertCount(1, $message->getCertificateChain());

        $message->addCertificate($cert2);
        $this->assertCount(2, $message->getCertificateChain());

        // 测试设置证书链
        $certificates = [$cert1, $cert2];
        $message->setCertificateChain($certificates);
        $this->assertEquals($certificates, $message->getCertificateChain());
    }

    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new CertificateMessage();

        // 添加证书
        $cert1 = str_repeat('A', 50);
        $cert2 = str_repeat('B', 60);
        $originalMessage->addCertificate($cert1);
        $originalMessage->addCertificate($cert2);

        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedMessage = CertificateMessage::decode($encodedData);

        // 比较原始消息和解码后的消息
        $this->assertCount(count($originalMessage->getCertificateChain()), $decodedMessage->getCertificateChain());
        $this->assertEquals($originalMessage->getCertificateChain(), $decodedMessage->getCertificateChain());
    }

    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new CertificateMessage();

        // 空的证书链是无效的
        $this->assertFalse($message->isValid());

        // 添加证书后应该有效
        $message->addCertificate(str_repeat('A', 50));
        $this->assertTrue($message->isValid());
    }

    /**
     * 测试证书格式错误情况
     */
    public function testInvalidCertificateFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // 创建一个包含证书长度但实际数据长度不够的二进制数据
        $data = "\x00\x00\x03too"; // 声明长度3但实际没有足够的数据
        CertificateMessage::decode($data);
    }

    /**
     * 测试 addCertificate 方法
     */
    public function testAddCertificate(): void
    {
        $message = new CertificateMessage();

        // 测试默认状态
        $this->assertEmpty($message->getCertificateChain());

        // 测试添加第一个证书
        $cert1 = str_repeat('A', 50);
        $result = $message->addCertificate($cert1);

        // 测试返回值（链式调用）
        $this->assertSame($message, $result);

        // 测试证书是否被添加
        $this->assertCount(1, $message->getCertificateChain());
        $this->assertEquals([$cert1], $message->getCertificateChain());

        // 测试添加第二个证书
        $cert2 = str_repeat('B', 60);
        $message->addCertificate($cert2);

        $this->assertCount(2, $message->getCertificateChain());
        $this->assertEquals([$cert1, $cert2], $message->getCertificateChain());

        // 测试添加空证书
        $message->addCertificate('');
        $this->assertCount(3, $message->getCertificateChain());

        // 消息因为空证书而变得无效
        $this->assertFalse($message->isValid());
    }
}
