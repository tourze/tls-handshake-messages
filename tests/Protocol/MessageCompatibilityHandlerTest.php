<?php

namespace Tourze\TLSHandshakeMessages\Tests\Protocol;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;
use Tourze\TLSHandshakeMessages\Message\EncryptedExtensionsMessage;
use Tourze\TLSHandshakeMessages\Message\ServerHelloDoneMessage;
use Tourze\TLSHandshakeMessages\Message\ServerHelloMessage;
use Tourze\TLSHandshakeMessages\Protocol\MessageCompatibilityHandler;

/**
 * MessageCompatibilityHandler单元测试
 */
class MessageCompatibilityHandlerTest extends TestCase
{
    /**
     * 测试消息版本兼容性检测
     */
    public function testIsMessageCompatibleWithVersion(): void
    {
        // TLS 1.3特有的消息
        $encryptedExtensions = new EncryptedExtensionsMessage();
        $this->assertTrue(MessageCompatibilityHandler::isMessageCompatibleWithVersion(
            $encryptedExtensions,
            MessageCompatibilityHandler::TLS_VERSION_1_3
        ));
        $this->assertFalse(MessageCompatibilityHandler::isMessageCompatibleWithVersion(
            $encryptedExtensions,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        ));

        // TLS 1.2特有的消息
        $serverHelloDone = new ServerHelloDoneMessage();
        $this->assertTrue(MessageCompatibilityHandler::isMessageCompatibleWithVersion(
            $serverHelloDone,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        ));
        $this->assertFalse(MessageCompatibilityHandler::isMessageCompatibleWithVersion(
            $serverHelloDone,
            MessageCompatibilityHandler::TLS_VERSION_1_3
        ));
    }

    /**
     * 测试ClientHello消息兼容性处理
     */
    public function testAdaptClientHelloMessage(): void
    {
        // 创建一个同时包含TLS 1.2和TLS 1.3密码套件的ClientHello
        $clientHello = new ClientHelloMessage();
        $clientHello->setCipherSuites([
            0x1301, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            0x1302, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
            0xc030  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
        ]);

        // 适配到TLS 1.3版本
        $tlsV13ClientHello = MessageCompatibilityHandler::adaptMessageToVersion(
            $clientHello,
            MessageCompatibilityHandler::TLS_VERSION_1_3
        );

        // 只应保留TLS 1.3的密码套件
        $this->assertInstanceOf(ClientHelloMessage::class, $tlsV13ClientHello);
        $tlsV13CipherSuites = $tlsV13ClientHello->getCipherSuites();
        $this->assertCount(2, $tlsV13CipherSuites);
        $this->assertTrue(in_array(0x1301, $tlsV13CipherSuites));
        $this->assertTrue(in_array(0x1302, $tlsV13CipherSuites));
        $this->assertFalse(in_array(0xc02f, $tlsV13CipherSuites));
        $this->assertFalse(in_array(0xc030, $tlsV13CipherSuites));

        // 适配到TLS 1.2版本
        $tlsV12ClientHello = MessageCompatibilityHandler::adaptMessageToVersion(
            $clientHello,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        );

        // 只应保留TLS 1.2的密码套件
        $this->assertInstanceOf(ClientHelloMessage::class, $tlsV12ClientHello);
        $tlsV12CipherSuites = $tlsV12ClientHello->getCipherSuites();
        $this->assertCount(2, $tlsV12CipherSuites);
        $this->assertFalse(in_array(0x1301, $tlsV12CipherSuites));
        $this->assertFalse(in_array(0x1302, $tlsV12CipherSuites));
        $this->assertTrue(in_array(0xc02f, $tlsV12CipherSuites));
        $this->assertTrue(in_array(0xc030, $tlsV12CipherSuites));
    }

    /**
     * 测试无法适配的情况（不兼容的密码套件）
     */
    public function testIncompatibleCipherSuites(): void
    {
        // 只有TLS 1.3密码套件的ClientHello
        $clientHello = new ClientHelloMessage();
        $clientHello->setCipherSuites([
            0x1301, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            0x1302  // TLS_AES_256_GCM_SHA384 (TLS 1.3)
        ]);

        // 尝试适配到TLS 1.2版本，应抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("No compatible cipher suites available for target TLS version");
        MessageCompatibilityHandler::adaptMessageToVersion(
            $clientHello,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        );
    }

    /**
     * 测试不兼容的消息类型
     */
    public function testIncompatibleMessageType(): void
    {
        // TLS 1.3特有的消息
        $encryptedExtensions = new EncryptedExtensionsMessage();

        // 尝试适配到TLS 1.2版本，应抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Message type ENCRYPTED_EXTENSIONS is only available in TLS 1.3+");
        MessageCompatibilityHandler::adaptMessageToVersion(
            $encryptedExtensions,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        );
    }

    /**
     * 测试ServerHello消息的适配
     */
    public function testServerHelloAdaptation(): void
    {
        // 创建TLS 1.3 ServerHello
        $serverHello = new ServerHelloMessage();
        $serverHello->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256 (TLS 1.3)

        // 适配到TLS 1.3，应该成功
        $tlsV13ServerHello = MessageCompatibilityHandler::adaptMessageToVersion(
            $serverHello,
            MessageCompatibilityHandler::TLS_VERSION_1_3
        );
        $this->assertInstanceOf(ServerHelloMessage::class, $tlsV13ServerHello);
        $this->assertEquals(0x1301, $tlsV13ServerHello->getCipherSuite());

        // 尝试适配到TLS 1.2，应抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Selected TLS 1.3 cipher suite is not compatible with TLS 1.2");
        MessageCompatibilityHandler::adaptMessageToVersion(
            $serverHello,
            MessageCompatibilityHandler::TLS_VERSION_1_2
        );
    }
}
