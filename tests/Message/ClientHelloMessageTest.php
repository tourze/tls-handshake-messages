<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ClientHello消息测试
 *
 * @internal
 */
#[CoversClass(ClientHelloMessage::class)]
final class ClientHelloMessageTest extends TestCase
{
    public function testMessageType(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals(HandshakeMessageType::CLIENT_HELLO, $message->getType());
    }

    public function testVersion(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals(0x0303, $message->getVersion()); // Default is TLS 1.2

        $message->setVersion(0x0304); // TLS 1.3
        $this->assertEquals(0x0304, $message->getVersion());
    }

    public function testRandom(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals(32, strlen($message->getRandom())); // Default random is 32 bytes

        $random = str_repeat('A', 32);
        $message->setRandom($random);
        $this->assertEquals($random, $message->getRandom());

        $this->expectException(\InvalidArgumentException::class);
        $message->setRandom('too_short');
    }

    public function testSessionId(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals('', $message->getSessionId()); // Default is empty

        $sessionId = hex2bin('0102030405060708090A0B0C0D0E0F10');
        $this->assertNotFalse($sessionId);
        $message->setSessionId($sessionId);
        $this->assertEquals($sessionId, $message->getSessionId());

        $this->expectException(\InvalidArgumentException::class);
        $message->setSessionId(str_repeat('X', 33)); // Too long
    }

    public function testCipherSuites(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEmpty($message->getCipherSuites()); // Default is empty

        $cipherSuites = [0x1301, 0x1302, 0x1303]; // TLS 1.3 cipher suites
        $message->setCipherSuites($cipherSuites);
        $this->assertEquals($cipherSuites, $message->getCipherSuites());
    }

    public function testCompressionMethods(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals([0], $message->getCompressionMethods()); // Default is null compression

        $compressionMethods = [0, 1]; // null and DEFLATE
        $message->setCompressionMethods($compressionMethods);
        $this->assertEquals($compressionMethods, $message->getCompressionMethods());
    }

    public function testExtensions(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEmpty($message->getExtensions()); // Default is empty

        $ext10 = hex2bin('0017001d');
        $ext13 = hex2bin('00020403');
        $this->assertNotFalse($ext10);
        $this->assertNotFalse($ext13);
        $extensions = [
            10 => $ext10, // supported_groups: x25519, secp256r1
            13 => $ext13, // signature_algorithms: RSA-PSS-SHA256, ECDSA-SHA256
        ];

        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());

        // Test individual extension with new instance
        $message2 = new ClientHelloMessage();
        $serverNameExt = hex2bin('00000e7777772e676f6f676c652e636f6d'); // server_name: www.google.com
        $this->assertNotFalse($serverNameExt);
        $extensionType = 0; // Server Name extension type
        $message2->addExtension($extensionType, $serverNameExt);
        $allExtensions = $message2->getExtensions();
        $this->assertArrayHasKey($extensionType, $allExtensions);
        $this->assertEquals($serverNameExt, $allExtensions[$extensionType]);
    }

    public function testEncodeAndDecode(): void
    {
        $original = new ClientHelloMessage();
        $original->setVersion(0x0303); // TLS 1.2
        $original->setRandom(str_repeat("\x42", 32));
        $sessionId = hex2bin('0102030405060708');
        $this->assertNotFalse($sessionId);
        $original->setSessionId($sessionId);
        $original->setCipherSuites([0x1301, 0x1302]); // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        $original->setCompressionMethods([0]); // null compression
        $extData = hex2bin('00000e7777772e676f6f676c652e636f6d');
        $this->assertNotFalse($extData);
        $original->addExtension(0, $extData); // server_name: www.google.com

        // Encode message
        $encoded = $original->encode();
        // Decode message
        $decoded = ClientHelloMessage::decode($encoded);

        // Verify decoded message matches original
        $this->assertEquals($original->getVersion(), $decoded->getVersion());
        $this->assertEquals($original->getRandom(), $decoded->getRandom());
        $this->assertEquals($original->getSessionId(), $decoded->getSessionId());
        $this->assertEquals($original->getCipherSuites(), $decoded->getCipherSuites());
        $this->assertEquals($original->getCompressionMethods(), $decoded->getCompressionMethods());
        $this->assertEquals($original->getExtensions(), $decoded->getExtensions());
    }

    public function testValidity(): void
    {
        $message = new ClientHelloMessage();

        // 默认情况下无效，因为没有加密套件
        $this->assertFalse($message->isValid());

        // 添加加密套件后应有效
        $message->setCipherSuites([0x1301]);
        $this->assertTrue($message->isValid());

        // 更改随机数长度后应无效
        $reflection = new \ReflectionClass($message);
        $property = $reflection->getProperty('random');
        $property->setAccessible(true);
        $property->setValue($message, 'too_short');

        $this->assertFalse($message->isValid());
    }

    /**
     * 测试 addExtension 方法
     */
    public function testAddExtension(): void
    {
        $message = new ClientHelloMessage();

        // 测试默认状态
        $this->assertEmpty($message->getExtensions());

        // 测试添加第一个扩展
        $extType1 = 0; // server_name extension
        $extData1 = hex2bin('00000e7777772e676f6f676c652e636f6d'); // www.google.com
        $this->assertNotFalse($extData1);
        $message->addExtension($extType1, $extData1);

        // 测试扩展是否被添加
        $extensions = $message->getExtensions();
        $this->assertCount(1, $extensions);
        $this->assertArrayHasKey($extType1, $extensions);
        $this->assertEquals($extData1, $extensions[$extType1]);

        // 测试添加第二个扩展
        $extType2 = 10; // supported_groups extension
        $extData2 = hex2bin('0017001d'); // x25519, secp256r1
        $this->assertNotFalse($extData2);
        $message->addExtension($extType2, $extData2);

        $extensions = $message->getExtensions();
        $this->assertCount(2, $extensions);
        $this->assertArrayHasKey($extType2, $extensions);
        $this->assertEquals($extData2, $extensions[$extType2]);

        // 测试覆盖已存在的扩展
        $extData1New = hex2bin('00000f7777772e6578616d706c652e636f6d'); // www.example.com
        $this->assertNotFalse($extData1New);
        $message->addExtension($extType1, $extData1New);

        $extensions = $message->getExtensions();
        $this->assertCount(2, $extensions); // 数量不变
        $this->assertEquals($extData1New, $extensions[$extType1]); // 数据被覆盖

        // 测试添加空数据扩展
        $extType3 = 23; // session_ticket extension
        $extData3 = '';
        $message->addExtension($extType3, $extData3);

        $extensions = $message->getExtensions();
        $this->assertCount(3, $extensions);
        $this->assertArrayHasKey($extType3, $extensions);
        $this->assertEquals($extData3, $extensions[$extType3]);
    }
}
