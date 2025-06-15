<?php

namespace Tourze\TLSHandshakeMessages\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * ClientHello消息测试
 */
class ClientHelloMessageTest extends TestCase
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
        
        $extensions = [
            10 => hex2bin('0017001d'), // supported_groups: x25519, secp256r1
            13 => hex2bin('00020403'), // signature_algorithms: RSA-PSS-SHA256, ECDSA-SHA256
        ];
        
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());
        
        // Test individual extension
        $serverNameExt = hex2bin('00000e7777772e676f6f676c652e636f6d'); // server_name: www.google.com
        $message->addExtension(0, $serverNameExt);
        $this->assertEquals($serverNameExt, $message->getExtensions()[0]);
    }
    
    public function testEncodeAndDecode(): void
    {
        $original = new ClientHelloMessage();
        $original->setVersion(0x0303); // TLS 1.2
        $original->setRandom(str_repeat("\x42", 32));
        $original->setSessionId(hex2bin('0102030405060708'));
        $original->setCipherSuites([0x1301, 0x1302]); // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        $original->setCompressionMethods([0]); // null compression
        $original->addExtension(0, hex2bin('00000e7777772e676f6f676c652e636f6d')); // server_name: www.google.com
        
        // Encode message
        $encoded = $original->encode();
        $this->assertIsString($encoded);
        
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
} 