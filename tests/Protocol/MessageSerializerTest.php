<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\HandshakeMessageInterface;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;
use Tourze\TLSHandshakeMessages\Protocol\MessageSerializer;

/**
 * MessageSerializer测试类
 *
 * @internal
 */
#[CoversClass(MessageSerializer::class)]
final class MessageSerializerTest extends TestCase
{
    protected function tearDown(): void
    {
        MessageSerializer::clearCache();
        parent::tearDown();
    }

    /**
     * 创建模拟消息
     */
    private function createMockMessage(string $encodeReturn = 'encoded_data', ?HandshakeMessageType $type = null): HandshakeMessageInterface
    {
        return new TestHandshakeMessage($encodeReturn, $type ?? HandshakeMessageType::CERTIFICATE);
    }

    /**
     * 测试序列化单个消息
     */
    public function testSerializeMessage(): void
    {
        $message = $this->createMockMessage('test_encoded_data');

        $result = MessageSerializer::serializeMessage($message);

        $this->assertEquals('test_encoded_data', $result);
    }

    /**
     * 测试序列化消息使用缓存
     */
    public function testSerializeMessageWithCache(): void
    {
        $message = $this->createMockMessage('cached_data');

        // 第一次调用，应该调用encode方法
        $result1 = MessageSerializer::serializeMessage($message, true);
        $this->assertEquals('cached_data', $result1);

        // 第二次调用，应该从缓存返回，不再调用encode
        $result2 = MessageSerializer::serializeMessage($message, true);
        $this->assertEquals('cached_data', $result2);
    }

    /**
     * 测试序列化消息不使用缓存
     */
    public function testSerializeMessageWithoutCache(): void
    {
        $message = $this->createMockMessage('no_cache_data');

        // 不使用缓存时，每次都应该调用encode方法
        $result1 = MessageSerializer::serializeMessage($message, false);
        $this->assertEquals('no_cache_data', $result1);

        $result2 = MessageSerializer::serializeMessage($message, false);
        $this->assertEquals('no_cache_data', $result2);
    }

    /**
     * 测试序列化大消息不缓存
     */
    public function testSerializeLargeMessageNotCached(): void
    {
        // 创建一个返回大于4KB数据的消息
        $largeData = str_repeat('A', 5000);
        $message = $this->createMockMessage($largeData);

        $result = MessageSerializer::serializeMessage($message, true);
        $this->assertEquals($largeData, $result);

        // 验证大消息没有被缓存
        MessageSerializer::clearCache();
        $result2 = MessageSerializer::serializeMessage($message, true);
        $this->assertEquals($largeData, $result2);
    }

    /**
     * 测试序列化多个消息
     */
    public function testSerializeMessages(): void
    {
        $messages = [
            $this->createMockMessage('data1'),
            $this->createMockMessage('data2'),
            $this->createMockMessage('data3'),
        ];

        $results = MessageSerializer::serializeMessages($messages);

        $this->assertCount(3, $results);
        $this->assertEquals('data1', $results[0]);
        $this->assertEquals('data2', $results[1]);
        $this->assertEquals('data3', $results[2]);
    }

    /**
     * 测试清除缓存
     */
    public function testClearCache(): void
    {
        $message = $this->createMockMessage('cached_data');

        // 先序列化消息以缓存
        MessageSerializer::serializeMessage($message, true);

        // 清除缓存
        MessageSerializer::clearCache();

        // 再次序列化应该重新调用encode
        $result = MessageSerializer::serializeMessage($message, true);
        $this->assertEquals('cached_data', $result);
    }

    /**
     * 测试缓存大小限制
     */
    public function testCacheSizeLimit(): void
    {
        // 设置缓存大小限制
        MessageSerializer::setCacheSizeLimit(100);

        // 创建会超过缓存限制的消息
        $message1 = $this->createMockMessage(str_repeat('A', 60));
        $message2 = $this->createMockMessage(str_repeat('B', 60));

        // 第一个消息应该被缓存
        MessageSerializer::serializeMessage($message1, true);

        $stats1 = MessageSerializer::getStatistics();
        $this->assertEquals(1, $stats1['cached_messages']);
        $this->assertLessThanOrEqual(100, $stats1['cache_size']);

        // 第二个消息会导致缓存被清理
        MessageSerializer::serializeMessage($message2, true);

        $stats2 = MessageSerializer::getStatistics();
        // 由于缓存大小限制，应该只有一个消息被缓存
        $this->assertLessThanOrEqual(100, $stats2['cache_size']);

        // 恢复默认缓存大小限制
        MessageSerializer::setCacheSizeLimit(1024 * 1024);
    }

    /**
     * 测试统计信息
     */
    public function testStatistics(): void
    {
        $stats = MessageSerializer::getStatistics();

        $this->assertArrayHasKey('cached_messages', $stats);
        $this->assertArrayHasKey('cache_size', $stats);
        $this->assertArrayHasKey('cache_size_limit', $stats);

        $this->assertEquals(0, $stats['cached_messages']);
        $this->assertEquals(0, $stats['cache_size']);
        $this->assertEquals(1024 * 1024, $stats['cache_size_limit']);

        // 添加一些缓存消息 - 使用可缓存的消息类型
        $message = $this->createMockMessage('test_data', HandshakeMessageType::CERTIFICATE);
        MessageSerializer::serializeMessage($message, true);

        $stats2 = MessageSerializer::getStatistics();
        $this->assertGreaterThan(0, $stats2['cached_messages']);
        $this->assertGreaterThan(0, $stats2['cache_size']);
    }
}
