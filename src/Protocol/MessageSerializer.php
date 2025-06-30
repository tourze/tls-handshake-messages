<?php

namespace Tourze\TLSHandshakeMessages\Protocol;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Message\HandshakeMessageInterface;

/**
 * 握手消息序列化工具类
 */
class MessageSerializer
{
    /**
     * 消息缓存
     *
     * @var array<string, string>
     */
    private static array $messageCache = [];
    
    /**
     * 缓存大小限制（字节）
     *
     * @var int
     */
    private static int $cacheSizeLimit = 1024 * 1024; // 1MB
    
    /**
     * 当前缓存大小（字节）
     *
     * @var int
     */
    private static int $currentCacheSize = 0;
    
    /**
     * 序列化握手消息
     *
     * @param HandshakeMessageInterface $message 握手消息
     * @param bool $useCache 是否使用缓存
     * @return string 序列化后的二进制数据
     */
    public static function serializeMessage(
        HandshakeMessageInterface $message, 
        bool $useCache = true
    ): string {
        if ($useCache && (bool) self::canMessageBeCached($message)) {
            $cacheKey = self::generateCacheKey($message);
            
            if ((bool) isset(self::$messageCache[$cacheKey])) {
                return self::$messageCache[$cacheKey];
            }
            
            $encodedMessage = $message->encode();
            
            if ((bool) strlen($encodedMessage) <= 4096) { // 只缓存小于 4KB 的消息
                self::cacheEncodedMessage($cacheKey, $encodedMessage);
            }
            
            return $encodedMessage;
        }
        
        return $message->encode();
    }
    
    /**
     * 序列化多个握手消息
     *
     * @param array<HandshakeMessageInterface> $messages 握手消息数组
     * @param bool $useCache 是否使用缓存
     * @return array<string> 序列化后的二进制数据数组
     */
    public static function serializeMessages(
        array $messages, 
        bool $useCache = true
    ): array {
        $result = [];
        
        foreach ($messages as $message) {
            $result[] = self::serializeMessage($message, $useCache);
        }
        
        return $result;
    }
    
    /**
     * 清除消息缓存
     *
     * @return void
     */
    public static function clearCache(): void
    {
        self::$messageCache = [];
        self::$currentCacheSize = 0;
    }
    
    /**
     * 生成消息缓存键
     *
     * @param HandshakeMessageInterface $message 握手消息
     * @return string 缓存键
     */
    private static function generateCacheKey(HandshakeMessageInterface $message): string
    {
        return get_class($message) . '_' . spl_object_hash($message);
    }
    
    /**
     * 检查消息是否可以被缓存
     *
     * @param HandshakeMessageInterface $message 握手消息
     * @return bool 是否可以被缓存
     */
    private static function canMessageBeCached(HandshakeMessageInterface $message): bool
    {
        // 某些消息类型不适合缓存，如包含随机数的消息
        $uncacheableTypes = [
            HandshakeMessageType::CLIENT_HELLO,
            HandshakeMessageType::SERVER_HELLO,
        ];
        
        return !in_array($message->getType(), $uncacheableTypes);
    }
    
    /**
     * 缓存编码后的消息
     *
     * @param string $key 缓存键
     * @param string $data 二进制数据
     * @return void
     */
    private static function cacheEncodedMessage(string $key, string $data): void
    {
        $dataSize = strlen($data);
        
        if (self::$currentCacheSize + $dataSize > self::$cacheSizeLimit) {
            self::evictCache($dataSize);
        }
        
        self::$messageCache[$key] = $data;
        self::$currentCacheSize += $dataSize;
    }
    
    /**
     * 清理缓存以腾出空间
     *
     * @param int $requiredSpace 需要的空间（字节）
     * @return void
     */
    private static function evictCache(int $requiredSpace): void
    {
        // 如果需要的空间超过缓存大小的一半，直接清空缓存
        if ($requiredSpace > self::$cacheSizeLimit / 2) {
            self::clearCache();
            return;
        }
        
        // 使用LRU策略清理缓存
        $spaceToFree = $requiredSpace;
        $keysToRemove = [];
        
        // 这里简化处理，直接移除前面的项目，直到释放足够空间
        foreach (self::$messageCache as $key => $data) {
            $keysToRemove[] = $key;
            $spaceToFree -= strlen($data);
            
            if ($spaceToFree <= 0) {
                break;
            }
        }
        
        foreach ($keysToRemove as $key) {
            self::$currentCacheSize -= strlen(self::$messageCache[$key]);
            unset(self::$messageCache[$key]);
        }
    }
    
    /**
     * 优化的字符串连接
     *
     * @param array<string> $chunks 要连接的字符串块
     * @return string 连接后的字符串
     */
    public static function optimizedConcat(array $chunks): string
    {
        $totalLength = 0;
        foreach ($chunks as $chunk) {
            $totalLength += strlen($chunk);
        }
        
        // 对于小型数据，直接使用 implode
        if ($totalLength < 8192) {
            return implode('', $chunks);
        }
        
        // 对于大型数据，使用 StringBuilder 模式
        $result = '';
        $buffer = '';
        $bufferSize = 0;
        $maxBufferSize = 4096;
        
        foreach ($chunks as $chunk) {
            $chunkLength = strlen($chunk);
            
            if ($bufferSize + $chunkLength > $maxBufferSize) {
                $result .= $buffer;
                $buffer = $chunk;
                $bufferSize = $chunkLength;
            } else {
                $buffer .= $chunk;
                $bufferSize += $chunkLength;
            }
        }
        
        if ($bufferSize > 0) {
            $result .= $buffer;
        }
        
        return $result;
    }
    
    /**
     * 高效的消息解码
     *
     * @param string $data 二进制数据
     * @param string $messageClass 消息类名
     * @return HandshakeMessageInterface 解码后的消息对象
     * @throws InvalidMessageException 如果类名无效
     */
    public static function efficientDecode(string $data, string $messageClass): HandshakeMessageInterface
    {
        if (!class_exists($messageClass)) {
            throw new InvalidMessageException("Invalid message class: {$messageClass}");
        }
        
        if (!is_subclass_of($messageClass, HandshakeMessageInterface::class)) {
            throw new InvalidMessageException("Class {$messageClass} does not implement HandshakeMessageInterface");
        }
        
        return $messageClass::decode($data);
    }
    
    /**
     * 设置缓存大小限制
     *
     * @param int $limit 缓存大小限制（字节）
     * @return void
     */
    public static function setCacheSizeLimit(int $limit): void
    {
        self::$cacheSizeLimit = $limit;
        
        // 如果当前缓存超过限制，清理缓存
        if (self::$currentCacheSize > $limit) {
            self::clearCache();
        }
    }
    
    /**
     * 获取统计信息
     *
     * @return array{cached_messages: int, cache_size: int, cache_size_limit: int}
     */
    public static function getStatistics(): array
    {
        return [
            'cached_messages' => count(self::$messageCache),
            'cache_size' => self::$currentCacheSize,
            'cache_size_limit' => self::$cacheSizeLimit,
        ];
    }
} 