<?php

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 握手消息接口
 */
interface HandshakeMessageInterface
{
    /**
     * 获取消息类型
     *
     * @return HandshakeMessageType 消息类型
     */
    public function getType(): HandshakeMessageType;
    
    /**
     * 将消息序列化为二进制数据
     *
     * @return string 序列化后的二进制数据
     */
    public function encode(): string;
    
    /**
     * 从二进制数据反序列化消息
     *
     * @param string $data 二进制数据
     * @return static 解析后的消息对象
     */
    public static function decode(string $data): static;
    
    /**
     * 获取消息长度
     *
     * @return int 消息长度（字节数）
     */
    public function getLength(): int;
    
    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool;
} 