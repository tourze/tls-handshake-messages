<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 握手消息的抽象基类
 */
abstract class AbstractHandshakeMessage implements HandshakeMessageInterface
{
    /**
     * 获取消息类型
     *
     * @return HandshakeMessageType 消息类型
     */
    abstract public function getType(): HandshakeMessageType;

    /**
     * 获取消息长度
     *
     * @return int 消息长度（字节数）
     */
    public function getLength(): int
    {
        return strlen($this->encode());
    }

    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        return true;
    }

    /**
     * 编码16位无符号整数
     *
     * @param int $value 整数值
     *
     * @return string 编码后的二进制数据
     */
    protected function encodeUint16(int $value): string
    {
        return pack('n', $value);
    }

    /**
     * 编码32位无符号整数
     *
     * @param int $value 整数值
     *
     * @return string 编码后的二进制数据
     */
    protected function encodeUint32(int $value): string
    {
        return pack('N', $value);
    }

    /**
     * 编码8位无符号整数
     *
     * @param int $value 整数值
     *
     * @return string 编码后的二进制数据
     */
    protected function encodeUint8(int $value): string
    {
        return pack('C', $value);
    }

    /**
     * 解码16位无符号整数
     *
     * @param string $data   二进制数据
     * @param int    $offset 偏移量
     *
     * @return int 解码后的整数值
     */
    protected static function decodeUint16(string $data, int $offset = 0): int
    {
        $unpacked = unpack('n', substr($data, $offset, 2));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack 16-bit unsigned integer');
        }

        return $unpacked[1];
    }

    /**
     * 解码32位无符号整数
     *
     * @param string $data   二进制数据
     * @param int    $offset 偏移量
     *
     * @return int 解码后的整数值
     */
    protected static function decodeUint32(string $data, int $offset = 0): int
    {
        $unpacked = unpack('N', substr($data, $offset, 4));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack 32-bit unsigned integer');
        }

        return $unpacked[1];
    }

    /**
     * 解码8位无符号整数
     *
     * @param string $data   二进制数据
     * @param int    $offset 偏移量
     *
     * @return int 解码后的整数值
     */
    protected static function decodeUint8(string $data, int $offset = 0): int
    {
        $unpacked = unpack('C', substr($data, $offset, 1));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack 8-bit unsigned integer');
        }

        return $unpacked[1];
    }
}
