<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * HelloRequest 消息（仅限 TLS 1.2 及以下版本）
 *
 * 服务器可以发送 HelloRequest 消息请求客户端重新进行握手
 */
class HelloRequestMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::HELLO_REQUEST;

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 根据测试要求，返回空字符串
        return '';
    }

    /**
     * 解码消息
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的消息对象
     */
    public static function decode(string $data): static
    {
        // 根据测试要求，允许空字符串作为输入
        return new static(); // @phpstan-ignore-line
    }

    /**
     * 编码24位无符号整数
     *
     * @param int $value 整数值
     *
     * @return string 编码后的二进制数据
     */
    protected function encodeUint24(int $value): string
    {
        return pack('C3', ($value >> 16) & 0xFF, ($value >> 8) & 0xFF, $value & 0xFF);
    }

    /**
     * 解码24位无符号整数
     *
     * @param string $data   二进制数据
     * @param int    $offset 偏移量
     *
     * @return int 解码后的整数值
     */
    protected static function decodeUint24(string $data, int $offset = 0): int
    {
        $unpacked = unpack('C3', substr($data, $offset, 3));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack 24-bit unsigned integer');
        }

        return ($unpacked[1] << 16) | ($unpacked[2] << 8) | $unpacked[3];
    }

    /**
     * 获取消息类型
     *
     * @return HandshakeMessageType 消息类型
     */
    public function getType(): HandshakeMessageType
    {
        return self::MESSAGE_TYPE;
    }
}
