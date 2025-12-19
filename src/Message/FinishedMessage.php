<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * Finished 消息（握手完成）
 */
final class FinishedMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::FINISHED;

    /**
     * 验证数据
     */
    private string $verifyData = '';

    /**
     * 获取验证数据
     *
     * @return string 验证数据
     */
    public function getVerifyData(): string
    {
        return $this->verifyData;
    }

    /**
     * 设置验证数据
     *
     * @param string $verifyData 验证数据
     */
    public function setVerifyData(string $verifyData): void
    {
        $this->verifyData = $verifyData;
    }

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // Finished 消息体只包含验证数据
        $body = $this->verifyData;

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::FINISHED->value);
        $message .= $this->encodeUint24(strlen($body));
        $message .= $body;

        return $message;
    }

    /**
     * 解码消息
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的消息对象
     *
     * @throws InvalidMessageException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $message = new static();

        $offset = 0;

        // 验证消息类型
        $type = ord($data[$offset]);
        if ($type !== HandshakeMessageType::FINISHED->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取验证数据
        $message->verifyData = substr($data, $offset, $length);

        return $message;
    }

    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 最基本的验证：验证数据不能为空
        return '' !== $this->verifyData;
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
