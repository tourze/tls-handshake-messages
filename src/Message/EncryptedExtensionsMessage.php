<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 加密扩展消息（TLS 1.3）
 */
final class EncryptedExtensionsMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::ENCRYPTED_EXTENSIONS;

    /**
     * 扩展列表
     *
     * @var array<int, string>
     */
    private array $extensions = [];

    /**
     * 获取扩展列表
     *
     * @return array<int, string> 扩展列表
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    /**
     * 设置扩展列表
     *
     * @param array<int, string> $extensions 扩展列表
     */
    public function setExtensions(array $extensions): void
    {
        $this->extensions = $extensions;
    }

    /**
     * 添加扩展
     *
     * @param int    $type 扩展类型
     * @param string $data 扩展数据
     */
    public function addExtension(int $type, string $data): void
    {
        $this->extensions[$type] = $data;
    }

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 编码扩展数据
        $extensionsData = '';
        foreach ($this->extensions as $type => $data) {
            $extensionsData .= $this->encodeUint16($type);
            $extensionsData .= $this->encodeUint16(strlen($data));
            $extensionsData .= $data;
        }

        // 构造消息体
        $body = $this->encodeUint16(strlen($extensionsData));
        $body .= $extensionsData;

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::ENCRYPTED_EXTENSIONS->value);
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
        if ($type !== HandshakeMessageType::ENCRYPTED_EXTENSIONS->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取扩展总长度
        $extensionsLength = self::decodeUint16($data, $offset);
        $offset += 2;

        // 读取扩展数据
        $extensionsEnd = $offset + $extensionsLength;
        $message->extensions = [];

        while ($offset < $extensionsEnd) {
            $extType = self::decodeUint16($data, $offset);
            $offset += 2;

            $extLength = self::decodeUint16($data, $offset);
            $offset += 2;

            $extData = substr($data, $offset, $extLength);
            $offset += $extLength;

            $message->extensions[$extType] = $extData;
        }

        return $message;
    }

    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 最基本的验证，这里简单返回true
        return true;
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
