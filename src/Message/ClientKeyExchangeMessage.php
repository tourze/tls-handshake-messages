<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 客户端密钥交换消息
 */
class ClientKeyExchangeMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::CLIENT_KEY_EXCHANGE;

    /**
     * 加密的预主密钥
     */
    private string $encryptedPreMasterSecret = '';

    /**
     * 获取加密的预主密钥
     *
     * @return string 加密的预主密钥
     */
    public function getEncryptedPreMasterSecret(): string
    {
        return $this->encryptedPreMasterSecret;
    }

    /**
     * 设置加密的预主密钥
     *
     * @param string $encryptedPreMasterSecret 加密的预主密钥
     */
    public function setEncryptedPreMasterSecret(string $encryptedPreMasterSecret): void
    {
        $this->encryptedPreMasterSecret = $encryptedPreMasterSecret;
    }

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 对于RSA密钥交换，预主密钥前面需要加上长度
        $body = pack('n', strlen($this->encryptedPreMasterSecret)) . $this->encryptedPreMasterSecret;

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::CLIENT_KEY_EXCHANGE->value);
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
        $message = new static(); // @phpstan-ignore-line

        $offset = 0;

        // 验证消息类型
        $type = ord($data[$offset]);
        if ($type !== HandshakeMessageType::CLIENT_KEY_EXCHANGE->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取加密预主密钥长度
        $unpacked = unpack('n', substr($data, $offset, 2));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack pre-master secret length');
        }
        $secretLength = $unpacked[1];
        $offset += 2;

        // 读取加密预主密钥
        if ($offset + $secretLength > strlen($data)) {
            throw new InvalidMessageException('Invalid pre-master secret length');
        }

        $message->encryptedPreMasterSecret = substr($data, $offset, $secretLength);

        return $message;
    }

    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 最基本的验证
        return '' !== $this->encryptedPreMasterSecret;
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
