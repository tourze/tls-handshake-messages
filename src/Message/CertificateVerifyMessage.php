<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 证书验证消息
 */
class CertificateVerifyMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::CERTIFICATE_VERIFY;

    /**
     * 签名算法
     */
    private int $signatureAlgorithm = 0;

    /**
     * 签名数据
     */
    private string $signature = '';

    /**
     * 获取签名算法
     *
     * @return int 签名算法
     */
    public function getSignatureAlgorithm(): int
    {
        return $this->signatureAlgorithm;
    }

    /**
     * 设置签名算法
     *
     * @param int $signatureAlgorithm 签名算法
     */
    public function setSignatureAlgorithm(int $signatureAlgorithm): void
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * 获取签名数据
     *
     * @return string 签名数据
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * 设置签名数据
     *
     * @param string $signature 签名数据
     */
    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 构造消息体
        $body = $this->encodeUint16($this->signatureAlgorithm);
        $body .= $this->encodeUint16(strlen($this->signature));
        $body .= $this->signature;

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::CERTIFICATE_VERIFY->value);
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
        if ($type !== HandshakeMessageType::CERTIFICATE_VERIFY->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取签名算法
        $message->signatureAlgorithm = self::decodeUint16($data, $offset);
        $offset += 2;

        // 读取签名长度
        $signatureLength = self::decodeUint16($data, $offset);
        $offset += 2;

        // 读取签名数据
        $message->signature = substr($data, $offset, $signatureLength);

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
        return '' !== $this->signature;
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
