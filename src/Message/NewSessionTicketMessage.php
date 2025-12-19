<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 新会话票据消息（TLS 1.3特有）
 */
final class NewSessionTicketMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::NEW_SESSION_TICKET;

    /**
     * 票据生命周期（秒）
     */
    private int $ticketLifetime = 0;

    /**
     * 票据年龄附加值
     */
    private int $ticketAgeAdd = 0;

    /**
     * 票据随机数
     */
    private string $ticketNonce = '';

    /**
     * 票据数据
     */
    private string $ticket = '';

    /**
     * 扩展数据
     *
     * @var array<int, string>
     */
    private array $extensions = [];

    /**
     * 获取票据生命周期
     *
     * @return int 票据生命周期（秒）
     */
    public function getTicketLifetime(): int
    {
        return $this->ticketLifetime;
    }

    /**
     * 设置票据生命周期
     *
     * @param int $ticketLifetime 票据生命周期（秒）
     */
    public function setTicketLifetime(int $ticketLifetime): void
    {
        $this->ticketLifetime = $ticketLifetime;
    }

    /**
     * 获取票据年龄附加值
     *
     * @return int 票据年龄附加值
     */
    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd;
    }

    /**
     * 设置票据年龄附加值
     *
     * @param int $ticketAgeAdd 票据年龄附加值
     */
    public function setTicketAgeAdd(int $ticketAgeAdd): void
    {
        $this->ticketAgeAdd = $ticketAgeAdd;
    }

    /**
     * 获取票据随机数
     *
     * @return string 票据随机数
     */
    public function getTicketNonce(): string
    {
        return $this->ticketNonce;
    }

    /**
     * 设置票据随机数
     *
     * @param string $ticketNonce 票据随机数
     */
    public function setTicketNonce(string $ticketNonce): void
    {
        $this->ticketNonce = $ticketNonce;
    }

    /**
     * 获取票据数据
     *
     * @return string 票据数据
     */
    public function getTicket(): string
    {
        return $this->ticket;
    }

    /**
     * 设置票据数据
     *
     * @param string $ticket 票据数据
     */
    public function setTicket(string $ticket): void
    {
        $this->ticket = $ticket;
    }

    /**
     * 获取扩展数据
     *
     * @return array<int, string> 扩展数据
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    /**
     * 设置扩展数据
     *
     * @param array<int, string> $extensions 扩展数据
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
    public function addExtension(int $type, string $data): self
    {
        $this->extensions[$type] = $data;

        return $this;
    }

    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 构造消息体
        $body = pack('N', $this->ticketLifetime);  // 票据生命周期
        $body .= pack('N', $this->ticketAgeAdd);   // 票据年龄附加值

        // 票据随机数
        $body .= pack('C', strlen($this->ticketNonce));
        $body .= $this->ticketNonce;

        // 票据数据
        $body .= pack('n', strlen($this->ticket));
        $body .= $this->ticket;

        // 扩展
        $extensionsData = '';
        foreach ($this->extensions as $type => $data) {
            $extensionsData .= pack('n', $type);
            $extensionsData .= pack('n', strlen($data));
            $extensionsData .= $data;
        }

        $body .= pack('n', strlen($extensionsData));
        $body .= $extensionsData;

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::NEW_SESSION_TICKET->value);
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
        if ($type !== HandshakeMessageType::NEW_SESSION_TICKET->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取票据生命周期
        $unpacked = unpack('N', substr($data, $offset, 4));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack ticket lifetime');
        }
        $message->ticketLifetime = $unpacked[1];
        $offset += 4;

        // 读取票据年龄附加值
        $unpacked = unpack('N', substr($data, $offset, 4));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack ticket age add');
        }
        $message->ticketAgeAdd = $unpacked[1];
        $offset += 4;

        // 读取票据随机数
        $nonceLength = ord($data[$offset]);
        ++$offset;
        $message->ticketNonce = substr($data, $offset, $nonceLength);
        $offset += $nonceLength;

        // 读取票据数据
        $unpacked = unpack('n', substr($data, $offset, 2));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack ticket length');
        }
        $ticketLength = $unpacked[1];
        $offset += 2;
        $message->ticket = substr($data, $offset, $ticketLength);
        $offset += $ticketLength;

        // 读取扩展
        $unpacked = unpack('n', substr($data, $offset, 2));
        if (false === $unpacked) {
            throw new InvalidMessageException('Failed to unpack extensions length');
        }
        $extensionsLength = $unpacked[1];
        $offset += 2;

        $extensionsEnd = $offset + $extensionsLength;
        $message->extensions = [];

        while ($offset < $extensionsEnd) {
            $unpacked = unpack('n', substr($data, $offset, 2));
            if (false === $unpacked) {
                throw new InvalidMessageException('Failed to unpack extension type');
            }
            $extType = $unpacked[1];
            $offset += 2;

            $unpacked = unpack('n', substr($data, $offset, 2));
            if (false === $unpacked) {
                throw new InvalidMessageException('Failed to unpack extension length');
            }
            $extLength = $unpacked[1];
            $offset += 2;

            $extData = substr($data, $offset, $extLength);
            $message->extensions[$extType] = $extData;

            $offset += $extLength;
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
        // 最基本的验证
        return '' !== $this->ticket;
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
