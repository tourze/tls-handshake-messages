<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 客户端Hello消息
 */
final class ClientHelloMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::CLIENT_HELLO;

    /**
     * TLS版本
     */
    private int $version;

    /**
     * 32字节随机数
     */
    private string $random;

    /**
     * 会话ID
     */
    private string $sessionId;

    /**
     * 加密套件列表
     *
     * @var array<int>
     */
    private array $cipherSuites = [];

    /**
     * 压缩方法列表
     *
     * @var array<int>
     */
    private array $compressionMethods = [];

    /**
     * 扩展列表
     *
     * @var array<int, string>
     */
    private array $extensions = [];

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->version = 0x0303; // TLS 1.2
        $this->random = random_bytes(32);
        $this->sessionId = '';
        $this->compressionMethods = [0]; // null compression
    }

    /**
     * 获取TLS版本
     *
     * @return int TLS版本
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * 设置TLS版本
     *
     * @param int $version TLS版本
     */
    public function setVersion(int $version): void
    {
        $this->version = $version;
    }

    /**
     * 获取随机数
     *
     * @return string 随机数
     */
    public function getRandom(): string
    {
        return $this->random;
    }

    /**
     * 设置随机数
     *
     * @param string $random 32字节随机数
     *
     * @throws InvalidMessageException 如果随机数长度不是32字节
     */
    public function setRandom(string $random): void
    {
        if (32 !== strlen($random)) {
            throw new InvalidMessageException('Random data must be exactly 32 bytes');
        }

        $this->random = $random;
    }

    /**
     * 获取会话ID
     *
     * @return string 会话ID
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    /**
     * 设置会话ID
     *
     * @param string $sessionId 会话ID
     *
     * @throws InvalidMessageException 如果会话ID长度超过32字节
     */
    public function setSessionId(string $sessionId): void
    {
        if (strlen($sessionId) > 32) {
            throw new InvalidMessageException('Session ID cannot exceed 32 bytes');
        }

        $this->sessionId = $sessionId;
    }

    /**
     * 获取加密套件列表
     *
     * @return array<int> 加密套件列表
     */
    public function getCipherSuites(): array
    {
        return $this->cipherSuites;
    }

    /**
     * 设置加密套件列表
     *
     * @param array<int> $cipherSuites 加密套件列表
     */
    public function setCipherSuites(array $cipherSuites): void
    {
        $this->cipherSuites = $cipherSuites;
    }

    /**
     * 获取压缩方法列表
     *
     * @return array<int> 压缩方法列表
     */
    public function getCompressionMethods(): array
    {
        return $this->compressionMethods;
    }

    /**
     * 设置压缩方法列表
     *
     * @param array<int> $compressionMethods 压缩方法列表
     */
    public function setCompressionMethods(array $compressionMethods): void
    {
        $this->compressionMethods = $compressionMethods;
    }

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
        // 计算加密套件数据长度
        $cipherSuitesLength = count($this->cipherSuites) * 2;

        // 编码加密套件
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= $this->encodeUint16($suite);
        }

        // 编码压缩方法
        $compressionMethodsData = pack('C', count($this->compressionMethods));
        foreach ($this->compressionMethods as $method) {
            $compressionMethodsData .= pack('C', $method);
        }

        // 编码扩展
        $extensionsData = '';
        if ([] !== $this->extensions) {
            foreach ($this->extensions as $type => $data) {
                $extensionsData .= $this->encodeUint16($type);
                $extensionsData .= $this->encodeUint16(strlen($data));
                $extensionsData .= $data;
            }
            $extensionsData = $this->encodeUint16(strlen($extensionsData)) . $extensionsData;
        }

        // 构造消息体
        $body = $this->encodeUint16($this->version);
        $body .= $this->random;
        $body .= pack('C', strlen($this->sessionId)) . $this->sessionId;
        $body .= $this->encodeUint16($cipherSuitesLength);
        $body .= $cipherSuitesData;
        $body .= $compressionMethodsData;

        if ('' !== $extensionsData) {
            $body .= $extensionsData;
        }

        // 构造完整消息
        $message = pack('C', HandshakeMessageType::CLIENT_HELLO->value);
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
        if ($type !== HandshakeMessageType::CLIENT_HELLO->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        ++$offset;

        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;

        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }

        // 读取协议版本
        $message->version = self::decodeUint16($data, $offset);
        $offset += 2;

        // 读取随机数
        $message->random = substr($data, $offset, 32);
        $offset += 32;

        // 读取会话ID
        $sessionIdLength = ord($data[$offset]);
        ++$offset;
        $message->sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;

        // 读取加密套件
        $cipherSuitesLength = self::decodeUint16($data, $offset);
        $offset += 2;

        if (0 !== $cipherSuitesLength % 2) {
            throw new InvalidMessageException('Invalid cipher suites length');
        }

        $message->cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            $message->cipherSuites[] = self::decodeUint16($data, $offset + $i);
        }
        $offset += $cipherSuitesLength;

        // 读取压缩方法
        $compressionMethodsLength = ord($data[$offset]);
        ++$offset;

        $message->compressionMethods = [];
        for ($i = 0; $i < $compressionMethodsLength; ++$i) {
            $message->compressionMethods[] = ord($data[$offset + $i]);
        }
        $offset += $compressionMethodsLength;

        // 如果还有剩余数据，读取扩展
        if ($offset < strlen($data)) {
            $extensionsLength = self::decodeUint16($data, $offset);
            $offset += 2;
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
        if (32 !== strlen($this->random)) {
            return false;
        }

        if (strlen($this->sessionId) > 32) {
            return false;
        }

        if ([] === $this->cipherSuites) {
            return false;
        }

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
