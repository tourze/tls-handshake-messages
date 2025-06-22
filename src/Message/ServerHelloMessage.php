<?php

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 服务器Hello消息
 */
class ServerHelloMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::SERVER_HELLO;
    
    /**
     * TLS版本
     *
     * @var int
     */
    private int $version;
    
    /**
     * 32字节随机数
     *
     * @var string
     */
    private string $random;
    
    /**
     * 会话ID
     *
     * @var string
     */
    private string $sessionId;
    
    /**
     * 选择的加密套件
     *
     * @var int
     */
    private int $cipherSuite;
    
    /**
     * 选择的压缩方法
     *
     * @var int
     */
    private int $compressionMethod;
    
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
        $this->cipherSuite = 0;
        $this->compressionMethod = 0; // null compression
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
     * @return self
     */
    public function setVersion(int $version): self
    {
        $this->version = $version;
        return $this;
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
     * @return self
     * @throws \InvalidArgumentException 如果随机数长度不是32字节
     */
    public function setRandom(string $random): self
    {
        if (strlen($random) !== 32) {
            throw new \InvalidArgumentException('Random data must be exactly 32 bytes');
        }
        
        $this->random = $random;
        return $this;
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
     * @return self
     * @throws \InvalidArgumentException 如果会话ID长度超过32字节
     */
    public function setSessionId(string $sessionId): self
    {
        if (strlen($sessionId) > 32) {
            throw new \InvalidArgumentException('Session ID cannot exceed 32 bytes');
        }
        
        $this->sessionId = $sessionId;
        return $this;
    }
    
    /**
     * 获取选择的加密套件
     *
     * @return int 加密套件
     */
    public function getCipherSuite(): int
    {
        return $this->cipherSuite;
    }
    
    /**
     * 设置选择的加密套件
     *
     * @param int $cipherSuite 加密套件
     * @return self
     */
    public function setCipherSuite(int $cipherSuite): self
    {
        $this->cipherSuite = $cipherSuite;
        return $this;
    }
    
    /**
     * 获取选择的压缩方法
     *
     * @return int 压缩方法
     */
    public function getCompressionMethod(): int
    {
        return $this->compressionMethod;
    }
    
    /**
     * 设置选择的压缩方法
     *
     * @param int $compressionMethod 压缩方法
     * @return self
     */
    public function setCompressionMethod(int $compressionMethod): self
    {
        $this->compressionMethod = $compressionMethod;
        return $this;
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
     * @return self
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;
        return $this;
    }
    
    /**
     * 添加扩展
     *
     * @param int $type 扩展类型
     * @param string $data 扩展数据
     * @return self
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
        // 编码扩展
        $extensionsData = '';
        if (!empty($this->extensions)) {
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
        $body .= $this->encodeUint16($this->cipherSuite);
        $body .= pack('C', $this->compressionMethod);
        
        if (!empty($extensionsData)) {
            $body .= $extensionsData;
        }
        
        // 构造完整消息
        $message = pack('C', HandshakeMessageType::SERVER_HELLO->value);
        $message .= $this->encodeUint24(strlen($body));
        $message .= $body;
        
        return $message;
    }
    
    /**
     * 解码消息
     *
     * @param string $data 二进制数据
     * @return static 解码后的消息对象
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $message = new static();
        
        $offset = 0;
        
        // 验证消息类型
        $type = ord($data[$offset]);
        if ($type !== HandshakeMessageType::SERVER_HELLO->value) {
            throw new \InvalidArgumentException('Invalid message type');
        }
        $offset++;
        
        // 读取消息长度
        $length = (ord($data[$offset]) << 16) | (ord($data[$offset + 1]) << 8) | ord($data[$offset + 2]);
        $offset += 3;
        
        if (strlen($data) - $offset < $length) {
            throw new \InvalidArgumentException('Incomplete message data');
        }
        
        // 读取协议版本
        $message->version = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 读取随机数
        $message->random = substr($data, $offset, 32);
        $offset += 32;
        
        // 读取会话ID
        $sessionIdLength = ord($data[$offset]);
        $offset++;
        $message->sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;
        
        // 读取加密套件
        $message->cipherSuite = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 读取压缩方法
        $message->compressionMethod = ord($data[$offset]);
        $offset++;
        
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
        if (strlen($this->random) !== 32) {
            return false;
        }
        
        if (strlen($this->sessionId) > 32) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 编码24位无符号整数
     *
     * @param int $value 整数值
     * @return string 编码后的二进制数据
     */
    protected function encodeUint24(int $value): string
    {
        return pack('C3', ($value >> 16) & 0xFF, ($value >> 8) & 0xFF, $value & 0xFF);
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