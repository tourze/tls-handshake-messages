<?php

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 服务器密钥交换消息
 */
class ServerKeyExchangeMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::SERVER_KEY_EXCHANGE;
    
    /**
     * 密钥交换参数
     */
    private string $keyExchangeParams = '';
    
    /**
     * 签名算法
     */
    private int $signatureAlgorithm = 0;
    
    /**
     * 签名数据
     */
    private string $signature = '';
    
    /**
     * 获取密钥交换参数
     *
     * @return string 密钥交换参数
     */
    public function getKeyExchangeParams(): string
    {
        return $this->keyExchangeParams;
    }
    
    /**
     * 设置密钥交换参数
     *
     * @param string $keyExchangeParams 密钥交换参数
     * @return self
     */
    public function setKeyExchangeParams(string $keyExchangeParams): self
    {
        $this->keyExchangeParams = $keyExchangeParams;
        return $this;
    }
    
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
     * @return self
     */
    public function setSignatureAlgorithm(int $signatureAlgorithm): self
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
        return $this;
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
     * @return self
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
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
        $body = $this->keyExchangeParams;
        
        // 如果有签名，添加签名算法和签名数据
        if (!empty($this->signature)) {
            $body .= pack('n', $this->signatureAlgorithm);
            $body .= pack('n', strlen($this->signature));
            $body .= $this->signature;
        }
        
        // 构造完整消息
        $message = pack('C', HandshakeMessageType::SERVER_KEY_EXCHANGE->value);
        $message .= $this->encodeUint24(strlen($body));
        $message .= $body;
        
        return $message;
    }
    
    /**
     * 解码消息
     *
     * @param string $data 二进制数据
     * @return static 解码后的消息对象
     * @throws InvalidMessageException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $message = new static();
        
        $offset = 0;
        
        // 验证消息类型
        $type = ord($data[$offset]);
        if ($type !== HandshakeMessageType::SERVER_KEY_EXCHANGE->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        $offset++;
        
        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;
        
        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }
        
        // 提取消息体
        $body = substr($data, $offset, $length);
        $bodyOffset = 0;
        
        // 判断是否还有签名部分
        if (strlen($body) <= $bodyOffset) {
            // 没有签名，全部当作密钥交换参数
            $message->keyExchangeParams = $body;
            return $message;
        }
        
        // 尝试解析签名算法和签名
        if (strlen($body) - $bodyOffset >= 4) { // 至少需要2+2字节用于签名算法和签名长度
            // 假设剩余部分的开始是签名算法
            $possibleAlgorithm = unpack('n', substr($body, strlen($body) - 4, 2))[1];
            $possibleSignatureLength = unpack('n', substr($body, strlen($body) - 2, 2))[1];
            
            // 如果解析出的签名长度与数据长度相符，则认为这是有效的签名
            if (strlen($body) - $bodyOffset - 4 == $possibleSignatureLength) {
                $message->signatureAlgorithm = $possibleAlgorithm;
                $message->signature = substr($body, $bodyOffset, $possibleSignatureLength);
                $message->keyExchangeParams = substr($body, 0, $bodyOffset);
            } else {
                // 没有有效的签名标记，全部当作密钥交换参数
                $message->keyExchangeParams = $body;
            }
        } else {
            // 没有足够的数据来包含签名，全部当作密钥交换参数
            $message->keyExchangeParams = $body;
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
        return !empty($this->keyExchangeParams);
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
     * 解码24位无符号整数
     *
     * @param string $data 二进制数据
     * @param int $offset 偏移量
     * @return int 解码后的整数值
     */
    protected static function decodeUint24(string $data, int $offset = 0): int
    {
        $unpacked = unpack('C3', substr($data, $offset, 3));
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