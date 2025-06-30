<?php

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 证书消息
 */
class CertificateMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::CERTIFICATE;
    
    /**
     * 证书链（DER编码）
     *
     * @var array<string>
     */
    private array $certificateChain = [];
    
    /**
     * 获取证书链
     *
     * @return array<string> 证书链
     */
    public function getCertificateChain(): array
    {
        return $this->certificateChain;
    }
    
    /**
     * 设置证书链
     *
     * @param array<string> $certificateChain 证书链
     * @return self
     */
    public function setCertificateChain(array $certificateChain): self
    {
        foreach ($certificateChain as $cert) {
            if (!is_string($cert)) {
                throw new InvalidMessageException('Certificate must be in DER format');
            }
        }
        
        $this->certificateChain = $certificateChain;
        return $this;
    }
    
    /**
     * 添加证书
     *
     * @param string $certificate DER编码的证书
     * @return self
     */
    public function addCertificate(string $certificate): self
    {
        $this->certificateChain[] = $certificate;
        return $this;
    }
    
    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 编码证书链
        $certsData = '';
        foreach ($this->certificateChain as $cert) {
            $certsData .= $this->encodeUint24(strlen($cert)) . $cert;
        }
        
        // 证书链总长度
        $chainLength = strlen($certsData);
        
        // 构造消息体
        $body = $this->encodeUint24($chainLength) . $certsData;
        
        // 构造完整消息
        $message = pack('C', HandshakeMessageType::CERTIFICATE->value);
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
        if ($type !== HandshakeMessageType::CERTIFICATE->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        $offset++;
        
        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;
        
        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }
        
        // 读取证书链总长度
        $chainLength = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;
        
        // 读取证书
        $endOffset = $offset + $chainLength;
        $message->certificateChain = [];
        
        while ($offset < $endOffset) {
            $certLength = self::decodeUint24(substr($data, $offset, 3));
            $offset += 3;
            
            if ($offset + $certLength > $endOffset) {
                throw new InvalidMessageException('Invalid certificate length');
            }
            
            $cert = substr($data, $offset, $certLength);
            $message->certificateChain[] = $cert;
            
            $offset += $certLength;
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
        // 如果证书链为空，则消息无效
        if (empty($this->certificateChain)) {
            return false;
        }
        
        // 验证每个证书
        foreach ($this->certificateChain as $cert) {
            if (!is_string($cert) || empty($cert)) {
                return false;
            }
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