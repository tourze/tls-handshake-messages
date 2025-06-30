<?php

namespace Tourze\TLSHandshakeMessages\Message;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 证书请求消息
 */
class CertificateRequestMessage extends AbstractHandshakeMessage
{
    /**
     * 消息类型
     */
    public const MESSAGE_TYPE = HandshakeMessageType::CERTIFICATE_REQUEST;
    
    /**
     * 证书类型列表
     *
     * @var array<int>
     */
    private array $certificateTypes = [];
    
    /**
     * 签名算法列表
     *
     * @var array<int>
     */
    private array $signatureAlgorithms = [];
    
    /**
     * 可接受的证书颁发机构列表
     *
     * @var array<string>
     */
    private array $certificateAuthorities = [];
    
    /**
     * 获取证书类型列表
     *
     * @return array<int> 证书类型列表
     */
    public function getCertificateTypes(): array
    {
        return $this->certificateTypes;
    }
    
    /**
     * 设置证书类型列表
     *
     * @param array<int> $certificateTypes 证书类型列表
     * @return self
     */
    public function setCertificateTypes(array $certificateTypes): self
    {
        $this->certificateTypes = $certificateTypes;
        return $this;
    }
    
    /**
     * 添加证书类型
     *
     * @param int $certificateType 证书类型
     * @return self
     */
    public function addCertificateType(int $certificateType): self
    {
        $this->certificateTypes[] = $certificateType;
        return $this;
    }
    
    /**
     * 获取签名算法列表
     *
     * @return array<int> 签名算法列表
     */
    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }
    
    /**
     * 设置签名算法列表
     *
     * @param array<int> $signatureAlgorithms 签名算法列表
     * @return self
     */
    public function setSignatureAlgorithms(array $signatureAlgorithms): self
    {
        $this->signatureAlgorithms = $signatureAlgorithms;
        return $this;
    }

    /**
     * 添加签名算法
     *
     * @param int $signatureAlgorithm 签名算法
     * @return self
     */
    public function addSignatureAlgorithm(int $signatureAlgorithm): self
    {
        $this->signatureAlgorithms[] = $signatureAlgorithm;
        return $this;
    }

    /**
     * 获取证书颁发机构列表
     *
     * @return array<string> 证书颁发机构列表
     */
    public function getCertificateAuthorities(): array
    {
        return $this->certificateAuthorities;
    }
    
    /**
     * 设置证书颁发机构列表
     *
     * @param array<string> $certificateAuthorities 证书颁发机构列表
     * @return self
     */
    public function setCertificateAuthorities(array $certificateAuthorities): self
    {
        $this->certificateAuthorities = $certificateAuthorities;
        return $this;
    }
    
    /**
     * 添加证书颁发机构
     *
     * @param string $certificateAuthority 证书颁发机构
     * @return self
     */
    public function addCertificateAuthority(string $certificateAuthority): self
    {
        $this->certificateAuthorities[] = $certificateAuthority;
        return $this;
    }
    
    /**
     * 编码消息
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 编码证书类型
        $body = pack('C', count($this->certificateTypes));
        foreach ($this->certificateTypes as $type) {
            $body .= pack('C', $type);
        }
        
        // 编码签名算法
        $signatureAlgorithmsData = '';
        foreach ($this->signatureAlgorithms as $algorithm) {
            $signatureAlgorithmsData .= $this->encodeUint16($algorithm);
        }
        $body .= $this->encodeUint16(count($this->signatureAlgorithms) * 2);
        $body .= $signatureAlgorithmsData;
        
        // 编码证书颁发机构
        $authoritiesData = '';
        foreach ($this->certificateAuthorities as $authority) {
            $authoritiesData .= $this->encodeUint16(strlen($authority)) . $authority;
        }
        $body .= $this->encodeUint16(strlen($authoritiesData));
        $body .= $authoritiesData;
        
        // 构造完整消息
        $message = pack('C', HandshakeMessageType::CERTIFICATE_REQUEST->value);
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
        if ($type !== HandshakeMessageType::CERTIFICATE_REQUEST->value) {
            throw new InvalidMessageException('Invalid message type');
        }
        $offset++;
        
        // 读取消息长度
        $length = self::decodeUint24(substr($data, $offset, 3));
        $offset += 3;
        
        if (strlen($data) - $offset < $length) {
            throw new InvalidMessageException('Incomplete message data');
        }
        
        // 读取证书类型数量
        $typesCount = ord($data[$offset]);
        $offset++;
        
        // 读取证书类型
        $message->certificateTypes = [];
        for ($i = 0; $i < $typesCount; $i++) {
            $message->certificateTypes[] = ord($data[$offset]);
            $offset++;
        }
        
        // 读取签名算法列表长度
        $signatureAlgorithmsLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 读取签名算法
        $message->signatureAlgorithms = [];
        for ($i = 0; $i < $signatureAlgorithmsLength; $i += 2) {
            $message->signatureAlgorithms[] = self::decodeUint16($data, $offset + $i);
        }
        $offset += $signatureAlgorithmsLength;
        
        // 读取证书颁发机构列表长度
        $authoritiesLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 读取证书颁发机构
        $authoritiesEnd = $offset + $authoritiesLength;
        $message->certificateAuthorities = [];
        
        while ($offset < $authoritiesEnd) {
            $authorityLength = self::decodeUint16($data, $offset);
            $offset += 2;
            
            $authority = substr($data, $offset, $authorityLength);
            $message->certificateAuthorities[] = $authority;
            
            $offset += $authorityLength;
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
        // 最基本的验证：只需要有证书类型列表即可
        return !empty($this->certificateTypes);
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
