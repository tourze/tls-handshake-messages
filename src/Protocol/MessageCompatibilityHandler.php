<?php

namespace Tourze\TLSHandshakeMessages\Protocol;

use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;
use Tourze\TLSHandshakeMessages\Message\HandshakeMessageInterface;
use Tourze\TLSHandshakeMessages\Message\ServerHelloMessage;

/**
 * TLS消息版本兼容性处理工具类
 * 
 * 用于处理TLS 1.2和TLS 1.3之间的消息格式差异和兼容性问题
 */
class MessageCompatibilityHandler
{
    /**
     * TLS 1.2版本常量
     */
    public const TLS_VERSION_1_2 = 0x0303;
    
    /**
     * TLS 1.3版本常量
     */
    public const TLS_VERSION_1_3 = 0x0304;
    
    /**
     * 调整消息以适应目标TLS版本
     *
     * @param HandshakeMessageInterface $message 原始消息
     * @param int $targetVersion 目标TLS版本
     * @return HandshakeMessageInterface 调整后的消息
     */
    public static function adaptMessageToVersion(
        HandshakeMessageInterface $message, 
        int $targetVersion
    ): HandshakeMessageInterface {
        // 根据消息类型和目标版本进行适配
        $messageType = $message->getType();
        
        // 处理ClientHello消息
        if ($messageType === HandshakeMessageType::CLIENT_HELLO) {
            return self::adaptClientHello($message, $targetVersion);
        }
        
        // 处理ServerHello消息
        if ($messageType === HandshakeMessageType::SERVER_HELLO) {
            return self::adaptServerHello($message, $targetVersion);
        }
        
        // 处理TLS 1.3特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS,
            HandshakeMessageType::NEW_SESSION_TICKET
        ])) {
            if ($targetVersion < self::TLS_VERSION_1_3) {
                throw new \InvalidArgumentException(sprintf(
                    "Message type %s is only available in TLS 1.3+",
                    $messageType->getName()
                ));
            }
        }
        
        // 处理TLS 1.2特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
            HandshakeMessageType::SERVER_HELLO_DONE
        ])) {
            if ($targetVersion >= self::TLS_VERSION_1_3) {
                throw new \InvalidArgumentException(sprintf(
                    "Message type %s is not available in TLS 1.3+",
                    $messageType->getName()
                ));
            }
        }
        
        return $message;
    }
    
    /**
     * 适配ClientHello消息
     *
     * @param HandshakeMessageInterface $message ClientHello消息
     * @param int $targetVersion 目标TLS版本
     * @return HandshakeMessageInterface 适配后的消息
     */
    private static function adaptClientHello(
        HandshakeMessageInterface $message, 
        int $targetVersion
    ): HandshakeMessageInterface {
        if (!($message instanceof ClientHelloMessage)) {
            throw new \InvalidArgumentException("Expected ClientHelloMessage instance");
        }
        
        $clientHello = clone $message;
        
        // 设置正确的版本
        $clientHello->setVersion($targetVersion);
        
        // 根据版本过滤密码套件
        $cipherSuites = $clientHello->getCipherSuites();
        $filteredCipherSuites = [];
        
        foreach ($cipherSuites as $suite) {
            // TLS 1.3的密码套件（0x13xx）
            $isTLS13Suite = (($suite >> 8) & 0xFF) === 0x13;
            
            if ($targetVersion >= self::TLS_VERSION_1_3) {
                if ((bool) $isTLS13Suite) {
                    $filteredCipherSuites[] = $suite;
                }
            } else {
                if (!$isTLS13Suite) {
                    $filteredCipherSuites[] = $suite;
                }
            }
        }
        
        // 确保有至少一个密码套件
        if ((bool) empty($filteredCipherSuites)) {
            throw new \InvalidArgumentException(
                "No compatible cipher suites available for target TLS version"
            );
        }
        
        $clientHello->setCipherSuites($filteredCipherSuites);
        
        return $clientHello;
    }
    
    /**
     * 适配ServerHello消息
     *
     * @param HandshakeMessageInterface $message ServerHello消息
     * @param int $targetVersion 目标TLS版本
     * @return HandshakeMessageInterface 适配后的消息
     */
    private static function adaptServerHello(
        HandshakeMessageInterface $message, 
        int $targetVersion
    ): HandshakeMessageInterface {
        if (!($message instanceof ServerHelloMessage)) {
            throw new \InvalidArgumentException("Expected ServerHelloMessage instance");
        }
        
        $serverHello = clone $message;
        
        // 设置正确的版本
        $serverHello->setVersion($targetVersion);
        
        // 获取当前选择的密码套件
        $selectedCipherSuite = $serverHello->getCipherSuite();
        
        // 检查密码套件与TLS版本的兼容性
        $isTLS13Suite = (($selectedCipherSuite >> 8) & 0xFF) === 0x13;
        
        if ($targetVersion >= self::TLS_VERSION_1_3 && (bool) !$isTLS13Suite) {
            throw new \InvalidArgumentException(
                "Selected cipher suite is not compatible with TLS 1.3+"
            );
        }
        
        if ($targetVersion < self::TLS_VERSION_1_3 && (bool) $isTLS13Suite) {
            throw new \InvalidArgumentException(
                "Selected TLS 1.3 cipher suite is not compatible with TLS 1.2"
            );
        }
        
        return $serverHello;
    }
    
    /**
     * 检测消息是否与指定的TLS版本兼容
     *
     * @param HandshakeMessageInterface $message 握手消息
     * @param int $version TLS版本
     * @return bool 是否兼容
     */
    public static function isMessageCompatibleWithVersion(
        HandshakeMessageInterface $message, 
        int $version
    ): bool {
        $messageType = $message->getType();
        
        // TLS 1.3特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS,
            HandshakeMessageType::NEW_SESSION_TICKET
        ])) {
            return $version >= self::TLS_VERSION_1_3;
        }
        
        // TLS 1.2特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
            HandshakeMessageType::SERVER_HELLO_DONE
        ])) {
            return $version < self::TLS_VERSION_1_3;
        }
        
        // ClientHello和ServerHello需要检查密码套件兼容性
        if ($messageType === HandshakeMessageType::CLIENT_HELLO && $message instanceof ClientHelloMessage) {
            $cipherSuites = $message->getCipherSuites();
            
            if ($version >= self::TLS_VERSION_1_3) {
                // 检查是否有至少一个TLS 1.3密码套件
                foreach ($cipherSuites as $suite) {
                    if ((($suite >> 8) & 0xFF) === 0x13) {
                        return true;
                    }
                }
                return false;
            } else {
                // 检查是否有至少一个非TLS 1.3密码套件
                foreach ($cipherSuites as $suite) {
                    if ((($suite >> 8) & 0xFF) !== 0x13) {
                        return true;
                    }
                }
                return false;
            }
        }
        
        if ($messageType === HandshakeMessageType::SERVER_HELLO && $message instanceof ServerHelloMessage) {
            $selectedCipherSuite = $message->getCipherSuite();
            $isTLS13Suite = (($selectedCipherSuite >> 8) & 0xFF) === 0x13;
            
            if ($version >= self::TLS_VERSION_1_3) {
                return $isTLS13Suite;
            } else {
                return !$isTLS13Suite;
            }
        }
        
        // 其他消息在两个版本都兼容
        return true;
    }
}
