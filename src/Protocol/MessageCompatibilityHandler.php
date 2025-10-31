<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Protocol;

use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;
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
     * @param HandshakeMessageInterface $message       原始消息
     * @param int                       $targetVersion 目标TLS版本
     *
     * @return HandshakeMessageInterface 调整后的消息
     */
    public static function adaptMessageToVersion(
        HandshakeMessageInterface $message,
        int $targetVersion,
    ): HandshakeMessageInterface {
        // 根据消息类型和目标版本进行适配
        $messageType = $message->getType();

        // 处理ClientHello消息
        if (HandshakeMessageType::CLIENT_HELLO === $messageType) {
            return self::adaptClientHello($message, $targetVersion);
        }

        // 处理ServerHello消息
        if (HandshakeMessageType::SERVER_HELLO === $messageType) {
            return self::adaptServerHello($message, $targetVersion);
        }

        // 处理TLS 1.3特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS,
            HandshakeMessageType::NEW_SESSION_TICKET,
        ], true)) {
            if ($targetVersion < self::TLS_VERSION_1_3) {
                throw new InvalidMessageException(sprintf('Message type %s is only available in TLS 1.3+', $messageType->getName()));
            }
        }

        // 处理TLS 1.2特有的消息
        if (in_array($messageType, [
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
            HandshakeMessageType::SERVER_HELLO_DONE,
        ], true)) {
            if ($targetVersion >= self::TLS_VERSION_1_3) {
                throw new InvalidMessageException(sprintf('Message type %s is not available in TLS 1.3+', $messageType->getName()));
            }
        }

        return $message;
    }

    /**
     * 适配ClientHello消息
     *
     * @param HandshakeMessageInterface $message       ClientHello消息
     * @param int                       $targetVersion 目标TLS版本
     *
     * @return HandshakeMessageInterface 适配后的消息
     */
    private static function adaptClientHello(
        HandshakeMessageInterface $message,
        int $targetVersion,
    ): HandshakeMessageInterface {
        if (!($message instanceof ClientHelloMessage)) {
            throw new InvalidMessageException('Expected ClientHelloMessage instance');
        }

        $clientHello = clone $message;
        $clientHello->setVersion($targetVersion);

        $filteredCipherSuites = self::filterCipherSuitesForVersion(
            $clientHello->getCipherSuites(),
            $targetVersion
        );

        $clientHello->setCipherSuites($filteredCipherSuites);

        return $clientHello;
    }

    /**
     * 根据TLS版本过滤密码套件
     *
     * @param array<int> $cipherSuites  原始密码套件列表
     * @param int        $targetVersion 目标TLS版本
     *
     * @return array<int> 过滤后的密码套件列表
     */
    private static function filterCipherSuitesForVersion(array $cipherSuites, int $targetVersion): array
    {
        $filteredCipherSuites = [];
        $isTLS13Target = $targetVersion >= self::TLS_VERSION_1_3;

        foreach ($cipherSuites as $suite) {
            $isTLS13Suite = self::isTLS13CipherSuite($suite);

            if ($isTLS13Target === $isTLS13Suite) {
                $filteredCipherSuites[] = $suite;
            }
        }

        if ([] === $filteredCipherSuites) {
            throw new InvalidMessageException('No compatible cipher suites available for target TLS version');
        }

        return $filteredCipherSuites;
    }

    /**
     * 检查是否为TLS 1.3密码套件
     *
     * @param int $suite 密码套件值
     *
     * @return bool 是否为TLS 1.3密码套件
     */
    private static function isTLS13CipherSuite(int $suite): bool
    {
        return (($suite >> 8) & 0xFF) === 0x13;
    }

    /**
     * 适配ServerHello消息
     *
     * @param HandshakeMessageInterface $message       ServerHello消息
     * @param int                       $targetVersion 目标TLS版本
     *
     * @return HandshakeMessageInterface 适配后的消息
     */
    private static function adaptServerHello(
        HandshakeMessageInterface $message,
        int $targetVersion,
    ): HandshakeMessageInterface {
        if (!($message instanceof ServerHelloMessage)) {
            throw new InvalidMessageException('Expected ServerHelloMessage instance');
        }

        $serverHello = clone $message;
        $serverHello->setVersion($targetVersion);

        self::validateServerHelloCipherSuite($serverHello->getCipherSuite(), $targetVersion);

        return $serverHello;
    }

    /**
     * 验证ServerHello的密码套件与TLS版本的兼容性
     *
     * @param int $selectedCipherSuite 选择的密码套件
     * @param int $targetVersion       目标TLS版本
     *
     * @throws InvalidMessageException 当密码套件不兼容时
     */
    private static function validateServerHelloCipherSuite(int $selectedCipherSuite, int $targetVersion): void
    {
        $isTLS13Suite = self::isTLS13CipherSuite($selectedCipherSuite);

        if ($targetVersion >= self::TLS_VERSION_1_3 && !$isTLS13Suite) {
            throw new InvalidMessageException('Selected cipher suite is not compatible with TLS 1.3+');
        }

        if ($targetVersion < self::TLS_VERSION_1_3 && $isTLS13Suite) {
            throw new InvalidMessageException('Selected TLS 1.3 cipher suite is not compatible with TLS 1.2');
        }
    }

    /**
     * 检测消息是否与指定的TLS版本兼容
     *
     * @param HandshakeMessageInterface $message 握手消息
     * @param int                       $version TLS版本
     *
     * @return bool 是否兼容
     */
    public static function isMessageCompatibleWithVersion(
        HandshakeMessageInterface $message,
        int $version,
    ): bool {
        $messageType = $message->getType();

        if (self::isTLS13OnlyMessage($messageType)) {
            return $version >= self::TLS_VERSION_1_3;
        }

        if (self::isTLS12OnlyMessage($messageType)) {
            return $version < self::TLS_VERSION_1_3;
        }

        if (HandshakeMessageType::CLIENT_HELLO === $messageType) {
            return self::isClientHelloCompatible($message, $version);
        }

        if (HandshakeMessageType::SERVER_HELLO === $messageType) {
            return self::isServerHelloCompatible($message, $version);
        }

        return true;
    }

    /**
     * 检查是否为TLS 1.3专有消息
     *
     * @param HandshakeMessageType $messageType 消息类型
     *
     * @return bool 是否为TLS 1.3专有消息
     */
    private static function isTLS13OnlyMessage(HandshakeMessageType $messageType): bool
    {
        return in_array($messageType, [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS,
            HandshakeMessageType::NEW_SESSION_TICKET,
        ], true);
    }

    /**
     * 检查是否为TLS 1.2专有消息
     *
     * @param HandshakeMessageType $messageType 消息类型
     *
     * @return bool 是否为TLS 1.2专有消息
     */
    private static function isTLS12OnlyMessage(HandshakeMessageType $messageType): bool
    {
        return in_array($messageType, [
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
            HandshakeMessageType::SERVER_HELLO_DONE,
        ], true);
    }

    /**
     * 检查ClientHello消息的兼容性
     *
     * @param HandshakeMessageInterface $message ClientHello消息
     * @param int                       $version TLS版本
     *
     * @return bool 是否兼容
     */
    private static function isClientHelloCompatible(HandshakeMessageInterface $message, int $version): bool
    {
        if (!($message instanceof ClientHelloMessage)) {
            return true;
        }

        $cipherSuites = $message->getCipherSuites();
        $isTLS13Target = $version >= self::TLS_VERSION_1_3;

        foreach ($cipherSuites as $suite) {
            $isTLS13Suite = self::isTLS13CipherSuite($suite);

            if ($isTLS13Target === $isTLS13Suite) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查ServerHello消息的兼容性
     *
     * @param HandshakeMessageInterface $message ServerHello消息
     * @param int                       $version TLS版本
     *
     * @return bool 是否兼容
     */
    private static function isServerHelloCompatible(HandshakeMessageInterface $message, int $version): bool
    {
        if (!($message instanceof ServerHelloMessage)) {
            return true;
        }

        $selectedCipherSuite = $message->getCipherSuite();
        $isTLS13Suite = self::isTLS13CipherSuite($selectedCipherSuite);

        return $version >= self::TLS_VERSION_1_3 ? $isTLS13Suite : !$isTLS13Suite;
    }
}
