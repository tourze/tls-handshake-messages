<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Protocol;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * 握手消息类型枚举
 */
enum HandshakeMessageType: int implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    /**
     * hello_request(0)
     */
    case HELLO_REQUEST = 0;

    /**
     * client_hello(1)
     */
    case CLIENT_HELLO = 1;

    /**
     * server_hello(2)
     */
    case SERVER_HELLO = 2;

    /**
     * new_session_ticket(4)
     * TLS 1.3
     */
    case NEW_SESSION_TICKET = 4;

    /**
     * encrypted_extensions(8)
     * TLS 1.3
     */
    case ENCRYPTED_EXTENSIONS = 8;

    /**
     * certificate(11)
     */
    case CERTIFICATE = 11;

    /**
     * server_key_exchange(12)
     * TLS 1.2
     */
    case SERVER_KEY_EXCHANGE = 12;

    /**
     * certificate_request(13)
     */
    case CERTIFICATE_REQUEST = 13;

    /**
     * server_hello_done(14)
     * TLS 1.2
     */
    case SERVER_HELLO_DONE = 14;

    /**
     * certificate_verify(15)
     */
    case CERTIFICATE_VERIFY = 15;

    /**
     * client_key_exchange(16)
     * TLS 1.2
     */
    case CLIENT_KEY_EXCHANGE = 16;

    /**
     * finished(20)
     */
    case FINISHED = 20;

    /**
     * 获取消息类型的名称
     *
     * @return string 消息类型名称
     */
    public function getName(): string
    {
        return match ($this) {
            self::HELLO_REQUEST => 'HELLO_REQUEST',
            self::CLIENT_HELLO => 'CLIENT_HELLO',
            self::SERVER_HELLO => 'SERVER_HELLO',
            self::NEW_SESSION_TICKET => 'NEW_SESSION_TICKET',
            self::ENCRYPTED_EXTENSIONS => 'ENCRYPTED_EXTENSIONS',
            self::CERTIFICATE => 'CERTIFICATE',
            self::SERVER_KEY_EXCHANGE => 'SERVER_KEY_EXCHANGE',
            self::CERTIFICATE_REQUEST => 'CERTIFICATE_REQUEST',
            self::SERVER_HELLO_DONE => 'SERVER_HELLO_DONE',
            self::CERTIFICATE_VERIFY => 'CERTIFICATE_VERIFY',
            self::CLIENT_KEY_EXCHANGE => 'CLIENT_KEY_EXCHANGE',
            self::FINISHED => 'FINISHED',
        };
    }

    /**
     * 获取消息类型标签
     *
     * @return string 消息类型标签
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::HELLO_REQUEST => 'Hello请求',
            self::CLIENT_HELLO => '客户端Hello',
            self::SERVER_HELLO => '服务器Hello',
            self::NEW_SESSION_TICKET => '新会话票据',
            self::ENCRYPTED_EXTENSIONS => '加密扩展',
            self::CERTIFICATE => '证书',
            self::SERVER_KEY_EXCHANGE => '服务器密钥交换',
            self::CERTIFICATE_REQUEST => '证书请求',
            self::SERVER_HELLO_DONE => '服务器Hello完成',
            self::CERTIFICATE_VERIFY => '证书验证',
            self::CLIENT_KEY_EXCHANGE => '客户端密钥交换',
            self::FINISHED => '完成',
        };
    }

    /**
     * 获取消息类型的名称（静态方法）
     *
     * @param int $type 消息类型
     *
     * @return string 消息类型名称
     */
    public static function getMessageTypeName(int $type): string
    {
        $enum = self::tryFrom($type);
        if (null === $enum) {
            return 'Unknown';
        }

        return $enum->getName();
    }
}
