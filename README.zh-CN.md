# TLS 握手消息

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/ci.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![PHP Version](https://img.shields.io/packagist/php-v/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![License](https://img.shields.io/packagist/l/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)

一个用于处理 TLS 握手协议消息的全面 PHP 库。该包提供了 TLS 握手消息结构的完整实现，包括序列化、反序列化和验证功能。

## 目录

- [特性](#特性)
- [安装](#安装)
- [系统要求](#系统要求)
- [支持的消息类型](#支持的消息类型)
- [快速入门](#快速入门)
  - [创建 ClientHello 消息](#创建-clienthello-消息)
  - [处理证书](#处理证书)
  - [消息验证](#消息验证)
  - [版本兼容性](#版本兼容性)
- [架构](#架构)
  - [消息接口](#消息接口)
  - [消息类型](#消息类型)
  - [异常处理](#异常处理)
- [测试](#测试)
- [开发](#开发)
  - [代码质量](#代码质量)
- [贡献](#贡献)
- [许可证](#许可证)
- [安全性](#安全性)
- [相关包](#相关包)

## 特性

- 🔒 **完整的 TLS 消息支持**：实现了所有主要的 TLS 握手消息类型
- 📦 **序列化/反序列化**：高效的二进制数据编码和解码
- ✅ **消息验证**：内置完整性和格式验证
- 🔄 **版本兼容**：支持多个 TLS 版本的兼容性处理
- 🧪 **充分测试**：包含 100+ 测试用例的全面测试套件
- 🚀 **高性能**：为生产使用而优化

## 安装

```bash
composer require tourze/tls-handshake-messages
```

## 系统要求

- PHP 8.1 或更高版本
- tourze/enum-extra: ^0.1
- tourze/tls-common: ^0.0

## 支持的消息类型

- **ClientHello**：客户端握手初始化
- **ServerHello**：服务器握手响应
- **Certificate**：证书链消息
- **CertificateRequest**：服务器证书请求
- **CertificateVerify**：证书验证消息
- **ClientKeyExchange**：客户端密钥交换消息
- **ServerKeyExchange**：服务器密钥交换消息
- **Finished**：握手完成消息
- **NewSessionTicket**：会话票据消息
- **EncryptedExtensions**：TLS 1.3 加密扩展
- **HelloRequest**：服务器 hello 请求消息
- **ServerHelloDone**：服务器 hello 完成消息

## 快速入门

### 创建 ClientHello 消息

```php
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;

// 创建新的 ClientHello 消息
$clientHello = new ClientHelloMessage();
$clientHello->setVersion(0x0303); // TLS 1.2
$clientHello->setRandom(random_bytes(32));
$clientHello->setSessionId('');
$clientHello->setCipherSuites([0x1301, 0x1302]); // TLS 1.3 加密套件
$clientHello->setCompressionMethods([0x00]);

// 添加扩展
$clientHello->addExtension(0, hex2bin('00000e7777772e676f6f676c652e636f6d')); // server_name

// 序列化为二进制数据
$binaryData = $clientHello->encode();

// 从二进制数据反序列化
$decodedMessage = ClientHelloMessage::decode($binaryData);
```

### 处理证书

```php
use Tourze\TLSHandshakeMessages\Message\CertificateMessage;

// 使用证书链创建证书消息
$certificate = new CertificateMessage();
$certificate->setCertificateChain([
    $serverCertificate,
    $intermediateCertificate,
    $rootCertificate
]);

// 或逐一添加证书
$certificate->addCertificate($serverCertificate);
$certificate->addCertificate($intermediateCertificate);

// 验证证书消息
if ($certificate->isValid()) {
    // 处理证书链
    $chain = $certificate->getCertificateChain();
}
```

### 消息验证

```php
// 所有消息都实现了验证功能
if ($message->isValid()) {
    // 消息格式正确
    $length = $message->getLength();
    $type = $message->getType();
}
```

### 版本兼容性

```php
use Tourze\TLSHandshakeMessages\Protocol\MessageCompatibilityHandler;

// 将消息适配到不同的 TLS 版本
$tls12Message = MessageCompatibilityHandler::adaptMessageToVersion(
    $originalMessage,
    MessageCompatibilityHandler::TLS_VERSION_1_2
);

// 检查兼容性
if (MessageCompatibilityHandler::isMessageCompatibleWithVersion($message, MessageCompatibilityHandler::TLS_VERSION_1_3)) {
    // 消息与 TLS 1.3 兼容
}
```

## 架构

### 消息接口

所有消息都实现了 `HandshakeMessageInterface` 接口，提供以下方法：

- `getType()`：获取消息类型
- `encode()`：序列化为二进制数据
- `decode()`：从二进制数据反序列化
- `getLength()`：获取消息长度
- `isValid()`：验证消息格式

### 消息类型

消息类型在 `HandshakeMessageType` 枚举中定义：

```php
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

$type = HandshakeMessageType::CLIENT_HELLO;
```

### 异常处理

该包使用 `InvalidMessageException` 来处理格式错误的消息：

```php
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;

try {
    $message = ClientHelloMessage::decode($invalidData);
} catch (InvalidMessageException $e) {
    // 处理无效消息格式
}
```

## 测试

运行测试套件：

```bash
vendor/bin/phpunit packages/tls-handshake-messages/tests
```

## 开发

### 代码质量

```bash
# 运行 PHPStan 分析
vendor/bin/phpstan analyse packages/tls-handshake-messages

# 运行测试
vendor/bin/phpunit packages/tls-handshake-messages/tests
```

## 贡献

1. Fork 仓库
2. 创建特性分支
3. 为新功能编写测试
4. 确保所有测试通过
5. 提交 Pull Request

## 许可证

MIT 许可证。详情参见 [LICENSE](LICENSE) 文件。

## 安全性

此包设计用于防御安全应用。如果您发现任何安全问题，请负责任地报告。

## 相关包

- [tourze/tls-common](../tls-common) - 通用 TLS 实用工具
- [tourze/enum-extra](../enum-extra) - 增强的枚举功能 