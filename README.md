# TLS Handshake Messages

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/ci.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![PHP Version](https://img.shields.io/packagist/php-v/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)
[![License](https://img.shields.io/packagist/l/tourze/tls-handshake-messages.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-messages)

A comprehensive PHP library for handling TLS handshake protocol messages. This package provides complete implementation of TLS handshake message structures with serialization, deserialization, and validation capabilities.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Supported Message Types](#supported-message-types)
- [Quick Start](#quick-start)
  - [Creating a ClientHello Message](#creating-a-clienthello-message)
  - [Working with Certificates](#working-with-certificates)
  - [Message Validation](#message-validation)
  - [Version Compatibility](#version-compatibility)
- [Architecture](#architecture)
  - [Message Interface](#message-interface)
  - [Message Types](#message-types)
  - [Exception Handling](#exception-handling)
- [Testing](#testing)
- [Development](#development)
  - [Code Quality](#code-quality)
- [Contributing](#contributing)
- [License](#license)
- [Security](#security)
- [Related Packages](#related-packages)

## Features

- 🔒 **Complete TLS Message Support**: Implements all major TLS handshake message types
- 📦 **Serialization/Deserialization**: Efficient binary data encoding and decoding
- ✅ **Message Validation**: Built-in integrity and format validation
- 🔄 **Version Compatibility**: Support for multiple TLS versions with compatibility handling
- 🧪 **Well Tested**: Comprehensive test suite with 100+ test cases
- 🚀 **High Performance**: Optimized for production use

## Installation

```bash
composer require tourze/tls-handshake-messages
```

## Requirements

- PHP 8.1 or higher
- tourze/enum-extra: ^0.1
- tourze/tls-common: ^0.0

## Supported Message Types

- **ClientHello**: Client handshake initialization
- **ServerHello**: Server handshake response
- **Certificate**: Certificate chain messages
- **CertificateRequest**: Certificate request from server
- **CertificateVerify**: Certificate verification messages
- **ClientKeyExchange**: Client key exchange messages
- **ServerKeyExchange**: Server key exchange messages
- **Finished**: Handshake completion messages
- **NewSessionTicket**: Session ticket messages
- **EncryptedExtensions**: TLS 1.3 encrypted extensions
- **HelloRequest**: Server hello request messages
- **ServerHelloDone**: Server hello done messages

## Quick Start

### Creating a ClientHello Message

```php
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;

// Create a new ClientHello message
$clientHello = new ClientHelloMessage();
$clientHello->setVersion(0x0303); // TLS 1.2
$clientHello->setRandom(random_bytes(32));
$clientHello->setSessionId('');
$clientHello->setCipherSuites([0x1301, 0x1302]); // TLS 1.3 cipher suites
$clientHello->setCompressionMethods([0x00]);

// Add extensions
$clientHello->addExtension(0, hex2bin('00000e7777772e676f6f676c652e636f6d')); // server_name

// Serialize to binary
$binaryData = $clientHello->encode();

// Deserialize from binary
$decodedMessage = ClientHelloMessage::decode($binaryData);
```

### Working with Certificates

```php
use Tourze\TLSHandshakeMessages\Message\CertificateMessage;

// Create certificate message with chain
$certificate = new CertificateMessage();
$certificate->setCertificateChain([
    $serverCertificate,
    $intermediateCertificate,
    $rootCertificate
]);

// Or add certificates one by one
$certificate->addCertificate($serverCertificate);
$certificate->addCertificate($intermediateCertificate);

// Validate certificate message
if ($certificate->isValid()) {
    // Process certificate chain
    $chain = $certificate->getCertificateChain();
}
```

### Message Validation

```php
// All messages implement validation
if ($message->isValid()) {
    // Message is properly formatted
    $length = $message->getLength();
    $type = $message->getType();
}
```

### Version Compatibility

```php
use Tourze\TLSHandshakeMessages\Protocol\MessageCompatibilityHandler;

// Adapt message to different TLS versions
$tls12Message = MessageCompatibilityHandler::adaptMessageToVersion(
    $originalMessage,
    MessageCompatibilityHandler::TLS_VERSION_1_2
);

// Check compatibility
if (MessageCompatibilityHandler::isMessageCompatibleWithVersion($message, MessageCompatibilityHandler::TLS_VERSION_1_3)) {
    // Message is compatible with TLS 1.3
}
```

## Architecture

### Message Interface

All messages implement `HandshakeMessageInterface` which provides:

- `getType()`: Get message type
- `encode()`: Serialize to binary
- `decode()`: Deserialize from binary
- `getLength()`: Get message length
- `isValid()`: Validate message format

### Message Types

Message types are defined in `HandshakeMessageType` enum:

```php
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

$type = HandshakeMessageType::CLIENT_HELLO;
```

### Exception Handling

The package uses `InvalidMessageException` for handling malformed messages:

```php
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;

try {
    $message = ClientHelloMessage::decode($invalidData);
} catch (InvalidMessageException $e) {
    // Handle invalid message format
}
```

## Testing

Run the test suite:

```bash
vendor/bin/phpunit packages/tls-handshake-messages/tests
```

## Development

### Code Quality

```bash
# Run PHPStan analysis
vendor/bin/phpstan analyse packages/tls-handshake-messages

# Run tests
vendor/bin/phpunit packages/tls-handshake-messages/tests
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License. See [LICENSE](LICENSE) file for details.

## Security

This package is designed for defensive security applications. If you discover any security issues, please report them responsibly.

## Related Packages

- [tourze/tls-common](../tls-common) - Common TLS utilities
- [tourze/enum-extra](../enum-extra) - Enhanced enum functionality 