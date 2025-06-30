<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Unit\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;

/**
 * InvalidMessageException测试类
 */
class InvalidMessageExceptionTest extends TestCase
{
    /**
     * 测试异常继承关系
     */
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = new InvalidMessageException('Test message');
        
        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
        $this->assertInstanceOf(InvalidMessageException::class, $exception);
    }

    /**
     * 测试异常消息
     */
    public function testExceptionMessage(): void
    {
        $message = 'Invalid TLS message format';
        $exception = new InvalidMessageException($message);
        
        $this->assertEquals($message, $exception->getMessage());
    }

    /**
     * 测试异常代码
     */
    public function testExceptionCode(): void
    {
        $message = 'Test message';
        $code = 123;
        $exception = new InvalidMessageException($message, $code);
        
        $this->assertEquals($code, $exception->getCode());
    }

    /**
     * 测试异常前置异常
     */
    public function testExceptionPrevious(): void
    {
        $previousException = new \RuntimeException('Previous error');
        $exception = new InvalidMessageException('Test message', 0, $previousException);
        
        $this->assertSame($previousException, $exception->getPrevious());
    }

    /**
     * 测试抛出异常
     */
    public function testThrowException(): void
    {
        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Invalid message type');
        
        throw new InvalidMessageException('Invalid message type');
    }
}