<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeMessages\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;

/**
 * InvalidMessageException测试类
 *
 * @internal
 */
#[CoversClass(InvalidMessageException::class)]
final class InvalidMessageExceptionTest extends AbstractExceptionTestCase
{
    protected function getExceptionClass(): string
    {
        return InvalidMessageException::class;
    }

    protected function getDefaultMessage(): string
    {
        return 'Invalid TLS message format';
    }

    protected function getParentExceptionClass(): string
    {
        return \InvalidArgumentException::class;
    }
}
