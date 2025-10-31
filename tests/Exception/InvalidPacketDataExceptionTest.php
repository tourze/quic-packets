<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\PacketException;

/**
 * @internal
 */
#[CoversClass(InvalidPacketDataException::class)]
final class InvalidPacketDataExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionIsInstanceOfPacketException(): void
    {
        $exception = new InvalidPacketDataException('Test message');

        $this->assertInstanceOf(PacketException::class, $exception);
    }

    public function testExceptionWithMessage(): void
    {
        $message = 'Invalid packet data format';
        $exception = new InvalidPacketDataException($message);

        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionWithCode(): void
    {
        $code = 12345;
        $exception = new InvalidPacketDataException('Test message', $code);

        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidPacketDataException('Test message', 0, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }
}
