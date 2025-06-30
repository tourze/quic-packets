<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketNumberSpaceException;
use Tourze\QUIC\Packets\Exception\PacketException;

class InvalidPacketNumberSpaceExceptionTest extends TestCase
{
    public function testExceptionIsInstanceOfPacketException(): void
    {
        $exception = new InvalidPacketNumberSpaceException('Test message');
        
        $this->assertInstanceOf(PacketException::class, $exception);
    }

    public function testExceptionWithMessage(): void
    {
        $message = 'Invalid packet number space';
        $exception = new InvalidPacketNumberSpaceException($message);
        
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionWithCode(): void
    {
        $code = 54321;
        $exception = new InvalidPacketNumberSpaceException('Test message', $code);
        
        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidPacketNumberSpaceException('Test message', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}