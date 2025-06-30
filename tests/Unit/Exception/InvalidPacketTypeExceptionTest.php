<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\Exception\PacketException;

class InvalidPacketTypeExceptionTest extends TestCase
{
    public function testExceptionIsInstanceOfPacketException(): void
    {
        $exception = new InvalidPacketTypeException('Test message');
        
        $this->assertInstanceOf(PacketException::class, $exception);
    }

    public function testExceptionWithMessage(): void
    {
        $message = 'Invalid packet type';
        $exception = new InvalidPacketTypeException($message);
        
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionWithCode(): void
    {
        $code = 98765;
        $exception = new InvalidPacketTypeException('Test message', $code);
        
        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidPacketTypeException('Test message', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}