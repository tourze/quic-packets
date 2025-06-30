<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\PacketException;

class PacketExceptionTest extends TestCase
{
    public function testExceptionIsInstanceOfRuntimeException(): void
    {
        $exception = new PacketException('Test message');
        
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function testExceptionWithMessage(): void
    {
        $message = 'Packet processing error';
        $exception = new PacketException($message);
        
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionWithCode(): void
    {
        $code = 11111;
        $exception = new PacketException('Test message', $code);
        
        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new PacketException('Test message', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionWithAllParameters(): void
    {
        $message = 'Full test message';
        $code = 999;
        $previous = new \Exception('Previous test');
        
        $exception = new PacketException($message, $code, $previous);
        
        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}