<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\ShortHeaderPacket;

/**
 * @internal
 */
#[CoversClass(ShortHeaderPacket::class)]
final class ShortHeaderPacketTest extends TestCase
{
    public function testConstruct(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'dest_id_',
            packetNumber: 123,
            payload: 'test data',
            keyPhase: true
        );

        $this->assertSame(PacketType::ONE_RTT, $packet->getType());
        $this->assertSame('dest_id_', $packet->getDestinationConnectionId());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('test data', $packet->getPayload());
        $this->assertTrue($packet->getKeyPhase());
    }

    public function testConstructWithDefaults(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'conn_id_8',
            packetNumber: 456
        );

        $this->assertSame(PacketType::ONE_RTT, $packet->getType());
        $this->assertSame('conn_id_8', $packet->getDestinationConnectionId());
        $this->assertSame(456, $packet->getPacketNumber());
        $this->assertSame('', $packet->getPayload());
        $this->assertFalse($packet->getKeyPhase());
    }

    public function testGetDestinationConnectionId(): void
    {
        $packet = new ShortHeaderPacket('test_conn', 1);
        $this->assertSame('test_conn', $packet->getDestinationConnectionId());
    }

    public function testGetKeyPhase(): void
    {
        $packetTrue = new ShortHeaderPacket('conn_id', 1, '', true);
        $packetFalse = new ShortHeaderPacket('conn_id', 1, '', false);

        $this->assertTrue($packetTrue->getKeyPhase());
        $this->assertFalse($packetFalse->getKeyPhase());
    }

    public function testEncodeBasic(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'conn_id_',
            packetNumber: 123,
            payload: 'test',
            keyPhase: false
        );

        $encoded = $packet->encode();
        $this->assertNotEmpty($encoded);

        // 检查第一字节 - 应该是短包头包 (0x40 | packet_number_length)
        $firstByte = ord($encoded[0]);
        $this->assertSame(0, $firstByte & 0x80); // Header Form = 0
        $this->assertSame(0x40, $firstByte & 0x40); // Fixed Bit = 1
        $this->assertSame(0, $firstByte & 0x04); // Key Phase = 0
    }

    public function testEncodeWithKeyPhase(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'conn_id_',
            packetNumber: 123,
            payload: 'test',
            keyPhase: true
        );

        $encoded = $packet->encode();
        $firstByte = ord($encoded[0]);
        $this->assertSame(0x04, $firstByte & 0x04); // Key Phase = 1
    }

    public function testEncodePacketNumberLength(): void
    {
        // 测试不同的包号长度
        $testCases = [
            [100, 1],        // 1字节 (< 256)
            [1000, 2],       // 2字节 (< 65536)
            [100000, 3],     // 3字节 (< 16777216)
            [20000000, 4],   // 4字节 (>= 16777216)
        ];

        foreach ($testCases as [$packetNumber, $expectedLength]) {
            $packet = new ShortHeaderPacket('conn_id_', $packetNumber);
            $encoded = $packet->encode();
            $firstByte = ord($encoded[0]);
            $packetNumberLength = ($firstByte & 0x03) + 1;
            $this->assertSame($expectedLength, $packetNumberLength);
        }
    }

    public function testDecodeBasic(): void
    {
        $originalPacket = new ShortHeaderPacket(
            destinationConnectionId: 'conn_id_',
            packetNumber: 123,
            payload: 'test data',
            keyPhase: false
        );

        $encoded = $originalPacket->encode();
        $decodedPacket = ShortHeaderPacket::decode($encoded);

        $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
        $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
        $this->assertSame($originalPacket->getPayload(), $decodedPacket->getPayload());
        $this->assertSame($originalPacket->getKeyPhase(), $decodedPacket->getKeyPhase());
    }

    public function testDecodeWithKeyPhase(): void
    {
        $originalPacket = new ShortHeaderPacket(
            destinationConnectionId: 'testcon_',
            packetNumber: 456,
            payload: 'key phase test',
            keyPhase: true
        );

        $encoded = $originalPacket->encode();
        $decodedPacket = ShortHeaderPacket::decode($encoded);

        $this->assertTrue($decodedPacket->getKeyPhase());
        $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
    }

    public function testDecodeInsufficientData(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足');

        ShortHeaderPacket::decode('');
    }

    public function testDecodeInvalidHeaderForm(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('不是短包头包');

        // 创建长包头包的第一字节 (Header Form = 1)
        $data = chr(0x80) . str_repeat('x', 20);
        ShortHeaderPacket::decode($data);
    }

    public function testDecodeInvalidFixedBit(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('Fixed Bit 必须为1');

        // 创建没有设置Fixed Bit的数据
        $data = chr(0x00) . str_repeat('x', 20);
        ShortHeaderPacket::decode($data);
    }

    public function testDecodeInsufficientDataForConnectionId(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码连接ID');

        // 只有第一字节，没有足够数据给连接ID
        $data = chr(0x40);
        ShortHeaderPacket::decode($data);
    }

    public function testDecodeInsufficientDataForPacketNumber(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码包号');

        // 有连接ID但没有包号
        $data = chr(0x40) . str_repeat('x', 8);
        ShortHeaderPacket::decode($data);
    }

    public function testRoundTripEncodeDecode(): void
    {
        $testCases = [
            ['connid01', 1, 'payload1', false],
            ['connid02', 255, 'payload2', true],
            ['connid03', 65535, '', false],
            ['connid04', 16777215, 'large payload data', true],
        ];

        foreach ($testCases as [$connId, $packetNumber, $payload, $keyPhase]) {
            $originalPacket = new ShortHeaderPacket($connId, $packetNumber, $payload, $keyPhase);
            $encoded = $originalPacket->encode();
            $decodedPacket = ShortHeaderPacket::decode($encoded);

            $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
            $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
            $this->assertSame($originalPacket->getPayload(), $decodedPacket->getPayload());
            $this->assertSame($originalPacket->getKeyPhase(), $decodedPacket->getKeyPhase());
            $this->assertSame($originalPacket->getType(), $decodedPacket->getType());
        }
    }

    public function testGetSize(): void
    {
        $packet = new ShortHeaderPacket('conn_id_', 123, 'test');
        $size = $packet->getSize();
        $this->assertGreaterThan(0, $size);
        $this->assertSame(strlen($packet->encode()), $size);
    }

    public function testEmptyPayload(): void
    {
        $packet = new ShortHeaderPacket('conn_id_', 1, '');
        $encoded = $packet->encode();
        $decoded = ShortHeaderPacket::decode($encoded);

        $this->assertSame('', $decoded->getPayload());
    }

    public function testLargePayload(): void
    {
        $largePayload = str_repeat('A', 1000);
        $packet = new ShortHeaderPacket('conn_id_', 1, $largePayload);
        $encoded = $packet->encode();
        $decoded = ShortHeaderPacket::decode($encoded);

        $this->assertSame($largePayload, $decoded->getPayload());
    }
}
