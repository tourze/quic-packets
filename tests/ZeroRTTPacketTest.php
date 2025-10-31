<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\ZeroRTTPacket;

/**
 * @internal
 */
#[CoversClass(ZeroRTTPacket::class)]
final class ZeroRTTPacketTest extends TestCase
{
    public function testCreateZeroRTTPacket(): void
    {
        $packet = new ZeroRTTPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest_conn_id',
            sourceConnectionId: 'src_conn_id_',
            packetNumber: 123,
            payload: 'early data'
        );

        $this->assertSame(PacketType::ZERO_RTT, $packet->getType());
        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_conn_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_conn_id_', $packet->getSourceConnectionId());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('early data', $packet->getPayload());
    }

    public function testEncodeAndDecodeZeroRTTPacket(): void
    {
        $originalPacket = new ZeroRTTPacket(
            version: 0x00000001,
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            packetNumber: 456,
            payload: 'Hello 0-RTT World!'
        );

        // 编码
        $encoded = $originalPacket->encode();
        $this->assertNotEmpty($encoded);

        // 解码
        $decodedPacket = ZeroRTTPacket::decode($encoded);

        // 验证
        $this->assertSame($originalPacket->getType(), $decodedPacket->getType());
        $this->assertSame($originalPacket->getVersion(), $decodedPacket->getVersion());
        $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
        $this->assertSame($originalPacket->getSourceConnectionId(), $decodedPacket->getSourceConnectionId());
        $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
        $this->assertSame($originalPacket->getPayload(), $decodedPacket->getPayload());
    }

    public function testZeroRTTPacketWithDifferentPacketNumberLengths(): void
    {
        $testCases = [
            ['packetNumber' => 100, 'expectedLength' => 1],
            ['packetNumber' => 1000, 'expectedLength' => 2],
            ['packetNumber' => 100000, 'expectedLength' => 3],
            ['packetNumber' => 10000000, 'expectedLength' => 4],
        ];

        foreach ($testCases as $case) {
            $packet = new ZeroRTTPacket(
                version: 0x00000001,
                destinationConnectionId: 'dest',
                sourceConnectionId: 'src',
                packetNumber: $case['packetNumber'],
                payload: 'test'
            );

            $encoded = $packet->encode();
            $decoded = ZeroRTTPacket::decode($encoded);

            $this->assertSame($case['packetNumber'], $decoded->getPacketNumber());
        }
    }

    public function testZeroRTTPacketWithEmptyPayload(): void
    {
        $packet = new ZeroRTTPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            packetNumber: 1,
            payload: ''
        );

        $encoded = $packet->encode();
        $decoded = ZeroRTTPacket::decode($encoded);

        $this->assertSame('', $decoded->getPayload());
    }

    public function testDecodeInvalidZeroRTTPacket(): void
    {
        // 测试错误的包类型
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('不是 0-RTT 包');

        // 创建一个 Initial 包的数据，然后尝试用 ZeroRTTPacket 解码
        $invalidData = "\xc0\x00\x00\x00\x01\x04dest\x04src_\x01\x00\x05hello";
        ZeroRTTPacket::decode($invalidData);
    }

    public function testDecodeInsufficientData(): void
    {
        $this->expectException(InvalidPacketDataException::class);

        // 数据长度不足
        $invalidData = "\xd0\x00\x00\x00\x01";
        ZeroRTTPacket::decode($invalidData);
    }
}
