<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\HandshakePacket;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;

class HandshakePacketTest extends TestCase
{
    public function testConstruct(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest_conn_id',
            sourceConnectionId: 'src_conn_id_',
            packetNumber: 123,
            payload: 'handshake data'
        );

        $this->assertSame(PacketType::HANDSHAKE, $packet->getType());
        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_conn_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_conn_id_', $packet->getSourceConnectionId());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('handshake data', $packet->getPayload());
    }

    public function testEncode(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            packetNumber: 456,
            payload: 'Hello Handshake!'
        );

        $encoded = $packet->encode();
        $this->assertNotEmpty($encoded);
    }

    public function testDecode(): void
    {
        $originalPacket = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            packetNumber: 456,
            payload: 'Hello Handshake!'
        );

        // 编码
        $encoded = $originalPacket->encode();

        // 解码
        $decodedPacket = HandshakePacket::decode($encoded);

        // 验证
        $this->assertSame($originalPacket->getType(), $decodedPacket->getType());
        $this->assertSame($originalPacket->getVersion(), $decodedPacket->getVersion());
        $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
        $this->assertSame($originalPacket->getSourceConnectionId(), $decodedPacket->getSourceConnectionId());
        $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
        $this->assertSame($originalPacket->getPayload(), $decodedPacket->getPayload());
    }

    public function testGetMethods(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest_id',
            sourceConnectionId: 'src_id',
            packetNumber: 789,
            payload: 'test payload'
        );

        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_id', $packet->getSourceConnectionId());
        $this->assertSame(789, $packet->getPacketNumber());
        $this->assertSame('test payload', $packet->getPayload());
        $this->assertSame(PacketType::HANDSHAKE, $packet->getType());
    }

    public function testHandshakePacketWithDifferentPacketNumberLengths(): void
    {
        $testCases = [
            ['packetNumber' => 100, 'expectedLength' => 1],
            ['packetNumber' => 1000, 'expectedLength' => 2], 
            ['packetNumber' => 100000, 'expectedLength' => 3],
            ['packetNumber' => 10000000, 'expectedLength' => 4],
        ];

        foreach ($testCases as $case) {
            $packet = new HandshakePacket(
                version: 0x00000001,
                destinationConnectionId: 'dest',
                sourceConnectionId: 'src',
                packetNumber: $case['packetNumber'],
                payload: 'test'
            );

            $encoded = $packet->encode();
            $decoded = HandshakePacket::decode($encoded);

            $this->assertSame($case['packetNumber'], $decoded->getPacketNumber());
        }
    }

    public function testHandshakePacketWithEmptyPayload(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            packetNumber: 1,
            payload: ''
        );

        $encoded = $packet->encode();
        $decoded = HandshakePacket::decode($encoded);

        $this->assertSame('', $decoded->getPayload());
        $this->assertSame(PacketType::HANDSHAKE, $decoded->getType());
    }

    public function testDecodeInvalidHandshakePacket(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('不是 Handshake 包');

        // 创建一个错误包类型的数据，然后尝试用 HandshakePacket 解码
        $invalidData = "\xc0\x00\x00\x00\x01\x04dest\x04src_\x01\x00\x05hello";
        HandshakePacket::decode($invalidData);
    }

    public function testDecodeInsufficientDataForPacketNumber(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码包号');

        // 数据长度不足以解码包号
        $invalidData = "\xe0\x00\x00\x00\x01\x04dest\x04src_\x05";
        HandshakePacket::decode($invalidData);
    }

    public function testDecodeInsufficientDataForPayload(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码负载');

        // 数据长度不足以解码负载
        $invalidData = "\xe0\x00\x00\x00\x01\x04dest\x04src_\x05\x01";
        HandshakePacket::decode($invalidData);
    }

    public function testEncodeDecodeWithLargePayload(): void
    {
        $largePayload = str_repeat('A', 1024);
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            packetNumber: 12345,
            payload: $largePayload
        );

        $encoded = $packet->encode();
        $decoded = HandshakePacket::decode($encoded);

        $this->assertSame($largePayload, $decoded->getPayload());
        $this->assertSame(12345, $decoded->getPacketNumber());
    }

    public function testConstructWithDefaultPayload(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            packetNumber: 1
        );

        $this->assertSame('', $packet->getPayload());
        $this->assertSame(PacketType::HANDSHAKE, $packet->getType());
    }
}
