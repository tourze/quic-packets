<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\VersionNegotiationPacket;

class VersionNegotiationPacketTest extends TestCase
{
    public function testCreateVersionNegotiationPacket(): void
    {
        $supportedVersions = [0x00000001, 0x12345678, 0x87654321];

        $packet = new VersionNegotiationPacket(
            destinationConnectionId: 'dest_conn_id',
            sourceConnectionId: 'src_conn_id_',
            supportedVersions: $supportedVersions
        );

        $this->assertSame(PacketType::VERSION_NEGOTIATION, $packet->getType());
        $this->assertSame('dest_conn_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_conn_id_', $packet->getSourceConnectionId());
        $this->assertSame($supportedVersions, $packet->getSupportedVersions());
    }

    public function testEncodeAndDecodeVersionNegotiationPacket(): void
    {
        $supportedVersions = [0x00000001, 0xaabbccdd, 0x12345678];

        $originalPacket = new VersionNegotiationPacket(
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            supportedVersions: $supportedVersions
        );

        // 编码
        $encoded = $originalPacket->encode();
        $this->assertNotEmpty($encoded);

        // 解码
        $decodedPacket = VersionNegotiationPacket::decode($encoded);

        // 验证
        $this->assertSame($originalPacket->getType(), $decodedPacket->getType());
        $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
        $this->assertSame($originalPacket->getSourceConnectionId(), $decodedPacket->getSourceConnectionId());
        $this->assertSame($originalPacket->getSupportedVersions(), $decodedPacket->getSupportedVersions());
    }

    public function testVersionSupport(): void
    {
        $supportedVersions = [0x00000001, 0x12345678, 0x87654321];
        $packet = new VersionNegotiationPacket(
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            supportedVersions: $supportedVersions
        );

        // 测试支持的版本
        $this->assertTrue($packet->supportsVersion(0x00000001));
        $this->assertTrue($packet->supportsVersion(0x12345678));
        $this->assertTrue($packet->supportsVersion(0x87654321));

        // 测试不支持的版本
        $this->assertFalse($packet->supportsVersion(0x99999999));
        $this->assertFalse($packet->supportsVersion(0x00000000));
    }

    public function testGetHighestAndLowestSupportedVersions(): void
    {
        $supportedVersions = [0x00000001, 0x12345678, 0x87654321];
        $packet = new VersionNegotiationPacket(
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            supportedVersions: $supportedVersions
        );

        $this->assertSame(0x87654321, $packet->getHighestSupportedVersion());
        $this->assertSame(0x00000001, $packet->getLowestSupportedVersion());
    }

    public function testDecodeInvalidVersionNegotiationPacket(): void
    {
        $this->expectException(InvalidPacketDataException::class);

        // 数据长度不足
        $invalidData = "\x80\x00\x00";
        VersionNegotiationPacket::decode($invalidData);
    }

    public function testDecodeNonVersionNegotiationPacket(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('不是版本协商包');

        // 版本不是 0x00000000
        $invalidData = "\x80\x00\x00\x00\x01\x04dest\x04src_";
        VersionNegotiationPacket::decode($invalidData);
    }
} 