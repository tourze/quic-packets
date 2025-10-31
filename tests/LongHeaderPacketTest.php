<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\LongHeaderPacket;
use Tourze\QUIC\Packets\PacketType;

/**
 * @internal
 */
#[CoversClass(LongHeaderPacket::class)]
final class LongHeaderPacketTest extends TestCase
{
    private function createTestPacket(
        PacketType $type = PacketType::INITIAL,
        int $version = 0x00000001,
        string $destinationConnectionId = 'dest_id',
        string $sourceConnectionId = 'src_id',
        ?int $packetNumber = 123,
        string $payload = 'test_payload',
    ): LongHeaderPacket {
        return new class($type, $version, $destinationConnectionId, $sourceConnectionId, $packetNumber, $payload) extends LongHeaderPacket {
            public function encode(): string
            {
                return $this->encodeLongHeader() . 'dummy_payload';
            }

            public static function decode(string $data): static
            {
                $headerData = self::decodeLongHeader($data, 0);

                return new self(
                    PacketType::INITIAL,
                    $headerData['version'],
                    $headerData['destinationConnectionId'],
                    $headerData['sourceConnectionId'],
                    123,
                    'decoded_payload'
                );
            }

            protected function getTypeSpecificBits(): int
            {
                return 0x00;
            }
        };
    }

    public function testConstructWithValidLongHeaderType(): void
    {
        $packet = $this->createTestPacket();

        $this->assertSame(PacketType::INITIAL, $packet->getType());
        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_id', $packet->getSourceConnectionId());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('test_payload', $packet->getPayload());
    }

    public function testConstructWithDifferentLongHeaderTypes(): void
    {
        $longHeaderTypes = [
            PacketType::INITIAL,
            PacketType::ZERO_RTT,
            PacketType::HANDSHAKE,
            PacketType::RETRY,
            PacketType::VERSION_NEGOTIATION,
        ];

        foreach ($longHeaderTypes as $type) {
            $packet = $this->createTestPacket($type);
            $this->assertSame($type, $packet->getType());
        }
    }

    public function testConstructWithInvalidShortHeaderType(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('只能用于长包头包类型');

        $packet = $this->createTestPacket(PacketType::ONE_RTT);
        $this->assertNotNull($packet); // 不会执行到这里，但避免 PHPStan 警告
    }

    public function testConstructWithStatelessResetType(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('只能用于长包头包类型');

        $packet = $this->createTestPacket(PacketType::STATELESS_RESET);
        $this->assertNotNull($packet); // 不会执行到这里，但避免 PHPStan 警告
    }

    public function testGetVersion(): void
    {
        $version = 0x12345678;
        $packet = $this->createTestPacket(version: $version);

        $this->assertSame($version, $packet->getVersion());
    }

    public function testGetDestinationConnectionId(): void
    {
        $destId = 'destination_connection_id_123';
        $packet = $this->createTestPacket(destinationConnectionId: $destId);

        $this->assertSame($destId, $packet->getDestinationConnectionId());
    }

    public function testGetSourceConnectionId(): void
    {
        $srcId = 'source_connection_id_456';
        $packet = $this->createTestPacket(sourceConnectionId: $srcId);

        $this->assertSame($srcId, $packet->getSourceConnectionId());
    }

    public function testEncodeLongHeader(): void
    {
        $packet = $this->createTestPacket();
        $encoded = $packet->encode();

        $this->assertNotEmpty($encoded);
    }

    public function testDecodeLongHeaderValidData(): void
    {
        // 创建一个测试用的长包头数据，确保 Fixed Bit 设置为1
        $testData = "\xC0\x00\x00\x00\x01\x07dest_id\x06src_id";
        $offset = 0;

        $headerData = TestLongHeaderPacket::decodeLongHeaderPublic($testData, $offset);

        $this->assertSame(0, $headerData['typeValue']);
        $this->assertSame(0x00000001, $headerData['version']);
        $this->assertSame('dest_id', $headerData['destinationConnectionId']);
        $this->assertSame('src_id', $headerData['sourceConnectionId']);
    }

    public function testDecodeLongHeaderInsufficientData(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码长包头');

        $shortData = "\x80\x00\x00"; // 数据太短
        $offset = 0;
        TestLongHeaderPacket::decodeLongHeaderPublic($shortData, $offset);
    }

    public function testDecodeLongHeaderNotLongHeader(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('不是长包头包');

        $shortHeaderData = "\x40\x00\x00\x00\x01\x07dest_id\x06src_id"; // 短包头
        $offset = 0;
        TestLongHeaderPacket::decodeLongHeaderPublic($shortHeaderData, $offset);
    }

    public function testDecodeLongHeaderInvalidFixedBit(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('Fixed Bit 必须为1');

        $invalidData = "\x80\x00\x00\x00\x01\x07dest_id\x06src_id"; // Fixed bit = 0
        $invalidData[0] = chr(ord($invalidData[0]) & ~0x40); // 清除 Fixed Bit
        $offset = 0;
        TestLongHeaderPacket::decodeLongHeaderPublic($invalidData, $offset);
    }

    public function testEmptyConnectionIds(): void
    {
        $packet = $this->createTestPacket(
            destinationConnectionId: '',
            sourceConnectionId: ''
        );

        $this->assertSame('', $packet->getDestinationConnectionId());
        $this->assertSame('', $packet->getSourceConnectionId());
    }
}
