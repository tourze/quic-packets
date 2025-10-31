<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\HandshakePacket;
use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketDecoder;
use Tourze\QUIC\Packets\PacketEncoder;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\RetryPacket;
use Tourze\QUIC\Packets\ShortHeaderPacket;
use Tourze\QUIC\Packets\VersionNegotiationPacket;
use Tourze\QUIC\Packets\ZeroRTTPacket;

/**
 * @internal
 */
#[CoversClass(PacketEncoder::class)]
final class PacketEncoderDecoderTest extends TestCase
{
    private PacketEncoder $encoder;

    private PacketDecoder $decoder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->encoder = new PacketEncoder();
        $this->decoder = new PacketDecoder();
    }

    public function testInitialPacketEncodeDecode(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src5678',
            token: 'test_token',
            packetNumber: 123,
            payload: 'Hello QUIC'
        );

        // 编码
        $encoded = $this->encoder->encode($packet);
        $this->assertNotEmpty($encoded);

        // 解码
        $decoded = $this->decoder->decode($encoded);
        $this->assertInstanceOf(InitialPacket::class, $decoded);
        $this->assertEquals(PacketType::INITIAL, $decoded->getType());
        $this->assertEquals(0x00000001, $decoded->getVersion());
        $this->assertEquals('dest1234', $decoded->getDestinationConnectionId());
        $this->assertEquals('src5678', $decoded->getSourceConnectionId());
        $this->assertEquals('test_token', $decoded->getToken());
        $this->assertEquals(123, $decoded->getPacketNumber());
        $this->assertEquals('Hello QUIC', $decoded->getPayload());
    }

    public function testHandshakePacketEncodeDecode(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src5678',
            packetNumber: 456,
            payload: 'Handshake data'
        );

        // 编码
        $encoded = $this->encoder->encode($packet);
        $this->assertNotEmpty($encoded);

        // 解码
        $decoded = $this->decoder->decode($encoded);
        $this->assertInstanceOf(HandshakePacket::class, $decoded);
        $this->assertEquals(PacketType::HANDSHAKE, $decoded->getType());
        $this->assertEquals(0x00000001, $decoded->getVersion());
        $this->assertEquals('dest1234', $decoded->getDestinationConnectionId());
        $this->assertEquals('src5678', $decoded->getSourceConnectionId());
        $this->assertEquals(456, $decoded->getPacketNumber());
        $this->assertEquals('Handshake data', $decoded->getPayload());
    }

    public function testShortHeaderPacketEncodeDecode(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'dest5678',
            packetNumber: 789,
            payload: '1-RTT data',
            keyPhase: true
        );

        // 编码
        $encoded = $this->encoder->encode($packet);
        $this->assertNotEmpty($encoded);

        // 解码
        $decoded = $this->decoder->decode($encoded);
        $this->assertInstanceOf(ShortHeaderPacket::class, $decoded);
        $this->assertEquals(PacketType::ONE_RTT, $decoded->getType());
        $this->assertEquals('dest5678', $decoded->getDestinationConnectionId());
        $this->assertEquals(789, $decoded->getPacketNumber());
        $this->assertEquals('1-RTT data', $decoded->getPayload());
        $this->assertTrue($decoded->getKeyPhase());
    }

    public function testBatchEncodeDecode(): void
    {
        $packets = [
            new InitialPacket(1, 'dest1234', 'src12345', 'token1', 1, 'payload1'),
            new HandshakePacket(1, 'dest1234', 'src12345', 2, 'payload2'),
            new ShortHeaderPacket('12345678', 3, 'payload3'), // 8字节连接ID
        ];

        // 批量编码
        $encoded = $this->encoder->encodeBatch($packets);
        $this->assertCount(3, $encoded);

        // 批量解码
        $decoded = $this->decoder->decodeBatch($encoded);
        $this->assertCount(3, $decoded);

        for ($i = 0; $i < 3; ++$i) {
            $this->assertEquals($packets[$i]->getType(), $decoded[$i]->getType());
            $this->assertEquals($packets[$i]->getPacketNumber(), $decoded[$i]->getPacketNumber());
            $this->assertEquals($packets[$i]->getPayload(), $decoded[$i]->getPayload());
        }
    }

    public function testPacketTypeDetection(): void
    {
        $initialPacket = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $handshakePacket = new HandshakePacket(1, 'dest', 'src', 2, 'data');
        $shortPacket = new ShortHeaderPacket('dest', 3, 'data');

        $initialEncoded = $this->encoder->encode($initialPacket);
        $handshakeEncoded = $this->encoder->encode($handshakePacket);
        $shortEncoded = $this->encoder->encode($shortPacket);

        $this->assertEquals(PacketType::INITIAL, $this->decoder->detectPacketType($initialEncoded));
        $this->assertEquals(PacketType::HANDSHAKE, $this->decoder->detectPacketType($handshakeEncoded));
        $this->assertEquals(PacketType::ONE_RTT, $this->decoder->detectPacketType($shortEncoded));
    }

    public function testPacketValidation(): void
    {
        $validPacket = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $validEncoded = $this->encoder->encode($validPacket);

        $this->assertTrue($this->decoder->validatePacketFormat($validEncoded));
        $this->assertFalse($this->decoder->validatePacketFormat(''));
        $this->assertFalse($this->decoder->validatePacketFormat('x')); // Fixed bit 错误
    }

    public function testInvalidPacketDecoding(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->decoder->decode('');
    }

    public function testTryDecode(): void
    {
        $validPacket = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $validEncoded = $this->encoder->encode($validPacket);

        $decoded = $this->decoder->tryDecode($validEncoded);
        $this->assertNotNull($decoded);
        $this->assertEquals(PacketType::INITIAL, $decoded->getType());

        $invalidDecoded = $this->decoder->tryDecode('invalid');
        $this->assertNull($invalidDecoded);
    }

    public function testEncoderCanEncode(): void
    {
        $packet = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $this->assertTrue($this->encoder->canEncode($packet));
    }

    public function testEncodedSize(): void
    {
        $packet = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $encoded = $this->encoder->encode($packet);
        $size = $this->encoder->getEncodedSize($packet);

        $this->assertEquals(strlen($encoded), $size);
        $this->assertGreaterThan(0, $size);
    }

    public function testDecodeAllPacketTypes(): void
    {
        $testPackets = [
            new InitialPacket(1, 'dest1', 'src1', 'token1', 1, 'initial_data'),
            new ZeroRTTPacket(1, 'dest2', 'src2', 2, 'early_data'),
            new HandshakePacket(1, 'dest3', 'src3', 3, 'handshake_data'),
            new RetryPacket(1, 'dest4', 'src4', 'retry_token', str_repeat("\x00", 16)),
            new VersionNegotiationPacket('dest5', 'src5', [0x00000001, 0x12345678]),
            new ShortHeaderPacket('conn67890', 4, 'app_data'),
        ];

        foreach ($testPackets as $originalPacket) {
            $encoded = $this->encoder->encode($originalPacket);
            $decodedPacket = $this->decoder->decode($encoded);

            $this->assertSame($originalPacket->getType(), $decodedPacket->getType());

            // 验证特定字段（使用类型检查和强制转换）
            if ($originalPacket instanceof InitialPacket && $decodedPacket instanceof InitialPacket) {
                $this->assertSame($originalPacket->getToken(), $decodedPacket->getToken());
            } elseif ($originalPacket instanceof RetryPacket && $decodedPacket instanceof RetryPacket) {
                $this->assertSame($originalPacket->getRetryToken(), $decodedPacket->getRetryToken());
            } elseif ($originalPacket instanceof VersionNegotiationPacket && $decodedPacket instanceof VersionNegotiationPacket) {
                $this->assertSame($originalPacket->getSupportedVersions(), $decodedPacket->getSupportedVersions());
            }
        }
    }

    public function testCanEncode(): void
    {
        $validPacket = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $this->assertTrue($this->encoder->canEncode($validPacket));

        $handshakePacket = new HandshakePacket(1, 'dest', 'src', 2, 'handshake');
        $this->assertTrue($this->encoder->canEncode($handshakePacket));
    }

    public function testEncodeBatch(): void
    {
        $packets = [
            new InitialPacket(1, 'dest1', 'src1', 'token1', 1, 'data1'),
            new HandshakePacket(1, 'dest2', 'src2', 2, 'data2'),
        ];

        $encoded = $this->encoder->encodeBatch($packets);
        $this->assertCount(2, $encoded);
        $this->assertIsString($encoded[0]);
        $this->assertIsString($encoded[1]);
    }

    public function testEncodeWithChecksum(): void
    {
        $packet = new InitialPacket(1, 'dest', 'src', 'token', 1, 'data');
        $encoded = $this->encoder->encodeWithChecksum($packet);
        $this->assertNotEmpty($encoded);

        // 验证与普通编码结果一致（当前实现中）
        $normalEncoded = $this->encoder->encode($packet);
        $this->assertEquals($normalEncoded, $encoded);
    }
}
