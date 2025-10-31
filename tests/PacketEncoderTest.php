<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\HandshakePacket;
use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\Packet;
use Tourze\QUIC\Packets\PacketEncoder;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\RetryPacket;
use Tourze\QUIC\Packets\ShortHeaderPacket;
use Tourze\QUIC\Packets\StatelessResetPacket;
use Tourze\QUIC\Packets\VersionNegotiationPacket;
use Tourze\QUIC\Packets\ZeroRTTPacket;

/**
 * @internal
 */
#[CoversClass(PacketEncoder::class)]
final class PacketEncoderTest extends TestCase
{
    private PacketEncoder $encoder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->encoder = new PacketEncoder();
    }

    public function testEncodeInitialPacket(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'test payload'
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeHandshakePacket(): void
    {
        $packet = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            packetNumber: 100,
            payload: 'handshake data'
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeZeroRTTPacket(): void
    {
        $packet = new ZeroRTTPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            packetNumber: 200,
            payload: '0-RTT data'
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeShortHeaderPacket(): void
    {
        $packet = new ShortHeaderPacket(
            destinationConnectionId: 'dest1234',
            packetNumber: 300,
            payload: 'short header payload'
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeVersionNegotiationPacket(): void
    {
        $packet = new VersionNegotiationPacket(
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            supportedVersions: [0x00000001, 0x00000002]
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeRetryPacket(): void
    {
        $packet = new RetryPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            retryToken: 'retry_token_data',
            retryIntegrityTag: str_repeat("\x00", 16)
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeStatelessResetPacket(): void
    {
        $packet = new StatelessResetPacket(
            randomData: str_repeat('X', 20),
            statelessResetToken: str_repeat("\xFF", 16)
        );

        $encoded = $this->encoder->encode($packet);

        $this->assertGreaterThan(0, strlen($encoded));
    }

    public function testEncodeBatchWithValidPackets(): void
    {
        $packets = [
            new InitialPacket(
                version: 0x00000001,
                destinationConnectionId: 'dest1',
                sourceConnectionId: 'src1',
                token: '',
                packetNumber: 1,
                payload: 'payload1'
            ),
            new HandshakePacket(
                version: 0x00000001,
                destinationConnectionId: 'dest2',
                sourceConnectionId: 'src2',
                packetNumber: 2,
                payload: 'payload2'
            ),
        ];

        $encoded = $this->encoder->encodeBatch($packets);

        $this->assertCount(2, $encoded);
        $this->assertIsString($encoded[0]);
        $this->assertIsString($encoded[1]);
        $this->assertGreaterThan(0, strlen($encoded[0]));
        $this->assertGreaterThan(0, strlen($encoded[1]));
    }

    public function testEncodeBatchWithInvalidElementThrowsException(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('所有元素必须是 Packet 实例');

        /** @var array<mixed> $packets - 故意混合类型以测试异常 */
        $packets = [
            new InitialPacket(
                version: 0x00000001,
                destinationConnectionId: 'dest1',
                sourceConnectionId: 'src1',
                token: '',
                packetNumber: 1,
                payload: 'payload1'
            ),
            'invalid_element',
        ];

        /** @phpstan-ignore-next-line */
        $this->encoder->encodeBatch($packets);
    }

    public function testEncodeWithChecksum(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'test payload'
        );

        $encoded = $this->encoder->encodeWithChecksum($packet);
        $normalEncoded = $this->encoder->encode($packet);

        // 当前实现中，checksum和普通编码相同
        $this->assertEquals($normalEncoded, $encoded);
    }

    public function testGetEncodedSize(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'test payload'
        );

        $size = $this->encoder->getEncodedSize($packet);
        $encoded = $this->encoder->encode($packet);

        $this->assertEquals(strlen($encoded), $size);
        $this->assertGreaterThan(0, $size);
    }

    public function testCanEncodeValidPacket(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'test payload'
        );

        $canEncode = $this->encoder->canEncode($packet);

        $this->assertTrue($canEncode);
    }

    public function testCanEncodeWithInvalidPacket(): void
    {
        // 创建一个会在编码时抛出异常的测试包
        // 通过匿名类实现来避免使用 mock
        $packet = new class extends Packet {
            public function __construct()
            {
                parent::__construct(PacketType::INITIAL);
            }

            public function encode(): string
            {
                throw new InvalidPacketDataException('编码失败');
            }

            public static function decode(string $data): static
            {
                throw new InvalidPacketDataException('解码失败');
            }
        };

        $canEncode = $this->encoder->canEncode($packet);

        $this->assertFalse($canEncode);
    }

    public function testEncodeDifferentPacketTypesReturnDifferentData(): void
    {
        $initialPacket = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'initial payload'
        );

        $handshakePacket = new HandshakePacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            packetNumber: 42,
            payload: 'handshake payload'
        );

        $initialEncoded = $this->encoder->encode($initialPacket);
        $handshakeEncoded = $this->encoder->encode($handshakePacket);

        $this->assertNotEquals($initialEncoded, $handshakeEncoded);
    }

    public function testEncodeSamePacketTwiceReturnsSameResult(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest1234',
            sourceConnectionId: 'src1234',
            token: 'token123',
            packetNumber: 42,
            payload: 'test payload'
        );

        $encoded1 = $this->encoder->encode($packet);
        $encoded2 = $this->encoder->encode($packet);

        $this->assertEquals($encoded1, $encoded2);
    }
}
