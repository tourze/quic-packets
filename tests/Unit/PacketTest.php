<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Packet;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;

class PacketTest extends TestCase
{
    private function createTestPacket(
        PacketType $type = PacketType::INITIAL,
        ?int $packetNumber = 123,
        string $payload = 'test_payload'
    ): Packet {
        return new class($type, $packetNumber, $payload) extends Packet {
            public function encode(): string
            {
                return 'encoded_packet_data';
            }

            public static function decode(string $data): static
            {
                return new static(PacketType::INITIAL, 123, 'decoded_payload');
            }
        };
    }

    public function testConstruct(): void
    {
        $packet = $this->createTestPacket();

        $this->assertSame(PacketType::INITIAL, $packet->getType());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('test_payload', $packet->getPayload());
    }

    public function testConstructWithNullPacketNumber(): void
    {
        $packet = $this->createTestPacket(packetNumber: null);

        $this->assertNull($packet->getPacketNumber());
    }

    public function testConstructWithEmptyPayload(): void
    {
        $packet = $this->createTestPacket(payload: '');

        $this->assertSame('', $packet->getPayload());
    }

    public function testGetType(): void
    {
        $type = PacketType::HANDSHAKE;
        $packet = $this->createTestPacket($type);

        $this->assertSame($type, $packet->getType());
    }

    public function testGetPacketNumber(): void
    {
        $packetNumber = 456789;
        $packet = $this->createTestPacket(packetNumber: $packetNumber);

        $this->assertSame($packetNumber, $packet->getPacketNumber());
    }

    public function testGetPayload(): void
    {
        $payload = 'custom_payload_data';
        $packet = $this->createTestPacket(payload: $payload);

        $this->assertSame($payload, $packet->getPayload());
    }

    public function testGetSize(): void
    {
        $packet = $this->createTestPacket();
        $size = $packet->getSize();

        $this->assertSame(strlen('encoded_packet_data'), $size);
        $this->assertGreaterThan(0, $size);
    }

    public function testEncodeVariableIntOneByteValues(): void
    {
        $testCases = [
            0 => "\x00",
            1 => "\x01",
            63 => "\x3F",
        ];

        foreach ($testCases as $value => $expected) {
            $encoded = TestPacket::encodeVariableIntPublic($value);
            $this->assertSame($expected, $encoded);
        }
    }

    public function testEncodeVariableIntTwoByteValues(): void
    {
        $testCases = [
            64 => "\x40\x40",
            100 => "\x40\x64",
            16383 => "\x7F\xFF",
        ];

        foreach ($testCases as $value => $expected) {
            $encoded = TestPacket::encodeVariableIntPublic($value);
            $this->assertSame($expected, $encoded);
        }
    }

    public function testEncodeVariableIntFourByteValues(): void
    {
        $testCases = [
            16384 => "\x80\x00\x40\x00",
            1000000 => "\x80\x0F\x42\x40",
            1073741823 => "\xBF\xFF\xFF\xFF",
        ];

        foreach ($testCases as $value => $expected) {
            $encoded = TestPacket::encodeVariableIntPublic($value);
            $this->assertSame($expected, $encoded);
        }
    }

    public function testEncodeVariableIntEightByteValues(): void
    {
        // 测试第一个值
        $encoded1 = TestPacket::encodeVariableIntPublic(1073741824);
        $this->assertSame("\xC0\x00\x00\x00\x40\x00\x00\x00", $encoded1);
        
        // 测试较大的值，使用正确的最大值（PHP_INT_MAX的变长整数限制内）
        // 4611686018427387903 是 (2^62 - 1)，这是8字节变长整数的最大值
        $maxValue = 0x3FFFFFFFFFFFFFFF; // 十六进制表示，避免浮点数转换
        $encoded2 = TestPacket::encodeVariableIntPublic($maxValue);
        $this->assertSame("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", $encoded2);
    }

    public function testEncodeVariableIntValueTooLarge(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $tooLargeValue = 0x4000000000000000; // 2^62，超过最大值
        $this->expectExceptionMessage('变长整数值过大：' . $tooLargeValue);

        TestPacket::encodeVariableIntPublic($tooLargeValue);
    }

    public function testDecodeVariableIntOneByteValues(): void
    {
        $testCases = [
            "\x00" => [0, 1],
            "\x01" => [1, 1],
            "\x3F" => [63, 1],
        ];

        foreach ($testCases as $data => $expected) {
            $result = TestPacket::decodeVariableIntPublic($data);
            $this->assertSame($expected, $result);
        }
    }

    public function testDecodeVariableIntTwoByteValues(): void
    {
        $testCases = [
            "\x40\x40" => [64, 2],
            "\x40\x64" => [100, 2],
            "\x7F\xFF" => [16383, 2],
        ];

        foreach ($testCases as $data => $expected) {
            $result = TestPacket::decodeVariableIntPublic($data);
            $this->assertSame($expected, $result);
        }
    }

    public function testDecodeVariableIntInsufficientData(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据不足以解码变长整数');

        TestPacket::decodeVariableIntPublic('');
    }

    public function testDecodeVariableIntInsufficientDataForTwoBytes(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据不足');

        TestPacket::decodeVariableIntPublic("\x40");
    }

    public function testEncodePacketNumberOneByte(): void
    {
        $encoded = TestPacket::encodePacketNumberPublic(123, 1);
        $this->assertSame(chr(123), $encoded);
    }

    public function testEncodePacketNumberTwoBytes(): void
    {
        $encoded = TestPacket::encodePacketNumberPublic(1000, 2);
        $this->assertSame(pack('n', 1000), $encoded);
    }

    public function testEncodePacketNumberThreeBytes(): void
    {
        $encoded = TestPacket::encodePacketNumberPublic(100000, 3);
        $expected = substr(pack('N', 100000), 1);
        $this->assertSame($expected, $encoded);
    }

    public function testEncodePacketNumberFourBytes(): void
    {
        $encoded = TestPacket::encodePacketNumberPublic(10000000, 4);
        $this->assertSame(pack('N', 10000000), $encoded);
    }

    public function testEncodePacketNumberInvalidLength(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('包号长度必须是1-4字节');

        TestPacket::encodePacketNumberPublic(123, 5);
    }

    public function testDecodePacketNumberOneByte(): void
    {
        $data = chr(123);
        $result = TestPacket::decodePacketNumberPublic($data, 0, 1);
        $this->assertSame(123, $result);
    }

    public function testDecodePacketNumberTwoBytes(): void
    {
        $data = pack('n', 1000);
        $result = TestPacket::decodePacketNumberPublic($data, 0, 2);
        $this->assertSame(1000, $result);
    }

    public function testDecodePacketNumberInvalidLength(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('包号长度必须是1-4字节');

        TestPacket::decodePacketNumberPublic('test', 0, 5);
    }
}

// 测试辅助类，用于测试 protected/static 方法
class TestPacket extends Packet
{
    public function encode(): string
    {
        return 'test_encoded_data';
    }

    public static function decode(string $data): static
    {
        return new static(PacketType::INITIAL);
    }

    public static function encodeVariableIntPublic(int $value): string
    {
        return static::encodeVariableInt($value);
    }

    public static function decodeVariableIntPublic(string $data, int $offset = 0): array
    {
        return static::decodeVariableInt($data, $offset);
    }

    public static function encodePacketNumberPublic(int $packetNumber, int $length): string
    {
        return static::encodePacketNumber($packetNumber, $length);
    }

    public static function decodePacketNumberPublic(string $data, int $offset, int $length): int
    {
        return static::decodePacketNumber($data, $offset, $length);
    }
}