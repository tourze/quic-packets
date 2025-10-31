<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use Tourze\QUIC\Packets\Packet;
use Tourze\QUIC\Packets\PacketType;

/**
 * 测试辅助类，用于测试 protected/static 方法
 *
 * @internal
 */
final class TestPacket extends Packet
{
    public static function decode(string $data): static
    {
        return new self(PacketType::INITIAL);
    }

    public static function encodeVariableIntPublic(int $value): string
    {
        return static::encodeVariableInt($value);
    }

    /**
     * @return array{0: int, 1: int} [值, 字节数]
     */
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

    public function encode(): string
    {
        return 'test_encoded_data';
    }
}
