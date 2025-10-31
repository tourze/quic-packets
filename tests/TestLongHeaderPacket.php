<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use Tourze\QUIC\Packets\LongHeaderPacket;
use Tourze\QUIC\Packets\PacketType;

/**
 * 测试辅助类，用于测试 protected/static 方法
 *
 * @internal
 */
final class TestLongHeaderPacket extends LongHeaderPacket
{
    public static function decode(string $data): static
    {
        return new self(PacketType::INITIAL, 1, '', '');
    }

    /**
     * @return array{typeValue: int, typeSpecificBits: int, version: int, destinationConnectionId: string, sourceConnectionId: string, offset: int}
     */
    public static function decodeLongHeaderPublic(string $data, int $offset): array
    {
        return static::decodeLongHeader($data, $offset);
    }

    public function encode(): string
    {
        return '';
    }

    protected function getTypeSpecificBits(): int
    {
        return 0;
    }
}
