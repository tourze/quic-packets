<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

/**
 * QUIC 包抽象基类
 *
 * 根据 RFC 9000 规范定义
 */
abstract class Packet
{
    public function __construct(
        protected readonly PacketType $type,
        protected readonly ?int $packetNumber = null,
        protected readonly string $payload = '',
    ) {
    }

    /**
     * 编码包为二进制数据
     */
    abstract public function encode(): string;

    /**
     * 从二进制数据解码包
     */
    abstract public static function decode(string $data): static;

    /**
     * 获取包类型
     */
    public function getType(): PacketType
    {
        return $this->type;
    }

    /**
     * 获取包号
     */
    public function getPacketNumber(): ?int
    {
        return $this->packetNumber;
    }

    /**
     * 获取负载
     */
    public function getPayload(): string
    {
        return $this->payload;
    }

    /**
     * 获取包大小
     */
    public function getSize(): int
    {
        return strlen($this->encode());
    }

    /**
     * 编码变长整数（RFC 9000 Section 16）
     */
    protected static function encodeVariableInt(int $value): string
    {
        if ($value < 64) {
            return chr($value);
        } elseif ($value < 16384) {
            return pack('n', $value | 0x4000);
        } elseif ($value < 1073741824) {
            return pack('N', $value | 0x80000000);
        } elseif ($value < 4611686018427387904) {
            return pack('J', $value | 0xC000000000000000);
        }

        throw new \InvalidArgumentException('变长整数值过大：' . $value);
    }

    /**
     * 解码变长整数
     */
    protected static function decodeVariableInt(string $data, int $offset = 0): array
    {
        if (!isset($data[$offset])) {
            throw new \InvalidArgumentException('数据不足以解码变长整数');
        }

        $firstByte = ord($data[$offset]);
        $prefix = ($firstByte & 0xC0) >> 6;

        return match ($prefix) {
            0 => [$firstByte & 0x3F, 1],
            1 => [
                (($firstByte & 0x3F) << 8) | ord($data[$offset + 1] ?? throw new \InvalidArgumentException('数据不足')),
                2
            ],
            2 => [
                (($firstByte & 0x3F) << 24) |
                (ord($data[$offset + 1] ?? throw new \InvalidArgumentException('数据不足')) << 16) |
                (ord($data[$offset + 2] ?? throw new \InvalidArgumentException('数据不足')) << 8) |
                ord($data[$offset + 3] ?? throw new \InvalidArgumentException('数据不足')),
                4
            ],
            3 => [
                (($firstByte & 0x3F) << 56) |
                (ord($data[$offset + 1] ?? throw new \InvalidArgumentException('数据不足')) << 48) |
                (ord($data[$offset + 2] ?? throw new \InvalidArgumentException('数据不足')) << 40) |
                (ord($data[$offset + 3] ?? throw new \InvalidArgumentException('数据不足')) << 32) |
                (ord($data[$offset + 4] ?? throw new \InvalidArgumentException('数据不足')) << 24) |
                (ord($data[$offset + 5] ?? throw new \InvalidArgumentException('数据不足')) << 16) |
                (ord($data[$offset + 6] ?? throw new \InvalidArgumentException('数据不足')) << 8) |
                ord($data[$offset + 7] ?? throw new \InvalidArgumentException('数据不足')),
                8
            ],
        };
    }

    /**
     * 编码包号（1-4字节）
     */
    protected static function encodePacketNumber(int $packetNumber, int $length): string
    {
        return match ($length) {
            1 => chr($packetNumber & 0xFF),
            2 => pack('n', $packetNumber & 0xFFFF),
            3 => substr(pack('N', $packetNumber), 1),
            4 => pack('N', $packetNumber),
            default => throw new \InvalidArgumentException('包号长度必须是1-4字节'),
        };
    }

    /**
     * 解码包号
     */
    protected static function decodePacketNumber(string $data, int $offset, int $length): int
    {
        return match ($length) {
            1 => ord($data[$offset]),
            2 => unpack('n', substr($data, $offset, 2))[1],
            3 => unpack('N', "\x00" . substr($data, $offset, 3))[1],
            4 => unpack('N', substr($data, $offset, 4))[1],
            default => throw new \InvalidArgumentException('包号长度必须是1-4字节'),
        };
    }
} 