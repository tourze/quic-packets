<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;

/**
 * 短包头包（1-RTT包）
 *
 * 根据 RFC 9000 Section 17.3 定义
 *
 * @phpstan-consistent-constructor
 */
class ShortHeaderPacket extends Packet
{
    public function __construct(
        protected readonly string $destinationConnectionId,
        int $packetNumber,
        string $payload = '',
        protected readonly bool $keyPhase = false,
    ) {
        parent::__construct(PacketType::ONE_RTT, $packetNumber, $payload);
    }

    /**
     * 获取目标连接ID
     */
    public function getDestinationConnectionId(): string
    {
        return $this->destinationConnectionId;
    }

    /**
     * 获取密钥阶段位
     */
    public function getKeyPhase(): bool
    {
        return $this->keyPhase;
    }

    /**
     * 编码包
     */
    public function encode(): string
    {
        assert(null !== $this->packetNumber, '包号不能为null');

        // 第一字节：Header Form (1) + Fixed Bit (1) + Spin Bit (1) + Reserved Bits (2) + Key Phase (1) + Packet Number Length (2)
        $firstByte = 0x40; // Header Form = 0, Fixed Bit = 1

        // Key Phase位
        if ($this->keyPhase) {
            $firstByte |= 0x04;
        }

        // 计算包号长度
        $packetNumberLength = $this->calculatePacketNumberLength($this->packetNumber);
        $firstByte |= ($packetNumberLength - 1) & 0x03; // Packet Number Length

        $packet = chr($firstByte);

        // 目标连接ID
        $packet .= $this->destinationConnectionId;

        // 包号
        $packet .= self::encodePacketNumber($this->packetNumber, $packetNumberLength);

        // 负载
        $packet .= $this->payload;

        return $packet;
    }

    /**
     * 解码包
     */
    public static function decode(string $data): static
    {
        $offset = 0;

        if (strlen($data) < 1) {
            throw new InvalidPacketDataException('数据长度不足');
        }

        $firstByte = ord($data[$offset++]);

        // 验证包格式
        if (($firstByte & 0x80) !== 0) {
            throw new InvalidPacketTypeException('不是短包头包');
        }

        if (($firstByte & 0x40) === 0) {
            throw new InvalidPacketDataException('Fixed Bit 必须为1');
        }

        // 解析 Key Phase
        $keyPhase = ($firstByte & 0x04) !== 0;

        // 解析包号长度
        $packetNumberLength = ($firstByte & 0x03) + 1;

        // 目标连接ID（需要从连接上下文获取长度，这里假设为8字节）
        $connIdLength = 8; // 实际实现中需要从连接状态获取
        if (strlen($data) < $offset + $connIdLength) {
            throw new InvalidPacketDataException('数据长度不足以解码连接ID');
        }
        $destinationConnectionId = substr($data, $offset, $connIdLength);
        $offset += $connIdLength;

        // 解析包号
        if (strlen($data) < $offset + $packetNumberLength) {
            throw new InvalidPacketDataException('数据长度不足以解码包号');
        }
        $packetNumber = self::decodePacketNumber($data, $offset, $packetNumberLength);
        $offset += $packetNumberLength;

        // 负载
        $payload = substr($data, $offset);

        return new static($destinationConnectionId, $packetNumber, $payload, $keyPhase);
    }

    /**
     * 计算包号编码所需的字节数
     */
    private function calculatePacketNumberLength(int $packetNumber): int
    {
        if ($packetNumber < 256) {
            return 1;
        }
        if ($packetNumber < 65536) {
            return 2;
        }
        if ($packetNumber < 16777216) {
            return 3;
        }

        return 4;
    }
}
