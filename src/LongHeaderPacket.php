<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;

/**
 * 长包头包抽象类
 *
 * 根据 RFC 9000 Section 17.2 定义
 */
abstract class LongHeaderPacket extends Packet
{
    public function __construct(
        PacketType $type,
        protected readonly int $version,
        protected readonly string $destinationConnectionId,
        protected readonly string $sourceConnectionId,
        ?int $packetNumber = null,
        string $payload = '',
    ) {
        if (!$type->isLongHeader()) {
            throw new InvalidPacketTypeException('只能用于长包头包类型');
        }

        parent::__construct($type, $packetNumber, $payload);
    }

    /**
     * 获取版本
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * 获取目标连接ID
     */
    public function getDestinationConnectionId(): string
    {
        return $this->destinationConnectionId;
    }

    /**
     * 获取源连接ID
     */
    public function getSourceConnectionId(): string
    {
        return $this->sourceConnectionId;
    }

    /**
     * 编码长包头公共部分
     */
    protected function encodeLongHeader(): string
    {
        $header = '';

        // 第一字节：Header Form (1) + Fixed Bit (1) + Long Packet Type (2) + Type-Specific Bits (4)
        $firstByte = 0x80; // Header Form = 1 (长包头)
        $firstByte |= 0x40; // Fixed Bit = 1
        $firstByte |= ($this->type->value & 0x03) << 4; // 包类型

        // Type-Specific Bits由子类设置
        $header .= chr($firstByte | $this->getTypeSpecificBits());

        // 版本（4字节）
        $header .= pack('N', $this->version);

        // 目标连接ID长度（1字节）+ 目标连接ID
        $header .= chr(strlen($this->destinationConnectionId));
        $header .= $this->destinationConnectionId;

        // 源连接ID长度（1字节）+ 源连接ID
        $header .= chr(strlen($this->sourceConnectionId));
        $header .= $this->sourceConnectionId;

        return $header;
    }

    /**
     * 解码长包头公共部分
     *
     * @return array{typeValue: int, typeSpecificBits: int, version: int, destinationConnectionId: string, sourceConnectionId: string, offset: int}
     */
    protected static function decodeLongHeader(string $data, int $offset): array
    {
        if (strlen($data) < $offset + 7) {
            throw new InvalidPacketDataException('数据长度不足以解码长包头');
        }

        $firstByte = ord($data[$offset++]);

        // 验证包格式
        if (($firstByte & 0x80) === 0) {
            throw new InvalidPacketDataException('不是长包头包');
        }

        if (($firstByte & 0x40) === 0) {
            throw new InvalidPacketDataException('Fixed Bit 必须为1');
        }

        // 解析包类型
        $typeValue = ($firstByte >> 4) & 0x03;
        $typeSpecificBits = $firstByte & 0x0F;

        // 解析版本
        $versionData = unpack('N', substr($data, $offset, 4));
        if (false === $versionData) {
            throw new InvalidPacketDataException('无法解码版本');
        }
        $version = $versionData[1];
        $offset += 4;

        // 解析目标连接ID
        $destConnIdLength = ord($data[$offset++]);
        if (strlen($data) < $offset + $destConnIdLength) {
            throw new InvalidPacketDataException('数据长度不足以解码目标连接ID');
        }
        $destinationConnectionId = substr($data, $offset, $destConnIdLength);
        $offset += $destConnIdLength;

        // 解析源连接ID
        $srcConnIdLength = ord($data[$offset++]);
        if (strlen($data) < $offset + $srcConnIdLength) {
            throw new InvalidPacketDataException('数据长度不足以解码源连接ID');
        }
        $sourceConnectionId = substr($data, $offset, $srcConnIdLength);
        $offset += $srcConnIdLength;

        return [
            'typeValue' => $typeValue,
            'typeSpecificBits' => $typeSpecificBits,
            'version' => $version,
            'destinationConnectionId' => $destinationConnectionId,
            'sourceConnectionId' => $sourceConnectionId,
            'offset' => $offset,
        ];
    }

    /**
     * 获取类型特定位
     */
    abstract protected function getTypeSpecificBits(): int;
}
