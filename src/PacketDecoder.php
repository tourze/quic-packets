<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;

/**
 * QUIC 包解码器
 *
 * 负责从二进制数据解码为包对象
 */
class PacketDecoder
{
    /**
     * 解码包
     */
    public function decode(string $data): Packet
    {
        if ('' === $data) {
            throw new InvalidPacketDataException('数据不能为空');
        }

        $firstByte = ord($data[0]);

        // 判断是长包头还是短包头
        if (($firstByte & 0x80) !== 0) {
            return $this->decodeLongHeaderPacket($data);
        }

        return $this->decodeShortHeaderPacket($data);
    }

    /**
     * 解码长包头包
     */
    private function decodeLongHeaderPacket(string $data): Packet
    {
        if (strlen($data) < 6) {
            throw new InvalidPacketDataException('长包头数据长度不足');
        }

        // 首先检查是否是版本协商包（版本为 0x00000000）
        $versionData = unpack('N', substr($data, 1, 4));
        if (false === $versionData) {
            throw new InvalidPacketDataException('无法解码版本');
        }
        $version = $versionData[1];
        if (0x00000000 === $version) {
            return VersionNegotiationPacket::decode($data);
        }

        $firstByte = ord($data[0]);
        $packetType = ($firstByte >> 4) & 0x03;

        return match ($packetType) {
            PacketType::INITIAL->value => InitialPacket::decode($data),
            PacketType::ZERO_RTT->value => ZeroRTTPacket::decode($data),
            PacketType::HANDSHAKE->value => HandshakePacket::decode($data),
            PacketType::RETRY->value => RetryPacket::decode($data),
            default => throw new InvalidPacketTypeException('未知的长包头包类型：' . $packetType),
        };
    }

    /**
     * 解码短包头包
     */
    private function decodeShortHeaderPacket(string $data): ShortHeaderPacket
    {
        return ShortHeaderPacket::decode($data);
    }

    /**
     * 尝试解码包（不抛出异常）
     */
    public function tryDecode(string $data): ?Packet
    {
        try {
            return $this->decode($data);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * 批量解码包
     *
     * @param array<string> $dataArray
     * @return array<Packet>
     */
    public function decodeBatch(array $dataArray): array
    {
        $packets = [];
        foreach ($dataArray as $data) {
            $packets[] = $this->decode($data);
        }

        return $packets;
    }

    /**
     * 检测包类型（不完整解码）
     */
    public function detectPacketType(string $data): ?PacketType
    {
        if ('' === $data) {
            return null;
        }

        $firstByte = ord($data[0]);

        // 短包头包直接返回
        if (($firstByte & 0x80) === 0) {
            return PacketType::ONE_RTT;
        }

        // 长包头包 - 检查版本协商包
        if ($this->isVersionNegotiationPacket($data)) {
            return PacketType::VERSION_NEGOTIATION;
        }

        // 其他长包头包
        $packetType = ($firstByte >> 4) & 0x03;

        return match ($packetType) {
            0 => PacketType::INITIAL,
            1 => PacketType::ZERO_RTT,
            2 => PacketType::HANDSHAKE,
            3 => PacketType::RETRY,
        };
    }

    /**
     * 验证包格式是否正确（不完整解码）
     */
    public function validatePacketFormat(string $data): bool
    {
        if ('' === $data) {
            return false;
        }

        $firstByte = ord($data[0]);

        // 检查 Fixed Bit
        if (($firstByte & 0x40) === 0) {
            return false;
        }

        // 检查最小长度
        if (($firstByte & 0x80) !== 0) {
            // 长包头包最少需要6字节
            if (strlen($data) < 6) {
                return false;
            }

            // 检查版本协商包
            $versionData = unpack('N', substr($data, 1, 4));
            if (false !== $versionData) {
                $version = $versionData[1];
                if (0x00000000 === $version) {
                    // 版本协商包至少需要7字节
                    return strlen($data) >= 7;
                }
            }

            return true;
        }

        // 短包头包最少需要2字节
        return strlen($data) >= 2;
    }

    /**
     * 检查是否为版本协商包
     */
    private function isVersionNegotiationPacket(string $data): bool
    {
        if (strlen($data) < 5) {
            return false;
        }

        $versionData = unpack('N', substr($data, 1, 4));
        if (false === $versionData) {
            return false;
        }

        return 0x00000000 === $versionData[1];
    }
}
