<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;

/**
 * Version Negotiation 包
 *
 * 根据 RFC 9000 Section 17.2.1 定义
 * 用于服务器向客户端发送支持的 QUIC 版本列表
 */
class VersionNegotiationPacket extends Packet
{
    public function __construct(
        protected readonly string $destinationConnectionId,
        protected readonly string $sourceConnectionId,
        protected readonly array $supportedVersions,
    ) {
        parent::__construct(
            PacketType::VERSION_NEGOTIATION,
            null
        );
    }

    /**
     * 获取目标连接 ID
     */
    public function getDestinationConnectionId(): string
    {
        return $this->destinationConnectionId;
    }

    /**
     * 获取源连接 ID
     */
    public function getSourceConnectionId(): string
    {
        return $this->sourceConnectionId;
    }

    /**
     * 获取支持的版本列表
     */
    public function getSupportedVersions(): array
    {
        return $this->supportedVersions;
    }

    /**
     * 编码包
     */
    public function encode(): string
    {
        $packet = '';

        // First byte: Fixed Bit (1) + Unused (1) + Form (1) + Fixed Bit (1) + Unused (4)
        $firstByte = 0x80; // Fixed bit + Form bit (long header)
        $packet .= chr($firstByte);

        // Version (0x00000000 for Version Negotiation)
        $packet .= pack('N', 0x00000000);

        // Destination Connection ID Length
        $dcidLength = strlen($this->destinationConnectionId);
        if ($dcidLength > 255) {
            throw new InvalidPacketDataException('目标连接 ID 长度不能超过 255 字节');
        }
        $packet .= chr($dcidLength);

        // Destination Connection ID
        $packet .= $this->destinationConnectionId;

        // Source Connection ID Length
        $scidLength = strlen($this->sourceConnectionId);
        if ($scidLength > 255) {
            throw new InvalidPacketDataException('源连接 ID 长度不能超过 255 字节');
        }
        $packet .= chr($scidLength);

        // Source Connection ID
        $packet .= $this->sourceConnectionId;

        // Supported Versions (4 bytes each)
        foreach ($this->supportedVersions as $version) {
            if (!is_int($version)) {
                throw new InvalidPacketDataException('版本必须是整数');
            }
            $packet .= pack('N', $version);
        }

        return $packet;
    }

    /**
     * 解码包
     */
    public static function decode(string $data): static
    {
        if (strlen($data) < 7) {
            throw new InvalidPacketDataException('数据长度不足以解码版本协商包');
        }

        $offset = 0;

        // First byte
        $firstByte = ord($data[$offset++]);
        if (($firstByte & 0x80) === 0) {
            throw new InvalidPacketTypeException('不是长包头包');
        }

        // Version (应该是 0x00000000)
        $version = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;
        if ($version !== 0x00000000) {
            throw new InvalidPacketTypeException('不是版本协商包');
        }

        // Destination Connection ID Length
        $dcidLength = ord($data[$offset++]);
        if (strlen($data) < $offset + $dcidLength) {
            throw new InvalidPacketDataException('数据长度不足以解码目标连接 ID');
        }

        // Destination Connection ID
        $destinationConnectionId = substr($data, $offset, $dcidLength);
        $offset += $dcidLength;

        // Source Connection ID Length
        if (strlen($data) < $offset + 1) {
            throw new InvalidPacketDataException('数据长度不足以解码源连接 ID 长度');
        }
        $scidLength = ord($data[$offset++]);
        if (strlen($data) < $offset + $scidLength) {
            throw new InvalidPacketDataException('数据长度不足以解码源连接 ID');
        }

        // Source Connection ID
        $sourceConnectionId = substr($data, $offset, $scidLength);
        $offset += $scidLength;

        // Supported Versions
        $supportedVersions = [];
        while ($offset + 4 <= strlen($data)) {
            $supportedVersions[] = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;
        }

        if (empty($supportedVersions)) {
            throw new InvalidPacketDataException('版本协商包必须包含至少一个支持的版本');
        }

        return new static(
            $destinationConnectionId,
            $sourceConnectionId,
            $supportedVersions
        );
    }

    /**
     * 检查是否支持指定版本
     */
    public function supportsVersion(int $version): bool
    {
        return in_array($version, $this->supportedVersions, true);
    }

    /**
     * 获取最高支持的版本
     */
    public function getHighestSupportedVersion(): int
    {
        return max($this->supportedVersions);
    }

    /**
     * 获取最低支持的版本
     */
    public function getLowestSupportedVersion(): int
    {
        return min($this->supportedVersions);
    }
} 