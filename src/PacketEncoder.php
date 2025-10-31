<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;

/**
 * QUIC 包编码器
 *
 * 负责将包对象编码为二进制数据
 */
class PacketEncoder
{
    /**
     * 编码包
     */
    public function encode(Packet $packet): string
    {
        return $packet->encode();
    }

    /**
     * 批量编码包
     *
     * @param array<Packet> $packets
     * @return array<string>
     */
    public function encodeBatch(array $packets): array
    {
        $encoded = [];
        foreach ($packets as $packet) {
            if (!$packet instanceof Packet) {
                throw new InvalidPacketDataException('所有元素必须是 Packet 实例');
            }
            $encoded[] = $this->encode($packet);
        }

        return $encoded;
    }

    /**
     * 编码包并添加校验和（如果需要）
     */
    public function encodeWithChecksum(Packet $packet): string
    {
        return $this->encode($packet);

        // 对于某些包类型，可能需要添加校验和
        // 这里是扩展点，暂时直接返回编码结果
    }

    /**
     * 获取编码后的包大小
     */
    public function getEncodedSize(Packet $packet): int
    {
        return strlen($this->encode($packet));
    }

    /**
     * 验证包是否可以编码
     */
    public function canEncode(Packet $packet): bool
    {
        try {
            $this->encode($packet);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
