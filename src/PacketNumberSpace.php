<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketNumberSpaceException;

/**
 * QUIC 包号空间管理器
 *
 * 根据 RFC 9000 Section 12.3 定义
 */
class PacketNumberSpace
{
    private int $nextPacketNumber = 0;

    private int $largestSentPacketNumber = -1;

    private int $largestReceivedPacketNumber = -1;

    /** @var array<int, array{sent_time: float, acked: bool, ack_time?: float}> */
    private array $sentPackets = [];

    /** @var array<int, array{received_time: float}> */
    private array $receivedPackets = [];

    public function __construct(
        private readonly PacketType $spaceType,
    ) {
        // 初始包号可以是随机值，这里为了简化设为0
        $this->nextPacketNumber = 0;
    }

    /**
     * 获取下一个包号
     */
    public function getNext(): int
    {
        $packetNumber = $this->nextPacketNumber++;
        $this->largestSentPacketNumber = max($this->largestSentPacketNumber, $packetNumber);
        $this->sentPackets[$packetNumber] = [
            'sent_time' => microtime(true),
            'acked' => false,
        ];

        return $packetNumber;
    }

    /**
     * 验证包号是否有效
     */
    public function isValid(int $packetNumber): bool
    {
        // 包号必须是非负数且不能超过最大值
        if ($packetNumber < 0 || $packetNumber > 0x3FFFFFFFFFFFFFFF) {
            return false;
        }

        // 如果是接收的包，检查是否重复
        if (isset($this->receivedPackets[$packetNumber])) {
            return false;
        }

        return true;
    }

    /**
     * 记录接收的包号
     */
    public function recordReceived(int $packetNumber): void
    {
        if (!$this->isValid($packetNumber)) {
            throw new InvalidPacketNumberSpaceException('无效的包号：' . $packetNumber);
        }

        $this->receivedPackets[$packetNumber] = [
            'received_time' => microtime(true),
        ];

        $this->largestReceivedPacketNumber = max($this->largestReceivedPacketNumber, $packetNumber);
    }

    /**
     * 确认包号（标记为已确认）
     */
    public function acknowledge(int $packetNumber): void
    {
        if (isset($this->sentPackets[$packetNumber])) {
            $this->sentPackets[$packetNumber]['acked'] = true;
            $this->sentPackets[$packetNumber]['ack_time'] = microtime(true);
        }
    }

    /**
     * 获取未确认的包号列表
     *
     * @return array<int>
     */
    public function getUnacknowledged(): array
    {
        $unacked = [];
        foreach ($this->sentPackets as $packetNumber => $info) {
            if (!$info['acked']) {
                $unacked[] = $packetNumber;
            }
        }

        return $unacked;
    }

    /**
     * 获取最大已发送包号
     */
    public function getLargestSent(): int
    {
        return $this->largestSentPacketNumber;
    }

    /**
     * 获取最大已接收包号
     */
    public function getLargestReceived(): int
    {
        return $this->largestReceivedPacketNumber;
    }

    /**
     * 获取包空间类型
     */
    public function getSpaceType(): PacketType
    {
        return $this->spaceType;
    }

    /**
     * 计算包号编码长度
     */
    public function calculatePacketNumberLength(int $packetNumber): int
    {
        // 根据包号大小选择编码长度
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

    /**
     * 检查是否有丢失的包
     *
     * @return array<int>
     */
    public function detectLoss(int $threshold = 3): array
    {
        $lostPackets = [];
        $largestAcked = -1;

        // 找到最大的已确认包号
        foreach ($this->sentPackets as $packetNumber => $info) {
            if ($info['acked']) {
                $largestAcked = max($largestAcked, $packetNumber);
            }
        }

        if (-1 === $largestAcked) {
            return $lostPackets;
        }

        // 检查在最大已确认包号之前的未确认包
        foreach ($this->sentPackets as $packetNumber => $info) {
            if (!$info['acked'] && $packetNumber < $largestAcked - $threshold) {
                $lostPackets[] = $packetNumber;
            }
        }

        return $lostPackets;
    }

    /**
     * 清理已确认的包信息（内存优化）
     */
    public function cleanup(): void
    {
        $cutoff = microtime(true) - 60; // 清理60秒前的记录

        foreach ($this->sentPackets as $packetNumber => $info) {
            if ($info['acked'] && $info['sent_time'] < $cutoff) {
                unset($this->sentPackets[$packetNumber]);
            }
        }

        foreach ($this->receivedPackets as $packetNumber => $info) {
            if ($info['received_time'] < $cutoff) {
                unset($this->receivedPackets[$packetNumber]);
            }
        }
    }

    /**
     * 获取统计信息
     *
     * @return array{space_type: string, next_packet_number: int, largest_sent: int, largest_received: int, sent_packets: int, received_packets: int, acked_packets: int, unacked_packets: int}
     */
    public function getStats(): array
    {
        $ackedCount = 0;
        $unackedCount = 0;

        foreach ($this->sentPackets as $info) {
            if ($info['acked']) {
                ++$ackedCount;
            } else {
                ++$unackedCount;
            }
        }

        return [
            'space_type' => $this->spaceType->getName(),
            'next_packet_number' => $this->nextPacketNumber,
            'largest_sent' => $this->largestSentPacketNumber,
            'largest_received' => $this->largestReceivedPacketNumber,
            'sent_packets' => count($this->sentPackets),
            'received_packets' => count($this->receivedPackets),
            'acked_packets' => $ackedCount,
            'unacked_packets' => $unackedCount,
        ];
    }
}
