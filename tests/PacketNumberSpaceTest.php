<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketNumberSpaceException;
use Tourze\QUIC\Packets\PacketNumberSpace;
use Tourze\QUIC\Packets\PacketType;

/**
 * 包号空间管理器测试
 */
class PacketNumberSpaceTest extends TestCase
{
    private PacketNumberSpace $space;

    protected function setUp(): void
    {
        $this->space = new PacketNumberSpace(PacketType::INITIAL);
    }

    public function testGetNext(): void
    {
        $first = $this->space->getNext();
        $second = $this->space->getNext();

        $this->assertEquals(0, $first);
        $this->assertEquals(1, $second);
        $this->assertEquals(1, $this->space->getLargestSent());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->space->isValid(0));
        $this->assertTrue($this->space->isValid(100));
        $this->assertTrue($this->space->isValid(0x3FFFFFFFFFFFFFFF));
        
        $this->assertFalse($this->space->isValid(-1));
        $this->assertFalse($this->space->isValid(0x4000000000000000));
    }

    public function testRecordReceived(): void
    {
        $this->space->recordReceived(5);
        $this->space->recordReceived(10);

        $this->assertEquals(10, $this->space->getLargestReceived());
        
        // 重复包号应该无效
        $this->assertFalse($this->space->isValid(5));
    }

    public function testAcknowledge(): void
    {
        $packetNumber = $this->space->getNext();
        $this->assertContains($packetNumber, $this->space->getUnacknowledged());

        $this->space->acknowledge($packetNumber);
        $this->assertNotContains($packetNumber, $this->space->getUnacknowledged());
    }

    public function testGetUnacknowledged(): void
    {
        $p1 = $this->space->getNext();
        $p2 = $this->space->getNext();
        $p3 = $this->space->getNext();

        $unacked = $this->space->getUnacknowledged();
        $this->assertCount(3, $unacked);
        $this->assertContains($p1, $unacked);
        $this->assertContains($p2, $unacked);
        $this->assertContains($p3, $unacked);

        $this->space->acknowledge($p2);
        $unacked = $this->space->getUnacknowledged();
        $this->assertCount(2, $unacked);
        $this->assertNotContains($p2, $unacked);
    }

    public function testCalculatePacketNumberLength(): void
    {
        $this->assertEquals(1, $this->space->calculatePacketNumberLength(255));
        $this->assertEquals(2, $this->space->calculatePacketNumberLength(256));
        $this->assertEquals(2, $this->space->calculatePacketNumberLength(65535));
        $this->assertEquals(3, $this->space->calculatePacketNumberLength(65536));
        $this->assertEquals(3, $this->space->calculatePacketNumberLength(16777215));
        $this->assertEquals(4, $this->space->calculatePacketNumberLength(16777216));
    }

    public function testDetectLoss(): void
    {
        // 发送5个包
        $packets = [];
        for ($i = 0; $i < 5; $i++) {
            $packets[] = $this->space->getNext();
        }

        // 确认包 2 和 4
        $this->space->acknowledge($packets[2]);
        $this->space->acknowledge($packets[4]);

        // 检测丢失（阈值为1，这样包0和包1会被认为丢失）
        $lost = $this->space->detectLoss(1);
        
        // 包0和包1应该被认为丢失（在包4之前且差距超过阈值）
        $this->assertCount(2, $lost);
        $this->assertContains($packets[0], $lost);
        $this->assertContains($packets[1], $lost);
    }

    public function testGetSpaceType(): void
    {
        $this->assertEquals(PacketType::INITIAL, $this->space->getSpaceType());

        $handshakeSpace = new PacketNumberSpace(PacketType::HANDSHAKE);
        $this->assertEquals(PacketType::HANDSHAKE, $handshakeSpace->getSpaceType());
    }

    public function testGetStats(): void
    {
        $this->space->getNext();
        $this->space->getNext();
        $p1 = $this->space->getNext();
        
        $this->space->acknowledge($p1);
        $this->space->recordReceived(10);

        $stats = $this->space->getStats();
        
        $this->assertEquals('Initial', $stats['space_type']);
        $this->assertEquals(3, $stats['next_packet_number']);
        $this->assertEquals(2, $stats['largest_sent']);
        $this->assertEquals(10, $stats['largest_received']);
        $this->assertEquals(3, $stats['sent_packets']);
        $this->assertEquals(1, $stats['received_packets']);
        $this->assertEquals(1, $stats['acked_packets']);
        $this->assertEquals(2, $stats['unacked_packets']);
    }

    public function testInvalidPacketNumberException(): void
    {
        $this->expectException(InvalidPacketNumberSpaceException::class);
        $this->space->recordReceived(-1);
    }

    public function testCleanup(): void
    {
        // 获取一个包号并确认它
        $packetNumber = $this->space->getNext();
        $this->space->acknowledge($packetNumber);
        
        // 记录一个接收的包
        $this->space->recordReceived(100);

        // 清理应该不会抛出错误
        $this->space->cleanup();
        
        // 验证数据结构仍然有效
        $stats = $this->space->getStats();
        $this->assertNotEmpty($stats);
    }
} 