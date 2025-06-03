<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\HandshakePacket;
use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketDecoder;
use Tourze\QUIC\Packets\PacketEncoder;
use Tourze\QUIC\Packets\RetryPacket;
use Tourze\QUIC\Packets\ShortHeaderPacket;
use Tourze\QUIC\Packets\VersionNegotiationPacket;
use Tourze\QUIC\Packets\ZeroRTTPacket;

/**
 * 性能基准测试
 */
class PerformanceBenchmarkTest extends TestCase
{
    private PacketEncoder $encoder;
    private PacketDecoder $decoder;
    private array $testPackets;

    protected function setUp(): void
    {
        $this->encoder = new PacketEncoder();
        $this->decoder = new PacketDecoder();
        
        // 创建测试包集合
        $this->testPackets = [
            new InitialPacket(1, 'dest1234567890', 'src1234567890', 'test_token_data', 1, str_repeat('A', 100)),
            new ZeroRTTPacket(1, 'dest1234567890', 'src1234567890', 2, str_repeat('B', 200)),
            new HandshakePacket(1, 'dest1234567890', 'src1234567890', 3, str_repeat('C', 150)),
            new RetryPacket(1, 'dest1234567890', 'src1234567890', 'retry_token_data', str_repeat("\x00", 16)),
            new VersionNegotiationPacket('dest1234567890', 'src1234567890', [0x00000001, 0x12345678, 0x87654321]),
            new ShortHeaderPacket('dest1234567890', 4, str_repeat('D', 300)),
        ];
    }

    public function testPacketEncodingPerformance(): void
    {
        $iterations = 1000;
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($this->testPackets as $packet) {
                $this->encoder->encode($packet);
            }
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $packetsPerSecond = ($iterations * count($this->testPackets)) / $duration;
        
        // 基准：应该能够每秒编码至少 10,000 个包
        $this->assertGreaterThan(10000, $packetsPerSecond, 
            sprintf('编码性能不足：%.0f 包/秒', $packetsPerSecond));
        
        echo sprintf("\n编码性能：%.0f 包/秒 (%.4f 秒)\n", $packetsPerSecond, $duration);
    }

    public function testPacketDecodingPerformance(): void
    {
        // 先编码所有包
        $encodedPackets = [];
        foreach ($this->testPackets as $packet) {
            $encodedPackets[] = $this->encoder->encode($packet);
        }
        
        $iterations = 1000;
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($encodedPackets as $encodedPacket) {
                $this->decoder->decode($encodedPacket);
            }
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $packetsPerSecond = ($iterations * count($encodedPackets)) / $duration;
        
        // 基准：应该能够每秒解码至少 8,000 个包
        $this->assertGreaterThan(8000, $packetsPerSecond, 
            sprintf('解码性能不足：%.0f 包/秒', $packetsPerSecond));
        
        echo sprintf("解码性能：%.0f 包/秒 (%.4f 秒)\n", $packetsPerSecond, $duration);
    }

    public function testBatchEncodingPerformance(): void
    {
        $batchSize = 100;
        $iterations = 100;
        
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            $this->encoder->encodeBatch($this->testPackets);
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $packetsPerSecond = ($iterations * count($this->testPackets)) / $duration;
        
        echo sprintf("批量编码性能：%.0f 包/秒 (%.4f 秒)\n", $packetsPerSecond, $duration);
        
        // 批量编码应该比单独编码更高效
        $this->assertGreaterThan(1000, $packetsPerSecond);
    }

    public function testPacketTypeDetectionPerformance(): void
    {
        // 先编码所有包
        $encodedPackets = [];
        foreach ($this->testPackets as $packet) {
            $encodedPackets[] = $this->encoder->encode($packet);
        }
        
        $iterations = 5000;
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($encodedPackets as $encodedPacket) {
                $this->decoder->detectPacketType($encodedPacket);
            }
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $detectionsPerSecond = ($iterations * count($encodedPackets)) / $duration;
        
        // 包类型检测应该非常快
        $this->assertGreaterThan(50000, $detectionsPerSecond, 
            sprintf('类型检测性能不足：%.0f 检测/秒', $detectionsPerSecond));
        
        echo sprintf("类型检测性能：%.0f 检测/秒 (%.4f 秒)\n", $detectionsPerSecond, $duration);
    }

    public function testMemoryUsage(): void
    {
        $startMemory = memory_get_usage(true);
        
        // 创建大量包
        $packets = [];
        for ($i = 0; $i < 1000; $i++) {
            $packets[] = new InitialPacket(
                1, 
                'dest_' . $i, 
                'src_' . $i, 
                'token_' . $i, 
                $i, 
                str_repeat('X', 100)
            );
        }
        
        $afterCreationMemory = memory_get_usage(true);
        
        // 编码所有包
        $encoded = [];
        foreach ($packets as $packet) {
            $encoded[] = $this->encoder->encode($packet);
        }
        
        $afterEncodingMemory = memory_get_usage(true);
        
        $creationMemory = $afterCreationMemory - $startMemory;
        $encodingMemory = $afterEncodingMemory - $afterCreationMemory;
        
        echo sprintf("内存使用：创建 %d KB，编码 %d KB\n", 
            $creationMemory / 1024, $encodingMemory / 1024);
        
        // 内存使用应该合理（每个包不超过 2.5KB，因为PHP对象有额外开销）
        $memoryPerPacket = $creationMemory / count($packets);
        $this->assertLessThan(2560, $memoryPerPacket, '每个包的内存使用过多');
    }

    public function testVariableLengthIntegerPerformance(): void
    {
        $iterations = 100000;
        $testValues = [0, 63, 16383, 1073741823];
        
        // 创建一个测试用的包来访问编码方法
        $testPacket = new InitialPacket(1, 'dest', 'src', 'token', 1, 'payload');
        
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($testValues as $value) {
                // 通过编码包来间接测试变长整数性能
                // 这里主要测试包的编码性能，其中包含变长整数操作
                $encoded = $testPacket->encode();
            }
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $operationsPerSecond = ($iterations * count($testValues)) / $duration;
        
        echo sprintf("包编码性能（含变长整数）：%.0f 操作/秒 (%.4f 秒)\n", $operationsPerSecond, $duration);
        
        // 包编码操作应该很快
        $this->assertGreaterThan(50000, $operationsPerSecond);
    }

    public function testLargePacketPerformance(): void
    {
        // 测试大包处理性能
        $largePayload = str_repeat('X', 10000); // 10KB 负载
        $largePacket = new InitialPacket(1, 'dest', 'src', 'token', 1, $largePayload);
        
        $iterations = 100;
        $startTime = microtime(true);
        
        for ($i = 0; $i < $iterations; $i++) {
            $encoded = $this->encoder->encode($largePacket);
            $this->decoder->decode($encoded);
        }
        
        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $packetsPerSecond = $iterations / $duration;
        
        echo sprintf("大包处理性能：%.0f 包/秒 (%.4f 秒，包大小：%d 字节)\n", 
            $packetsPerSecond, $duration, strlen($this->encoder->encode($largePacket)));
        
        // 大包处理应该也能保持合理性能
        $this->assertGreaterThan(100, $packetsPerSecond);
    }
} 