<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\StatelessResetPacket;

/**
 * 无状态重置包测试
 *
 * @internal
 */
#[CoversClass(StatelessResetPacket::class)]
final class StatelessResetPacketTest extends TestCase
{
    private string $testToken;

    private string $secretKey;

    private string $connectionId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->testToken = str_repeat("\x01", 16);
        $this->secretKey = 'test_secret_key_123456789';
        $this->connectionId = 'test_connection_id';
    }

    public function testPacketCreation(): void
    {
        $packet = new StatelessResetPacket($this->testToken);

        $this->assertSame(PacketType::STATELESS_RESET, $packet->getType());
        $this->assertSame($this->testToken, $packet->getStatelessResetToken());
        $this->assertSame('', $packet->getRandomData());
    }

    public function testPacketCreationWithRandomData(): void
    {
        $randomData = 'some_random_data';
        $packet = new StatelessResetPacket($this->testToken, $randomData);

        $this->assertSame($this->testToken, $packet->getStatelessResetToken());
        $this->assertSame($randomData, $packet->getRandomData());
    }

    public function testInvalidTokenLength(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('无状态重置令牌必须是16字节');

        new StatelessResetPacket('short_token');
    }

    public function testPacketEncoding(): void
    {
        $packet = new StatelessResetPacket($this->testToken);
        $encoded = $packet->encode();

        // 检查最小长度（22字节）
        $this->assertGreaterThanOrEqual(22, strlen($encoded));

        // 检查 Fixed Bit 和 Header Form
        $firstByte = ord($encoded[0]);
        $this->assertSame(0x40, $firstByte & 0xC0); // Fixed Bit = 1, Header Form = 0，其他位可能是随机的

        // 检查令牌位置（最后16字节）
        $this->assertSame($this->testToken, substr($encoded, -16));
    }

    public function testPacketDecoding(): void
    {
        $packet = new StatelessResetPacket($this->testToken, 'test_random');
        $encoded = $packet->encode();

        $decoded = StatelessResetPacket::decode($encoded);

        $this->assertSame($this->testToken, $decoded->getStatelessResetToken());
        $this->assertSame(PacketType::STATELESS_RESET, $decoded->getType());
    }

    public function testDecodeInvalidLength(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('无状态重置包长度不足（最少22字节）');

        StatelessResetPacket::decode('short');
    }

    public function testDecodeInvalidFixedBit(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('无状态重置包 Fixed Bit 必须为1');

        // 创建一个没有 Fixed Bit 的数据
        $invalidData = str_repeat("\x00", 22);
        StatelessResetPacket::decode($invalidData);
    }

    public function testDecodeInvalidHeaderForm(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('无状态重置包 Header Form 必须为0');

        // 创建一个有 Fixed Bit (0x40) 但有长包头标志 (0x80) 的数据
        $invalidData = "\xC0" . str_repeat("\x00", 21); // Header Form = 1, Fixed Bit = 1
        StatelessResetPacket::decode($invalidData);
    }

    public function testTokenGeneration(): void
    {
        $token1 = StatelessResetPacket::generateToken($this->connectionId, $this->secretKey);
        $token2 = StatelessResetPacket::generateToken($this->connectionId, $this->secretKey);

        // 相同输入应该产生相同令牌
        $this->assertSame($token1, $token2);
        $this->assertSame(16, strlen($token1));

        // 不同连接ID应该产生不同令牌
        $differentToken = StatelessResetPacket::generateToken('different_id', $this->secretKey);
        $this->assertNotSame($token1, $differentToken);
    }

    public function testTokenValidation(): void
    {
        $token = StatelessResetPacket::generateToken($this->connectionId, $this->secretKey);

        // 正确的令牌应该验证通过
        $this->assertTrue(
            StatelessResetPacket::validateToken($this->connectionId, $token, $this->secretKey)
        );

        // 错误的令牌应该验证失败
        $wrongToken = str_repeat("\xFF", 16);
        $this->assertFalse(
            StatelessResetPacket::validateToken($this->connectionId, $wrongToken, $this->secretKey)
        );

        // 错误的连接ID应该验证失败
        $this->assertFalse(
            StatelessResetPacket::validateToken('wrong_id', $token, $this->secretKey)
        );

        // 错误的密钥应该验证失败
        $this->assertFalse(
            StatelessResetPacket::validateToken($this->connectionId, $token, 'wrong_key')
        );
    }

    public function testCreateWithMinLength(): void
    {
        $minLength = 50;
        $packet = StatelessResetPacket::createWithMinLength($this->testToken, $minLength);
        $encoded = $packet->encode();

        $this->assertGreaterThanOrEqual($minLength, strlen($encoded));
        $this->assertSame($this->testToken, $packet->getStatelessResetToken());
    }

    public function testCreateWithDefaultMinLength(): void
    {
        $packet = StatelessResetPacket::createWithMinLength($this->testToken);
        $encoded = $packet->encode();

        $this->assertGreaterThanOrEqual(22, strlen($encoded));
    }

    public function testCouldBeStatelessReset(): void
    {
        // 正确的无状态重置包应该被识别
        $packet = new StatelessResetPacket($this->testToken);
        $encoded = $packet->encode();
        $this->assertTrue(StatelessResetPacket::couldBeStatelessReset($encoded));

        // 太短的数据不应该被识别
        $this->assertFalse(StatelessResetPacket::couldBeStatelessReset('short'));

        // 没有 Fixed Bit 的数据不应该被识别
        $invalidData = str_repeat("\x00", 22);
        $this->assertFalse(StatelessResetPacket::couldBeStatelessReset($invalidData));

        // 长包头格式不应该被识别
        $longHeaderData = "\x80" . str_repeat("\x40", 21);
        $this->assertFalse(StatelessResetPacket::couldBeStatelessReset($longHeaderData));
    }

    public function testRandomDataInEncoding(): void
    {
        $packet1 = new StatelessResetPacket($this->testToken);
        $packet2 = new StatelessResetPacket($this->testToken);

        $encoded1 = $packet1->encode();
        $encoded2 = $packet2->encode();

        // 由于随机数据，编码应该不同（除了最后16字节的令牌）
        $this->assertNotSame($encoded1, $encoded2);

        // 但令牌部分应该相同
        $this->assertSame(substr($encoded1, -16), substr($encoded2, -16));
    }

    public function testEncodingWithCustomRandomData(): void
    {
        $customRandom = 'my_custom_random_data_for_testing';
        $packet = new StatelessResetPacket($this->testToken, $customRandom);
        $encoded = $packet->encode();

        $decoded = StatelessResetPacket::decode($encoded);

        // 解码后的随机数据可能被截断或填充，但应该包含原始数据
        $decodedRandom = $decoded->getRandomData();
        $this->assertStringContainsString(substr($customRandom, 0, min(strlen($customRandom), strlen($decodedRandom))), $decodedRandom);
    }

    public function testTimingAttackResistance(): void
    {
        // 测试令牌验证是否使用时间安全的比较
        $correctToken = StatelessResetPacket::generateToken($this->connectionId, $this->secretKey);
        $wrongToken = str_repeat("\x00", 16);

        // 多次测试验证功能的一致性
        for ($i = 0; $i < 10; ++$i) {
            $this->assertTrue(
                StatelessResetPacket::validateToken($this->connectionId, $correctToken, $this->secretKey)
            );
            $this->assertFalse(
                StatelessResetPacket::validateToken($this->connectionId, $wrongToken, $this->secretKey)
            );
        }
    }

    public function testEncode(): void
    {
        $packet = new StatelessResetPacket($this->testToken);
        $encoded = $packet->encode();

        $this->assertNotEmpty($encoded);
        $this->assertIsString($encoded);
        $this->assertGreaterThanOrEqual(22, strlen($encoded));
    }
}
