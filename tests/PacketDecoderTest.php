<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\HandshakePacket;
use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketDecoder;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\RetryPacket;
use Tourze\QUIC\Packets\ShortHeaderPacket;
use Tourze\QUIC\Packets\VersionNegotiationPacket;
use Tourze\QUIC\Packets\ZeroRTTPacket;

class PacketDecoderTest extends TestCase
{
    private PacketDecoder $decoder;

    protected function setUp(): void
    {
        $this->decoder = new PacketDecoder();
    }

    public function testDecodeEmptyDataThrowsException(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据不能为空');

        $this->decoder->decode('');
    }

    public function testDecodeLongHeaderPacketInsufficientDataThrowsException(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('长包头数据长度不足');

        // 仅4字节数据，长包头至少需要6字节
        $data = "\xC0\x00\x00\x01";
        $this->decoder->decode($data);
    }

    public function testDecodeVersionNegotiationPacket(): void
    {
        // 版本协商包：首字节 + 版本0x00000000 + DCID长度 + DCID + SCID长度 + SCID + 支持版本列表
        $data = "\xC0" . pack('N', 0x00000000) . "\x08" . 
                str_repeat('A', 8) . "\x08" . str_repeat('B', 8) . 
                pack('N', 0x00000001);

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(VersionNegotiationPacket::class, $packet);
        $this->assertSame(PacketType::VERSION_NEGOTIATION, $packet->getType());
    }

    public function testDecodeInitialPacket(): void
    {
        // Initial包：首字节 0xC0 (类型0) + 版本 + DCID长度 + DCID + SCID长度 + SCID + 令牌长度 + 长度 + 包号 + 载荷
        $data = "\xC0" . pack('N', 0x00000001) . "\x08" . 
                str_repeat('A', 8) . "\x08" . str_repeat('B', 8) . 
                "\x00" . // 令牌长度为0
                pack('n', 10) . // 载荷长度
                "\x01" . // 包号长度1字节
                "\x01" . // 包号1
                str_repeat('X', 8); // 载荷数据

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(InitialPacket::class, $packet);
        $this->assertSame(PacketType::INITIAL, $packet->getType());
    }

    public function testDecodeZeroRTTPacket(): void
    {
        // 0-RTT包：首字节 0xD0 (类型1) + 版本 + DCID长度 + DCID + SCID长度 + SCID + 长度 + 包号 + 载荷
        $data = "\xD0" . pack('N', 0x00000001) . "\x08" . 
                str_repeat('A', 8) . "\x08" . str_repeat('B', 8) . 
                pack('n', 10) . // 载荷长度
                "\x01" . // 包号长度1字节
                "\x01" . // 包号1
                str_repeat('Y', 8); // 载荷数据

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(ZeroRTTPacket::class, $packet);
        $this->assertSame(PacketType::ZERO_RTT, $packet->getType());
    }

    public function testDecodeHandshakePacket(): void
    {
        // Handshake包：首字节 0xE0 (类型2) + 版本 + DCID长度 + DCID + SCID长度 + SCID + 长度 + 包号 + 载荷
        $data = "\xE0" . pack('N', 0x00000001) . "\x08" . 
                str_repeat('A', 8) . "\x08" . str_repeat('B', 8) . 
                pack('n', 10) . // 载荷长度
                "\x01" . // 包号长度1字节
                "\x01" . // 包号1
                str_repeat('Z', 8); // 载荷数据

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(HandshakePacket::class, $packet);
        $this->assertSame(PacketType::HANDSHAKE, $packet->getType());
    }

    public function testDecodeRetryPacket(): void
    {
        // Retry包：首字节 0xF0 (类型3) + 版本 + DCID长度 + DCID + SCID长度 + SCID + 重试令牌 + 重试完整性标签
        $data = "\xF0" . pack('N', 0x00000001) . "\x08" . 
                str_repeat('A', 8) . "\x08" . str_repeat('B', 8) . 
                str_repeat('D', 8) . // 重试令牌
                str_repeat('E', 16); // 重试完整性标签(16字节)

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(RetryPacket::class, $packet);
        $this->assertSame(PacketType::RETRY, $packet->getType());
    }

    public function testDecodeShortHeaderPacket(): void
    {
        // 短包头包：首字节不设置长包头位(0x80)，但需要设置固定位(0x40)
        $data = "\x40" . str_repeat('A', 8) . "\x01" . str_repeat('P', 16);

        $packet = $this->decoder->decode($data);
        $this->assertInstanceOf(ShortHeaderPacket::class, $packet);
        $this->assertSame(PacketType::ONE_RTT, $packet->getType());
    }

    public function testDecodeUnknownLongHeaderPacketTypeThrowsException(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('Fixed Bit 必须为1');

        // 无效的包类型（类型位设置为无效值）
        $data = "\x80" . pack('N', 0x00000001) . "\x08\x08" . str_repeat('A', 16);
        $this->decoder->decode($data);
    }

    public function testTryDecodeReturnsPacketOnSuccess(): void
    {
        $data = "\x40" . str_repeat('A', 8) . "\x01" . str_repeat('P', 16);

        $packet = $this->decoder->tryDecode($data);
        $this->assertInstanceOf(ShortHeaderPacket::class, $packet);
    }

    public function testTryDecodeReturnsNullOnFailure(): void
    {
        $packet = $this->decoder->tryDecode('');
        $this->assertNull($packet);
    }

    public function testDecodeBatch(): void
    {
        $data1 = "\x40" . str_repeat('A', 8) . "\x01" . str_repeat('P', 16);
        $data2 = "\x40" . str_repeat('B', 8) . "\x02" . str_repeat('Q', 16);

        $packets = $this->decoder->decodeBatch([$data1, $data2]);

        $this->assertCount(2, $packets);
        $this->assertInstanceOf(ShortHeaderPacket::class, $packets[0]);
        $this->assertInstanceOf(ShortHeaderPacket::class, $packets[1]);
    }

    public function testDetectPacketTypeEmpty(): void
    {
        $type = $this->decoder->detectPacketType('');
        $this->assertNull($type);
    }

    public function testDetectPacketTypeVersionNegotiation(): void
    {
        $data = "\xC0" . pack('N', 0x00000000) . "\x08\x08";
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::VERSION_NEGOTIATION, $type);
    }

    public function testDetectPacketTypeInitial(): void
    {
        $data = "\xC0" . pack('N', 0x00000001);
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::INITIAL, $type);
    }

    public function testDetectPacketTypeZeroRTT(): void
    {
        $data = "\xD0" . pack('N', 0x00000001);
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::ZERO_RTT, $type);
    }

    public function testDetectPacketTypeHandshake(): void
    {
        $data = "\xE0" . pack('N', 0x00000001);
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::HANDSHAKE, $type);
    }

    public function testDetectPacketTypeRetry(): void
    {
        $data = "\xF0" . pack('N', 0x00000001);
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::RETRY, $type);
    }

    public function testDetectPacketTypeOneRTT(): void
    {
        $data = "\x40" . str_repeat('A', 8);
        $type = $this->decoder->detectPacketType($data);
        $this->assertSame(PacketType::ONE_RTT, $type);
    }

    public function testValidatePacketFormatEmpty(): void
    {
        $isValid = $this->decoder->validatePacketFormat('');
        $this->assertFalse($isValid);
    }

    public function testValidatePacketFormatNoFixedBit(): void
    {
        // 缺少固定位(0x40)
        $data = "\x80" . pack('N', 0x00000001);
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertFalse($isValid);
    }

    public function testValidatePacketFormatLongHeaderInsufficientLength(): void
    {
        // 长包头包但长度不足6字节
        $data = "\xC0\x00\x00";
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertFalse($isValid);
    }

    public function testValidatePacketFormatVersionNegotiationInsufficientLength(): void
    {
        // 版本协商包但长度不足7字节
        $data = "\xC0" . pack('N', 0x00000000) . "\x08";
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertFalse($isValid);
    }

    public function testValidatePacketFormatShortHeaderInsufficientLength(): void
    {
        // 短包头包但长度不足2字节
        $data = "\x40";
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertFalse($isValid);
    }

    public function testValidatePacketFormatValidLongHeader(): void
    {
        $data = "\xC0" . pack('N', 0x00000001) . "\x08\x08";
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertTrue($isValid);
    }

    public function testValidatePacketFormatValidVersionNegotiation(): void
    {
        $data = "\xC0" . pack('N', 0x00000000) . "\x08\x08" . 'A';
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertTrue($isValid);
    }

    public function testValidatePacketFormatValidShortHeader(): void
    {
        $data = "\x40A";
        $isValid = $this->decoder->validatePacketFormat($data);
        $this->assertTrue($isValid);
    }
}
