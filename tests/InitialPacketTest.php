<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketType;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;
use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;

class InitialPacketTest extends TestCase
{
    public function testConstruct(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest_conn_id',
            sourceConnectionId: 'src_conn_id_',
            token: 'test_token_123',
            packetNumber: 123,
            payload: 'initial data'
        );

        $this->assertSame(PacketType::INITIAL, $packet->getType());
        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_conn_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_conn_id_', $packet->getSourceConnectionId());
        $this->assertSame('test_token_123', $packet->getToken());
        $this->assertSame(123, $packet->getPacketNumber());
        $this->assertSame('initial data', $packet->getPayload());
    }

    public function testConstructWithEmptyToken(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: '',
            packetNumber: 1,
            payload: 'test'
        );

        $this->assertSame('', $packet->getToken());
        $this->assertSame(PacketType::INITIAL, $packet->getType());
    }

    public function testGetToken(): void
    {
        $token = 'my_special_token_12345';
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: $token,
            packetNumber: 1
        );

        $this->assertSame($token, $packet->getToken());
    }

    public function testEncode(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            token: 'encode_token',
            packetNumber: 456,
            payload: 'Hello Initial!'
        );

        $encoded = $packet->encode();
        $this->assertNotEmpty($encoded);
    }

    public function testDecode(): void
    {
        $originalPacket = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'test_dest_12',
            sourceConnectionId: 'test_source_',
            token: 'decode_token_test',
            packetNumber: 456,
            payload: 'Hello Initial!'
        );

        // 编码
        $encoded = $originalPacket->encode();

        // 解码
        $decodedPacket = InitialPacket::decode($encoded);

        // 验证
        $this->assertSame($originalPacket->getType(), $decodedPacket->getType());
        $this->assertSame($originalPacket->getVersion(), $decodedPacket->getVersion());
        $this->assertSame($originalPacket->getDestinationConnectionId(), $decodedPacket->getDestinationConnectionId());
        $this->assertSame($originalPacket->getSourceConnectionId(), $decodedPacket->getSourceConnectionId());
        $this->assertSame($originalPacket->getToken(), $decodedPacket->getToken());
        $this->assertSame($originalPacket->getPacketNumber(), $decodedPacket->getPacketNumber());
        $this->assertSame($originalPacket->getPayload(), $decodedPacket->getPayload());
    }

    public function testGetMethods(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest_id',
            sourceConnectionId: 'src_id',
            token: 'test_token',
            packetNumber: 789,
            payload: 'test payload'
        );

        $this->assertSame(0x00000001, $packet->getVersion());
        $this->assertSame('dest_id', $packet->getDestinationConnectionId());
        $this->assertSame('src_id', $packet->getSourceConnectionId());
        $this->assertSame('test_token', $packet->getToken());
        $this->assertSame(789, $packet->getPacketNumber());
        $this->assertSame('test payload', $packet->getPayload());
        $this->assertSame(PacketType::INITIAL, $packet->getType());
    }

    public function testInitialPacketWithDifferentPacketNumberLengths(): void
    {
        $testCases = [
            ['packetNumber' => 100, 'expectedLength' => 1],
            ['packetNumber' => 1000, 'expectedLength' => 2], 
            ['packetNumber' => 100000, 'expectedLength' => 3],
            ['packetNumber' => 10000000, 'expectedLength' => 4],
        ];

        foreach ($testCases as $case) {
            $packet = new InitialPacket(
                version: 0x00000001,
                destinationConnectionId: 'dest',
                sourceConnectionId: 'src',
                token: 'test_token',
                packetNumber: $case['packetNumber'],
                payload: 'test'
            );

            $encoded = $packet->encode();
            $decoded = InitialPacket::decode($encoded);

            $this->assertSame($case['packetNumber'], $decoded->getPacketNumber());
            $this->assertSame('test_token', $decoded->getToken());
        }
    }

    public function testInitialPacketWithEmptyPayload(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: 'empty_payload_token',
            packetNumber: 1,
            payload: ''
        );

        $encoded = $packet->encode();
        $decoded = InitialPacket::decode($encoded);

        $this->assertSame('', $decoded->getPayload());
        $this->assertSame('empty_payload_token', $decoded->getToken());
        $this->assertSame(PacketType::INITIAL, $decoded->getType());
    }

    public function testInitialPacketWithLongToken(): void
    {
        $longToken = str_repeat('token_', 50); // 300 chars
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: $longToken,
            packetNumber: 1,
            payload: 'test'
        );

        $encoded = $packet->encode();
        $decoded = InitialPacket::decode($encoded);

        $this->assertSame($longToken, $decoded->getToken());
        $this->assertSame('test', $decoded->getPayload());
    }

    public function testDecodeInvalidInitialPacket(): void
    {
        $this->expectException(InvalidPacketTypeException::class);
        $this->expectExceptionMessage('不是 Initial 包');

        // 创建一个错误包类型的数据，然后尝试用 InitialPacket 解码
        $invalidData = "\xe0\x00\x00\x00\x01\x04dest\x04src_\x05\x01hello";
        InitialPacket::decode($invalidData);
    }

    public function testDecodeInsufficientDataForToken(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码令牌');

        // 数据长度不足以解码令牌
        $invalidData = "\xc0\x00\x00\x00\x01\x04dest\x04src_\x05";
        InitialPacket::decode($invalidData);
    }

    public function testDecodeInsufficientDataForPacketNumber(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码包号');

        // 数据长度不足以解码包号
        $invalidData = "\xc0\x00\x00\x00\x01\x04dest\x04src_\x00\x05";
        InitialPacket::decode($invalidData);
    }

    public function testDecodeInsufficientDataForPayload(): void
    {
        $this->expectException(InvalidPacketDataException::class);
        $this->expectExceptionMessage('数据长度不足以解码负载');

        // 数据长度不足以解码负载
        $invalidData = "\xc0\x00\x00\x00\x01\x04dest\x04src_\x00\x05\x01";
        InitialPacket::decode($invalidData);
    }

    public function testEncodeDecodeWithLargePayload(): void
    {
        $largePayload = str_repeat('A', 1024);
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: 'large_payload_token',
            packetNumber: 12345,
            payload: $largePayload
        );

        $encoded = $packet->encode();
        $decoded = InitialPacket::decode($encoded);

        $this->assertSame($largePayload, $decoded->getPayload());
        $this->assertSame('large_payload_token', $decoded->getToken());
        $this->assertSame(12345, $decoded->getPacketNumber());
    }

    public function testConstructWithDefaultPayload(): void
    {
        $packet = new InitialPacket(
            version: 0x00000001,
            destinationConnectionId: 'dest',
            sourceConnectionId: 'src',
            token: 'default_payload_token',
            packetNumber: 1
        );

        $this->assertSame('', $packet->getPayload());
        $this->assertSame('default_payload_token', $packet->getToken());
        $this->assertSame(PacketType::INITIAL, $packet->getType());
    }

    public function testTokenVariableLengthEncoding(): void
    {
        $testCases = [
            ['token' => '', 'description' => 'empty token'],
            ['token' => 'a', 'description' => 'single char token'],
            ['token' => str_repeat('x', 63), 'description' => '63 byte token'],
            ['token' => str_repeat('y', 64), 'description' => '64 byte token'],
            ['token' => str_repeat('z', 128), 'description' => '128 byte token'],
        ];

        foreach ($testCases as $case) {
            $packet = new InitialPacket(
                version: 0x00000001,
                destinationConnectionId: 'dest',
                sourceConnectionId: 'src',
                token: $case['token'],
                packetNumber: 1,
                payload: 'test'
            );

            $encoded = $packet->encode();
            $decoded = InitialPacket::decode($encoded);

            $this->assertSame($case['token'], $decoded->getToken(), "Failed for: {$case['description']}");
        }
    }
}
