<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

/**
 * Handshake 包
 *
 * 根据 RFC 9000 Section 17.2.4 定义
 */
class HandshakePacket extends LongHeaderPacket
{
    public function __construct(
        int $version,
        string $destinationConnectionId,
        string $sourceConnectionId,
        int $packetNumber,
        string $payload = '',
    ) {
        parent::__construct(
            PacketType::HANDSHAKE,
            $version,
            $destinationConnectionId,
            $sourceConnectionId,
            $packetNumber,
            $payload
        );
    }

    /**
     * 重新暴露父类方法，便于测试
     */
    public function getVersion(): int
    {
        return parent::getVersion();
    }

    public function getDestinationConnectionId(): string
    {
        return parent::getDestinationConnectionId();
    }

    public function getSourceConnectionId(): string
    {
        return parent::getSourceConnectionId();
    }

    /**
     * 编码包
     */
    public function encode(): string
    {
        $packet = $this->encodeLongHeader();

        // Length (变长整数) - 包号 + 负载的长度
        $packetNumberLength = $this->calculatePacketNumberLength($this->packetNumber);
        $payloadLength = $packetNumberLength + strlen($this->payload);
        $packet .= self::encodeVariableInt($payloadLength);

        // Packet Number
        $packet .= self::encodePacketNumber($this->packetNumber, $packetNumberLength);

        // Payload
        $packet .= $this->payload;

        return $packet;
    }

    /**
     * 解码包
     */
    public static function decode(string $data): static
    {
        $offset = 0;
        $headerInfo = self::decodeLongHeader($data, $offset);

        if ($headerInfo['typeValue'] !== PacketType::HANDSHAKE->value) {
            throw new \InvalidArgumentException('不是 Handshake 包');
        }

        // 解码 Length
        [$length, $bytesRead] = self::decodeVariableInt($data, $offset);
        $offset += $bytesRead;

        // 解码包号长度（从 Type-Specific Bits 获取）
        $packetNumberLength = ($headerInfo['typeSpecificBits'] & 0x03) + 1;

        // 解码包号
        if (strlen($data) < $offset + $packetNumberLength) {
            throw new \InvalidArgumentException('数据长度不足以解码包号');
        }
        $packetNumber = self::decodePacketNumber($data, $offset, $packetNumberLength);
        $offset += $packetNumberLength;

        // 解码负载
        $payloadLength = $length - $packetNumberLength;
        if (strlen($data) < $offset + $payloadLength) {
            throw new \InvalidArgumentException('数据长度不足以解码负载');
        }
        $payload = substr($data, $offset, $payloadLength);

        return new self(
            $headerInfo['version'],
            $headerInfo['destinationConnectionId'],
            $headerInfo['sourceConnectionId'],
            $packetNumber,
            $payload
        );
    }

    /**
     * 获取类型特定位
     */
    protected function getTypeSpecificBits(): int
    {
        // 包号长度编码在低2位
        $packetNumberLength = $this->calculatePacketNumberLength($this->packetNumber);
        return ($packetNumberLength - 1) & 0x03;
    }

    /**
     * 计算包号编码所需的字节数
     */
    private function calculatePacketNumberLength(int $packetNumber): int
    {
        if ($packetNumber < 256) {
            return 1;
        } elseif ($packetNumber < 65536) {
            return 2;
        } elseif ($packetNumber < 16777216) {
            return 3;
        } else {
            return 4;
        }
    }
} 