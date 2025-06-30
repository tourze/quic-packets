<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\QUIC\Packets\Exception\InvalidPacketDataException;
use Tourze\QUIC\Packets\Exception\InvalidPacketTypeException;

/**
 * Retry 包
 *
 * 根据 RFC 9000 Section 17.2.5 定义
 * 用于服务器要求客户端重试连接建立
 */
class RetryPacket extends LongHeaderPacket
{
    public function __construct(
        int $version,
        string $destinationConnectionId,
        string $sourceConnectionId,
        protected readonly string $retryToken,
        protected readonly string $retryIntegrityTag,
    ) {
        // Retry 包没有包号
        parent::__construct(
            PacketType::RETRY,
            $version,
            $destinationConnectionId,
            $sourceConnectionId,
            null,
            ''
        );
    }

    /**
     * 获取 Retry Token
     */
    public function getRetryToken(): string
    {
        return $this->retryToken;
    }

    /**
     * 获取 Retry Integrity Tag
     */
    public function getRetryIntegrityTag(): string
    {
        return $this->retryIntegrityTag;
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

        // Retry Token
        $packet .= $this->retryToken;

        // Retry Integrity Tag (16 bytes)
        $packet .= $this->retryIntegrityTag;

        return $packet;
    }

    /**
     * 解码包
     */
    public static function decode(string $data): static
    {
        $offset = 0;
        $headerInfo = self::decodeLongHeader($data, $offset);

        if ($headerInfo['typeValue'] !== PacketType::RETRY->value) {
            throw new InvalidPacketTypeException('不是 Retry 包');
        }

        // Retry 包的剩余部分是 Retry Token + Retry Integrity Tag (16 bytes)
        $remainingLength = strlen($data) - $offset;
        if ($remainingLength < 16) {
            throw new InvalidPacketDataException('Retry 包长度不足，缺少 Integrity Tag');
        }

        // Retry Token 是除了最后16字节（Integrity Tag）之外的所有数据
        $retryTokenLength = $remainingLength - 16;
        $retryToken = substr($data, $offset, $retryTokenLength);
        $offset += $retryTokenLength;

        // Retry Integrity Tag (16 bytes)
        $retryIntegrityTag = substr($data, $offset, 16);

        return new static(
            $headerInfo['version'],
            $headerInfo['destinationConnectionId'],
            $headerInfo['sourceConnectionId'],
            $retryToken,
            $retryIntegrityTag
        );
    }

    /**
     * 获取类型特定位
     * Retry 包的 Type-Specific Bits 是未使用的，设为0
     */
    protected function getTypeSpecificBits(): int
    {
        return 0x00;
    }

    /**
     * 生成 Retry Integrity Tag（简化实现）
     */
    public static function generateIntegrityTag(
        string $originalDestinationConnectionId,
        string $retryPacketWithoutTag
    ): string {
        // 这是一个简化实现，实际应该使用 AES-128-GCM
        // 实际实现需要使用 Original Destination Connection ID 和包内容生成
        return hash('sha256', $originalDestinationConnectionId . $retryPacketWithoutTag, true);
    }

    /**
     * 验证 Retry Integrity Tag（简化实现）
     */
    public function validateIntegrityTag(string $originalDestinationConnectionId): bool
    {
        // 构造不包含 Integrity Tag 的包数据
        $packetWithoutTag = $this->encodeLongHeader() . $this->retryToken;
        
        // 生成期望的 Integrity Tag
        $expectedTag = self::generateIntegrityTag($originalDestinationConnectionId, $packetWithoutTag);
        
        // 比较（实际实现中应该使用时间安全的比较）
        return hash_equals($expectedTag, $this->retryIntegrityTag);
    }
} 