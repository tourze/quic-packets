<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

/**
 * 无状态重置包
 *
 * 根据 RFC 9000 Section 10.3 定义
 * 用于在无法处理连接时发送重置信号
 */
class StatelessResetPacket extends Packet
{
    public function __construct(
        protected readonly string $statelessResetToken,
        protected readonly string $randomData = '',
    ) {
        if (strlen($statelessResetToken) !== 16) {
            throw new \InvalidArgumentException('无状态重置令牌必须是16字节');
        }

        parent::__construct(
            PacketType::STATELESS_RESET,
            null,
            ''
        );
    }

    /**
     * 获取无状态重置令牌
     */
    public function getStatelessResetToken(): string
    {
        return $this->statelessResetToken;
    }

    /**
     * 获取随机数据
     */
    public function getRandomData(): string
    {
        return $this->randomData;
    }

    /**
     * 编码包
     */
    public function encode(): string
    {
        $packet = '';

        // 第一字节：Header Form (0) + Fixed Bit (1) + Random Bits (6)
        $firstByte = 0x40; // Fixed Bit = 1, Header Form = 0
        $firstByte |= random_int(0, 0x3F); // 6位随机数据
        $packet .= chr($firstByte);

        // 随机数据（至少需要22字节总长度）
        $randomLength = max(21, strlen($this->randomData)); // 至少21字节加上第一字节
        if (strlen($this->randomData) < $randomLength) {
            $packet .= $this->randomData . random_bytes($randomLength - strlen($this->randomData));
        } else {
            $packet .= substr($this->randomData, 0, $randomLength);
        }

        // 无状态重置令牌（最后16字节）
        $packet .= $this->statelessResetToken;

        return $packet;
    }

    /**
     * 解码包
     */
    public static function decode(string $data): static
    {
        if (strlen($data) < 22) {
            throw new \InvalidArgumentException('无状态重置包长度不足（最少22字节）');
        }

        $firstByte = ord($data[0]);

        // 验证 Fixed Bit
        if (($firstByte & 0x40) === 0) {
            throw new \InvalidArgumentException('无状态重置包 Fixed Bit 必须为1');
        }

        // 验证 Header Form（应该为0，表示短包头）
        if (($firstByte & 0x80) !== 0) {
            throw new \InvalidArgumentException('无状态重置包 Header Form 必须为0');
        }

        // 无状态重置令牌是最后16字节
        $statelessResetToken = substr($data, -16);

        // 随机数据是除了第一字节和最后16字节之外的所有数据
        $randomData = substr($data, 1, -16);

        return new static($statelessResetToken, $randomData);
    }

    /**
     * 生成无状态重置令牌
     */
    public static function generateToken(string $connectionId, string $secretKey): string
    {
        // 简化实现：使用 HMAC-SHA256 的前16字节
        // 实际实现应该使用更安全的密钥派生函数
        return substr(hash_hmac('sha256', $connectionId, $secretKey, true), 0, 16);
    }

    /**
     * 验证无状态重置令牌
     */
    public static function validateToken(string $connectionId, string $token, string $secretKey): bool
    {
        $expectedToken = self::generateToken($connectionId, $secretKey);
        return hash_equals($expectedToken, $token);
    }

    /**
     * 创建具有指定最小长度的无状态重置包
     */
    public static function createWithMinLength(string $statelessResetToken, int $minLength = 22): static
    {
        $randomDataLength = max(0, $minLength - 17); // 减去第一字节和16字节令牌
        $randomData = random_bytes($randomDataLength);
        
        return new static($statelessResetToken, $randomData);
    }

    /**
     * 检查数据是否可能是无状态重置包
     * 这是一个启发式检查，因为无状态重置包故意设计得像普通数据
     */
    public static function couldBeStatelessReset(string $data): bool
    {
        if (strlen($data) < 22) {
            return false;
        }

        $firstByte = ord($data[0]);

        // 检查 Fixed Bit
        if (($firstByte & 0x40) === 0) {
            return false;
        }

        // 检查 Header Form（应该为0）
        if (($firstByte & 0x80) !== 0) {
            return false;
        }

        // 其他位是随机的，无法进一步验证
        return true;
    }
} 