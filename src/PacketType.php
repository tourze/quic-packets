<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * QUIC 包类型枚举
 *
 * 根据 RFC 9000 定义的包类型
 */
enum PacketType: int implements Labelable, Itemable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    // 长包头包类型
    case INITIAL = 0x00;
    case ZERO_RTT = 0x01;
    case HANDSHAKE = 0x02;
    case RETRY = 0x03;
    case VERSION_NEGOTIATION = 0xFF;

    // 短包头包类型（1-RTT）
    case ONE_RTT = 0x40;
    
    // 特殊包类型
    case STATELESS_RESET = 0x41;

    /**
     * 判断是否为长包头包
     */
    public function isLongHeader(): bool
    {
        return match ($this) {
            self::INITIAL, self::ZERO_RTT, self::HANDSHAKE, self::RETRY, self::VERSION_NEGOTIATION => true,
            self::ONE_RTT, self::STATELESS_RESET => false,
        };
    }

    /**
     * 判断是否需要包号
     */
    public function hasPacketNumber(): bool
    {
        return match ($this) {
            self::RETRY, self::VERSION_NEGOTIATION, self::STATELESS_RESET => false,
            default => true,
        };
    }

    /**
     * 获取包类型的显示名称
     */
    public function getName(): string
    {
        return match ($this) {
            self::INITIAL => 'Initial',
            self::ZERO_RTT => '0-RTT',
            self::HANDSHAKE => 'Handshake',
            self::RETRY => 'Retry',
            self::VERSION_NEGOTIATION => 'Version Negotiation',
            self::ONE_RTT => '1-RTT',
            self::STATELESS_RESET => 'Stateless Reset',
        };
    }

    /**
     * 获取标签（用于显示）
     */
    public function getLabel(): string
    {
        return $this->getName();
    }
} 