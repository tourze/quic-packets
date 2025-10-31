<?php

declare(strict_types=1);

namespace Tourze\QUIC\Packets\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\QUIC\Packets\PacketType;

/**
 * @internal
 */
#[CoversClass(PacketType::class)]
final class PacketTypeTest extends AbstractEnumTestCase
{
    public function testAllPacketTypeValues(): void
    {
        $this->assertSame(0x00, PacketType::INITIAL->value);
        $this->assertSame(0x01, PacketType::ZERO_RTT->value);
        $this->assertSame(0x02, PacketType::HANDSHAKE->value);
        $this->assertSame(0x03, PacketType::RETRY->value);
        $this->assertSame(0xFF, PacketType::VERSION_NEGOTIATION->value);
        $this->assertSame(0x40, PacketType::ONE_RTT->value);
        $this->assertSame(0x41, PacketType::STATELESS_RESET->value);
    }

    public function testIsLongHeaderForLongHeaderPackets(): void
    {
        $longHeaderTypes = [
            PacketType::INITIAL,
            PacketType::ZERO_RTT,
            PacketType::HANDSHAKE,
            PacketType::RETRY,
            PacketType::VERSION_NEGOTIATION,
        ];

        foreach ($longHeaderTypes as $type) {
            $this->assertTrue($type->isLongHeader(), "Type {$type->name} should be long header");
        }
    }

    public function testIsLongHeaderForShortHeaderPackets(): void
    {
        $shortHeaderTypes = [
            PacketType::ONE_RTT,
            PacketType::STATELESS_RESET,
        ];

        foreach ($shortHeaderTypes as $type) {
            $this->assertFalse($type->isLongHeader(), "Type {$type->name} should not be long header");
        }
    }

    public function testHasPacketNumberForPacketsWithPacketNumber(): void
    {
        $typesWithPacketNumber = [
            PacketType::INITIAL,
            PacketType::ZERO_RTT,
            PacketType::HANDSHAKE,
            PacketType::ONE_RTT,
        ];

        foreach ($typesWithPacketNumber as $type) {
            $this->assertTrue($type->hasPacketNumber(), "Type {$type->name} should have packet number");
        }
    }

    public function testHasPacketNumberForPacketsWithoutPacketNumber(): void
    {
        $typesWithoutPacketNumber = [
            PacketType::RETRY,
            PacketType::VERSION_NEGOTIATION,
            PacketType::STATELESS_RESET,
        ];

        foreach ($typesWithoutPacketNumber as $type) {
            $this->assertFalse($type->hasPacketNumber(), "Type {$type->name} should not have packet number");
        }
    }

    public function testGetName(): void
    {
        $this->assertSame('Initial', PacketType::INITIAL->getName());
        $this->assertSame('0-RTT', PacketType::ZERO_RTT->getName());
        $this->assertSame('Handshake', PacketType::HANDSHAKE->getName());
        $this->assertSame('Retry', PacketType::RETRY->getName());
        $this->assertSame('Version Negotiation', PacketType::VERSION_NEGOTIATION->getName());
        $this->assertSame('1-RTT', PacketType::ONE_RTT->getName());
        $this->assertSame('Stateless Reset', PacketType::STATELESS_RESET->getName());
    }

    public function testGetLabel(): void
    {
        $this->assertSame('Initial', PacketType::INITIAL->getLabel());
        $this->assertSame('0-RTT', PacketType::ZERO_RTT->getLabel());
        $this->assertSame('Handshake', PacketType::HANDSHAKE->getLabel());
        $this->assertSame('Retry', PacketType::RETRY->getLabel());
        $this->assertSame('Version Negotiation', PacketType::VERSION_NEGOTIATION->getLabel());
        $this->assertSame('1-RTT', PacketType::ONE_RTT->getLabel());
        $this->assertSame('Stateless Reset', PacketType::STATELESS_RESET->getLabel());
    }

    public function testGetLabelSameAsGetName(): void
    {
        $allTypes = [
            PacketType::INITIAL,
            PacketType::ZERO_RTT,
            PacketType::HANDSHAKE,
            PacketType::RETRY,
            PacketType::VERSION_NEGOTIATION,
            PacketType::ONE_RTT,
            PacketType::STATELESS_RESET,
        ];

        foreach ($allTypes as $type) {
            $this->assertSame($type->getName(), $type->getLabel());
        }
    }

    public function testAllCasesAreCovered(): void
    {
        $allCases = PacketType::cases();
        $this->assertCount(7, $allCases);

        $expectedCases = [
            PacketType::INITIAL,
            PacketType::ZERO_RTT,
            PacketType::HANDSHAKE,
            PacketType::RETRY,
            PacketType::VERSION_NEGOTIATION,
            PacketType::ONE_RTT,
            PacketType::STATELESS_RESET,
        ];

        foreach ($expectedCases as $expectedCase) {
            $this->assertContains($expectedCase, $allCases);
        }
    }

    public function testPacketTypeImplementsExpectedInterfaces(): void
    {
        $this->assertInstanceOf(Labelable::class, PacketType::INITIAL);
        $this->assertInstanceOf(Itemable::class, PacketType::INITIAL);
        $this->assertInstanceOf(Selectable::class, PacketType::INITIAL);
    }

    public function testToArray(): void
    {
        $array = PacketType::INITIAL->toArray();
        $this->assertIsArray($array);
        $this->assertCount(2, $array);
        $this->assertArrayHasKey('value', $array);
        $this->assertArrayHasKey('label', $array);
        $this->assertSame(0, $array['value']);
        $this->assertSame('Initial', $array['label']);

        $array = PacketType::VERSION_NEGOTIATION->toArray();
        $this->assertSame(255, $array['value']);
        $this->assertSame('Version Negotiation', $array['label']);
    }
}
