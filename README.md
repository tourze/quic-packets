# QUIC Packets

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-packets.svg?style=flat-square)]
(https://packagist.org/packages/tourze/quic-packets)
[![PHP Version](https://img.shields.io/packagist/php-v/tourze/quic-packets.svg?style=flat-square)]
(https://packagist.org/packages/tourze/quic-packets)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/quic-packets.svg?style=flat-square)]
(https://packagist.org/packages/tourze/quic-packets)
[![License](https://img.shields.io/packagist/l/tourze/quic-packets.svg?style=flat-square)](LICENSE)
[![Coverage Status](https://img.shields.io/badge/coverage-95%25-brightgreen.svg?style=flat-square)](#testing)

A comprehensive QUIC packet handling library implementing RFC 9000 specifications for PHP 8.1+.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Advanced Usage](#advanced-usage)
- [Testing](#testing)
- [Architecture](#architecture)
- [Performance](#performance)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Roadmap](#roadmap)
- [References](#references)

## Features

- **RFC 9000 Compliant**: Full support for QUIC packet format specifications
- **Complete Packet Types**: Initial, Handshake, and 1-RTT packets
- **Efficient Encoding/Decoding**: Optimized binary packet serialization
- **Packet Number Management**: Automatic numbering with loss detection
- **Type-Safe Design**: Modern PHP 8.1+ with enums and readonly properties
- **Comprehensive Testing**: 215 tests with 591 assertions across 19 test files

## Requirements

- PHP 8.1 or higher
- No external dependencies for core functionality

## Installation

Install via Composer:

```bash
composer require tourze/quic-packets
```

## Quick Start

### Basic Packet Creation and Encoding

```php
<?php

use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketEncoder;
use Tourze\QUIC\Packets\PacketDecoder;

// Create an Initial packet
$packet = new InitialPacket(
    version: 0x00000001,
    destinationConnectionId: 'destination_id',
    sourceConnectionId: 'source_id_12',
    token: 'auth_token',
    packetNumber: 123,
    payload: 'Hello QUIC'
);

// Encode to binary format
$encoder = new PacketEncoder();
$binaryData = $encoder->encode($packet);

// Decode back to packet object
$decoder = new PacketDecoder();
$decodedPacket = $decoder->decode($binaryData);

echo "Packet type: " . $decodedPacket->getType()->getName();
echo "Payload: " . $decodedPacket->getPayload();
```

### Packet Number Space Management

```php
use Tourze\QUIC\Packets\PacketNumberSpace;
use Tourze\QUIC\Packets\PacketType;

// Create packet number space for Initial packets
$space = new PacketNumberSpace(PacketType::INITIAL);

// Get next packet numbers
$packetNum1 = $space->getNext(); // 0
$packetNum2 = $space->getNext(); // 1

// Record received packets
$space->recordReceived(100);

// Acknowledge sent packets
$space->acknowledge($packetNum1);

// Check for lost packets
$lostPackets = $space->detectLoss();
```

### Handshake Packets

```php
use Tourze\QUIC\Packets\HandshakePacket;

$handshakePacket = new HandshakePacket(
    version: 0x00000001,
    destinationConnectionId: 'dest_conn_id',
    sourceConnectionId: 'src_conn_id_',
    packetNumber: 456,
    payload: 'TLS handshake data'
);

$encoded = $encoder->encode($handshakePacket);
```

### 1-RTT Data Packets

```php
use Tourze\QUIC\Packets\ShortHeaderPacket;

$dataPacket = new ShortHeaderPacket(
    destinationConnectionId: 'conn12345',
    packetNumber: 789,
    payload: 'Application data',
    keyPhase: true
);

$encoded = $encoder->encode($dataPacket);
```

## API Reference

### Core Classes

- **`PacketType`**: Enum defining QUIC packet types (Initial, Handshake, 1-RTT, etc.)
- **`Packet`**: Abstract base class for all packet types
- **`LongHeaderPacket`**: Base class for Initial and Handshake packets
- **`ShortHeaderPacket`**: For 1-RTT encrypted data packets
- **`PacketEncoder`**: Encodes packet objects to binary data
- **`PacketDecoder`**: Decodes binary data to packet objects
- **`PacketNumberSpace`**: Manages packet numbering and acknowledgments

### Supported Packet Types

| Type | Class | Description | Status |
|------|-------|-------------|--------|
| Initial | `InitialPacket` | Connection establishment | ✅ Complete |
| Handshake | `HandshakePacket` | TLS handshake completion | ✅ Complete |
| 1-RTT | `ShortHeaderPacket` | Encrypted data transmission | ✅ Complete |
| 0-RTT | `ZeroRTTPacket` | Early data | ✅ Complete |
| Retry | `RetryPacket` | Stateless retry | ✅ Complete |
| Version Negotiation | `VersionNegotiationPacket` | Version agreement | ✅ Complete |
| Stateless Reset | `StatelessResetPacket` | Connection reset | ✅ Complete |

## Advanced Usage

### Batch Processing

```php
$packets = [
    new InitialPacket(1, 'dest1', 'src1', 'token1', 1, 'data1'),
    new HandshakePacket(1, 'dest2', 'src2', 2, 'data2'),
];

// Batch encode
$encodedPackets = $encoder->encodeBatch($packets);

// Batch decode
$decodedPackets = $decoder->decodeBatch($encodedPackets);
```

### Packet Type Detection

```php
$packetType = $decoder->detectPacketType($binaryData);
if ($packetType === PacketType::INITIAL) {
    // Handle Initial packet
}
```

### Validation

```php
if ($decoder->validatePacketFormat($binaryData)) {
    $packet = $decoder->decode($binaryData);
}
```

## Testing

Run the test suite:

```bash
vendor/bin/phpunit
```

From project root:

```bash
./vendor/bin/phpunit packages/quic-packets/tests
```

## Architecture

The library follows a clean, object-oriented design:

```text
┌─────────────────┐    ┌──────────────────┐
│   PacketType    │    │     Packet       │
│    (enum)       │    │   (abstract)     │
└─────────────────┘    └──────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
         ┌──────────▼─────────┐  ┌──────▼──────┐
         │  LongHeaderPacket  │  │ShortHeader │
         │    (abstract)      │  │   Packet   │
         └────────┬───────────┘  └─────────────┘
                  │
         ┌────────┴────────┐
         │                 │
    ┌────▼─────┐    ┌─────▼──────┐
    │ Initial  │    │ Handshake  │
    │ Packet   │    │  Packet    │
    └──────────┘    └────────────┘
```

## Performance

- **Memory Efficient**: Readonly properties minimize memory usage
- **Fast Encoding**: Optimized binary serialization
- **Type Safety**: Compile-time type checking prevents runtime errors

## Security

This library is designed for QUIC packet handling and follows security best practices:

- **Input Validation**: All packet data is validated during decoding
- **Type Safety**: Strong typing prevents common security vulnerabilities
- **No External Dependencies**: Minimal attack surface for core functionality
- **Memory Safe**: Readonly properties prevent unintended modifications

For security vulnerabilities, please email security@tourze.com instead of using the issue tracker.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/tourze/quic-packets
cd quic-packets
composer install
vendor/bin/phpunit
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Roadmap

- [x] 0-RTT packet support
- [x] Retry packet implementation
- [x] Version negotiation packets
- [x] Stateless reset packets
- [ ] Packet encryption integration
- [ ] Performance optimizations
- [ ] Packet fragmentation support

## References

- [RFC 9000: QUIC Protocol](https://tools.ietf.org/html/rfc9000)
- [QUIC Transport Protocol](https://quicwg.org/)
- [IETF QUIC Working Group](https://datatracker.ietf.org/wg/quic/about/)
