# QUIC Packets

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-packets.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-packets)
[![PHP Version](https://img.shields.io/packagist/php-v/tourze/quic-packets.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-packets)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/quic-packets.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-packets)

为 PHP 8.1+ 实现 RFC 9000 规范的综合性 QUIC 包处理库。

## 特性

- **RFC 9000 兼容**: 全面支持 QUIC 包格式规范
- **完整的包类型**: Initial、Handshake 和 1-RTT 包
- **高效编解码**: 优化的二进制包序列化
- **包号管理**: 自动编号和丢失检测
- **类型安全设计**: 使用 PHP 8.1+ 枚举和只读属性
- **全面测试**: 21 个测试用例，87 个断言

## 系统要求

- PHP 8.1 或更高版本
- 核心功能无外部依赖

## 安装

通过 Composer 安装：

```bash
composer require tourze/quic-packets
```

## 快速开始

### 基本包创建和编码

```php
<?php

use Tourze\QUIC\Packets\InitialPacket;
use Tourze\QUIC\Packets\PacketEncoder;
use Tourze\QUIC\Packets\PacketDecoder;

// 创建 Initial 包
$packet = new InitialPacket(
    version: 0x00000001,
    destinationConnectionId: 'destination_id',
    sourceConnectionId: 'source_id_12',
    token: 'auth_token',
    packetNumber: 123,
    payload: 'Hello QUIC'
);

// 编码为二进制格式
$encoder = new PacketEncoder();
$binaryData = $encoder->encode($packet);

// 解码回包对象
$decoder = new PacketDecoder();
$decodedPacket = $decoder->decode($binaryData);

echo "包类型: " . $decodedPacket->getType()->getName();
echo "负载: " . $decodedPacket->getPayload();
```

### 包号空间管理

```php
use Tourze\QUIC\Packets\PacketNumberSpace;
use Tourze\QUIC\Packets\PacketType;

// 为 Initial 包创建包号空间
$space = new PacketNumberSpace(PacketType::INITIAL);

// 获取下一个包号
$packetNum1 = $space->getNext(); // 0
$packetNum2 = $space->getNext(); // 1

// 记录接收的包
$space->recordReceived(100);

// 确认已发送的包
$space->acknowledge($packetNum1);

// 检查丢失的包
$lostPackets = $space->detectLoss();
```

### Handshake 包

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

### 1-RTT 数据包

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

## API 参考

### 核心类

- **`PacketType`**: 定义 QUIC 包类型的枚举（Initial、Handshake、1-RTT 等）
- **`Packet`**: 所有包类型的抽象基类
- **`LongHeaderPacket`**: Initial 和 Handshake 包的基类
- **`ShortHeaderPacket`**: 1-RTT 加密数据包
- **`PacketEncoder`**: 将包对象编码为二进制数据
- **`PacketDecoder`**: 将二进制数据解码为包对象
- **`PacketNumberSpace`**: 管理包编号和确认

### 支持的包类型

| 类型 | 类名 | 描述 | 状态 |
|------|------|------|------|
| Initial | `InitialPacket` | 连接建立 | ✅ 完成 |
| Handshake | `HandshakePacket` | TLS 握手完成 | ✅ 完成 |
| 1-RTT | `ShortHeaderPacket` | 加密数据传输 | ✅ 完成 |
| 0-RTT | - | 早期数据 | 🚧 计划中 |
| Retry | - | 无状态重试 | 🚧 计划中 |
| Version Negotiation | - | 版本协商 | 🚧 计划中 |

## 高级用法

### 批量处理

```php
$packets = [
    new InitialPacket(1, 'dest1', 'src1', 'token1', 1, 'data1'),
    new HandshakePacket(1, 'dest2', 'src2', 2, 'data2'),
];

// 批量编码
$encodedPackets = $encoder->encodeBatch($packets);

// 批量解码
$decodedPackets = $decoder->decodeBatch($encodedPackets);
```

### 包类型检测

```php
$packetType = $decoder->detectPacketType($binaryData);
if ($packetType === PacketType::INITIAL) {
    // 处理 Initial 包
}
```

### 验证

```php
if ($decoder->validatePacketFormat($binaryData)) {
    $packet = $decoder->decode($binaryData);
}
```

## 测试

运行测试套件：

```bash
vendor/bin/phpunit
```

从项目根目录运行：

```bash
./vendor/bin/phpunit packages/quic-packets/tests
```

## 架构

该库遵循清晰的面向对象设计：

```
┌─────────────────┐    ┌──────────────────┐
│   PacketType    │    │     Packet       │
│    (枚举)       │    │    (抽象)        │
└─────────────────┘    └──────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
         ┌──────────▼─────────┐  ┌──────▼──────┐
         │  LongHeaderPacket  │  │ShortHeader │
         │     (抽象)         │  │   Packet   │
         └────────┬───────────┘  └─────────────┘
                  │
         ┌────────┴────────┐
         │                 │
    ┌────▼─────┐    ┌─────▼──────┐
    │ Initial  │    │ Handshake  │
    │ Packet   │    │  Packet    │
    └──────────┘    └────────────┘
```

## 性能

- **内存高效**: 只读属性最小化内存使用
- **快速编码**: 优化的二进制序列化
- **类型安全**: 编译时类型检查防止运行时错误

## 贡献

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

### 开发环境设置

```bash
git clone https://github.com/tourze/quic-packets
cd quic-packets
composer install
vendor/bin/phpunit
```

## 许可证

MIT 许可证。详情请参阅 [License File](LICENSE)。

## 路线图

- [ ] 0-RTT 包支持
- [ ] Retry 包实现
- [ ] 版本协商包
- [ ] 包加密集成
- [ ] 性能优化
- [ ] 包分片支持

## 参考资料

- [RFC 9000: QUIC 协议](https://tools.ietf.org/html/rfc9000)
- [QUIC 传输协议](https://quicwg.org/)
- [IETF QUIC 工作组](https://datatracker.ietf.org/wg/quic/about/)
