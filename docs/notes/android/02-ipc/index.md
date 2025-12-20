# Part 2: IPC Mechanisms

在 Android 沙箱体系中，进程间通信（IPC）是打破隔离、实现协作的唯一合法途径。对于安全研究员来说，IPC 接口是应用和系统服务最主要的**攻击面**。

## 1. 为什么 IPC 是核心攻击面？

由于沙箱的存在，攻击者通常无法直接访问敏感数据或硬件。他们必须通过 IPC 向高权限进程（如 `system_server` 或各种 HAL 服务）发送请求。如果这些请求的处理逻辑存在漏洞，攻击者就能实现提权（Privilege Escalation）。

## 参考（AOSP）

- 架构概览（系统服务/原生守护进程/库层级定位）：https://source.android.com/docs/core/architecture
- AIDL 概览（平台 IPC 抽象，含 service/dumpsys 交互入口）：https://source.android.com/docs/core/architecture/aidl
- HIDL（Android 10 起废弃、迁移到 AIDL 的官方口径）：https://source.android.com/docs/core/architecture/hidl
- SELinux（IPC 接口的 allow/connectto 等策略约束背景）：https://source.android.com/docs/security/features/selinux
