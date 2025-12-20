# Part 2: IPC Mechanisms

在 Android 沙箱体系中，进程间通信（IPC）是打破隔离、实现协作的唯一合法途径。对于安全研究员来说，IPC 接口是应用和系统服务最主要的**攻击面**。

## 1. 为什么 IPC 是核心攻击面？

由于沙箱的存在，攻击者通常无法直接访问敏感数据或硬件。他们必须通过 IPC 向高权限进程（如 `system_server` 或各种 HAL 服务）发送请求。如果这些请求的处理逻辑存在漏洞，攻击者就能实现提权（Privilege Escalation）。

## 2. 专题章节

在本专题中，我们将深入探讨 Android 的各种通信机制，从底层的 Binder 驱动到上层的 Intent 路由：

### [2x00 - Binder 深度解析](./01-binder-deep-dive.md)
- **核心内容**: 驱动层实现（mmap/线程池/对象引用）、UID/PID 注入、混淆代理、Parcel 反序列化。
- **安全案例**: CVE-2019-2215 (Bad Binder UAF)、CVE-2020-0041 (整数溢出)、CVE-2021-0928 (混淆代理)。
- **实战技能**: 接口审计方法、Fuzzing 技术、Frida/eBPF 动态追踪。

### [2x01 - Intent 系统安全](./02-intent-system.md)
- **核心内容**: 显式与隐式 Intent、Intent Filter、PendingIntent、Deep Link、URI 权限授予。
- **安全案例**: CVE-2020-0096 (StrandHogg 2.0 任务栈劫持)、CVE-2019-2208 (Intent 重定向提权)、CVE-2021-0490 (PendingIntent 可变性)、CVE-2020-0213 (Deep Link 参数注入)。
- **实战技能**: Drozer Fuzzing、Intent 重定向检测、Deep Link 参数校验、Frida Intent 监控。

### [2x02 - HIDL 与 AIDL (Treble 架构)](./03-hidl-aidl.md)
- **核心内容**: Project Treble 边界、HAL 进程隔离、binderized vs passthrough、Stable AIDL。
- **安全案例**: CVE-2020-0478 (MediaCodec HAL UAF)、CVE-2019-2213 (Binder UAF in HAL)。
- **实战技能**: HAL 服务枚举、VTS Fuzzing、Frida 动态追踪。

### [2x03 - 其他 IPC 机制](./04-other-ipc.md)
- **核心内容**: Unix Domain Sockets、共享内存 (ashmem/memfd)、System Properties。
- **安全案例**: CVE-2019-2043 (installd Socket 路径遍历)、CVE-2020-0286 (Bluetooth TOCTOU)、厂商调试属性滥用。
- **实战技能**: UDS 权限审计、共享内存 TOCTOU 检测、属性服务监控。

## 参考（AOSP）

- 架构概览（系统服务/原生守护进程/库层级定位）：https://source.android.com/docs/core/architecture
- AIDL 概览（平台 IPC 抽象，含 service/dumpsys 交互入口）：https://source.android.com/docs/core/architecture/aidl
- HIDL（Android 10 起废弃、迁移到 AIDL 的官方口径）：https://source.android.com/docs/core/architecture/hidl
- SELinux（IPC 接口的 allow/connectto 等策略约束背景）：https://source.android.com/docs/security/features/selinux
