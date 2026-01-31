# 5x04 - Android Virtualization Framework (AVF)

AVF 是 Android 13 引入的新特性，旨在提供比进程沙箱更强的隔离。

与传统"进程隔离"相比，虚拟化隔离的关键收益在于：

- 隔离边界从"同一内核下的 domain"提升到"不同虚拟机上下文"
- 内核被攻破后的横向扩展难度上升（取决于虚拟化层实现）

## 1. 核心组件

### 1.1 pKVM (Protected KVM)

pKVM 是 AVF 的核心 hypervisor 组件，基于 Linux KVM 但做了关键的安全增强。

**EL2 架构设计**

ARM64 架构定义了多个异常级别（Exception Levels），pKVM 运行在 EL2（Hypervisor 级别）：

- EL0：用户态应用
- EL1：操作系统内核（Android/Linux）
- EL2：Hypervisor（pKVM）
- EL3：Secure Monitor

pKVM 的核心设计是将所有敏感的内存管理操作上移到 EL2。这意味着即使 EL1 的 host 内核被完全攻破，攻击者仍然无法直接访问 guest VM 的内存，因为这些映射由 EL2 独占管理。

**Stage-2 页表隔离机制**

传统 KVM 中，host 内核管理 guest 的 stage-2 页表。pKVM 改变了这一设计：

- stage-2 页表完全由 EL2 hypervisor 管理
- host 内核（EL1）无法直接修改 guest 的地址映射
- hypervisor 维护独立的内存区域，对 host 和 guest 均不可见

这种架构确保了即使 host 内核存在漏洞，也无法篡改 guest 的内存视图。

**Memory Sharing 与 Memory Donation**

pKVM 实现了精细的内存状态管理：

| Host 页状态 | Guest Stage-2 状态 | 访问权限 |
|------------|-------------------|---------|
| MAPPABLE | SHARED | Host 和 Guest 均可访问 |
| NOMAP | OWNED | 仅 Guest 可访问 |
| NOMAP | SHARED | Guest 可访问，Host 无法映射 |
| MAPPABLE | NOPAGE | 仅 Host 可访问 |

**Memory Donation（内存捐赠）**：host 将内存页"捐赠"给 guest，之后该页从 host 的地址空间解除映射，仅 guest 和 hypervisor 可访问。这是保护 guest 机密数据的关键机制。

**Memory Sharing（内存共享）**：在特定场景下（如 VirtIO 通信），需要建立共享内存区域。pKVM 通过 hypercall 接口严格控制这些转换，确保每次状态变更都经过 EL2 验证。

### 1.2 Microdroid

Microdroid 是一个精简的 Android 操作系统，运行在隔离的虚拟机中。

### 1.3 概念层组件

- **Hypervisor 模式与隔离内存**：为 guest 提供独立的物理内存视图
- **设备虚拟化/半虚拟化**：尽量减少复杂设备面在 guest 的暴露
- **受控通信通道**：host 与 guest 的 IPC/共享内存需要更严格的边界

## 2. Microdroid 详解

Microdroid 是专为 pVM（Protected VM）设计的最小化 Android 系统。

### 2.1 最小化设计

与完整 Android 系统相比，Microdroid 移除了大量组件：

- 无 SystemServer
- 无 HAL 服务层
- 无 UI 框架
- 无蓝牙/WiFi 等网络栈

保留的核心组件：

- Linux 内核（精简配置）
- init 进程（定制版）
- 基础文件系统
- VirtIO 驱动（用于 host/guest 通信）
- 密钥管理相关服务

这种设计将攻击面降到最低，同时提供足够的运行时支持敏感计算任务。

### 2.2 启动流程与验证

Microdroid 采用完整的验证启动链：

1. **Bootloader 验证**：验证内核和 initramfs 的签名
2. **dm-verity 初始化**：first stage init 读取 `fstab.microdroid`，为每个分区设置 dm-verity
3. **根哈希验证**：使用 Merkle 树验证分区完整性，根哈希由 bootloader 签名保护
4. **运行时完整性**：任何对系统分区的篡改都会导致哈希校验失败

如果任何验证步骤失败，VM 会拒绝启动或进入安全状态。

### 2.3 与主系统的隔离边界

Microdroid 与 host 的交互受到严格限制：

- **通信通道**：仅通过 VirtIO（vsock）进行受控通信
- **文件系统**：无法访问 host 文件系统
- **网络**：默认无网络访问能力
- **设备**：无法访问物理硬件设备

## 3. pKVM 安全认证

### 3.1 SESIP Level 5 认证

2025 年 8 月，pKVM 获得了 SESIP（Security Evaluation Standard for IoT Platforms）Level 5 认证。这是该标准的最高级别，也是全球首个获得此认证的软件安全组件。

### 3.2 认证的意义

SESIP Level 5 认证要求：

- 符合 EN-17927 标准
- 通过 AVA_VAN.5 漏洞分析和渗透测试（ISO 15408 / Common Criteria 最高等级）
- 能够抵御高技能、资源充足、有内部知识的攻击者

认证由 DEKRA 执行，包括：

- 内核级代码审计
- 专用工具开发进行安全分析
- 模拟高级攻击场景的渗透测试

### 3.3 与其他 TEE 认证的对比

传统 TEE（如 TrustZone 实现）的认证情况：

- 许多厂商的 TEE 实现未经独立认证
- 部分仅达到较低的安全保障级别
- 认证范围往往有限（仅覆盖特定组件）

pKVM 的 SESIP Level 5 认证覆盖了整个 hypervisor 层，且基于开源代码，具有更高的透明度和可审计性。

## 4. 安全意义

- **隔离敏感计算**: 将生物识别、密钥处理等逻辑从主系统剥离。
- **防止内核提权**: 即使主系统内核被攻破，攻击者也无法轻易跨越虚拟机边界访问 pKVM 保护的数据。

更细化的威胁模型理解：

- 目标不是"消灭漏洞"，而是把高价值资产放到更难触达的域
- 仍需面对 guest 内部漏洞、host/guest 通信面漏洞、以及虚拟化层本身漏洞

## 5. 安全攻击面分析

### 5.1 Host/Guest 通信接口

VirtIO 是 pVM 与 host 通信的主要机制：

- **vsock**：虚拟套接字，用于 guest 与 host 的数据传输
- **virtio-blk**：块设备虚拟化
- **virtio-console**：控制台访问

每个 VirtIO 设备都是潜在的攻击面。攻击者可能尝试：

- 构造畸形的 VirtIO 描述符
- 触发 host 端驱动的解析漏洞
- 利用共享内存区域的竞态条件

### 5.2 共享内存的安全风险

共享内存区域存在固有风险：

- **TOCTOU（Time-of-check to time-of-use）**：host 检查数据后、使用前，guest 可能修改
- **信息泄露**：共享内存可能残留敏感数据
- **越界访问**：错误的边界检查可能允许访问非共享区域

缓解措施包括：在 host 侧复制数据后再处理、严格验证所有来自 guest 的输入。

### 5.3 CVE-2025-22413 案例分析

CVE-2025-22413 是一个 pKVM 中的 vCPU 状态管理漏洞，于 2025 年 3 月公开。

**漏洞根因**

位于 `hyp-main.c` 中的逻辑错误：内核可能运行一个不处于可运行 PSCI（Power State Coordination Interface）状态的 protected vCPU。

**技术细节**

- vCPU 状态机未正确验证状态转换
- 异常条件处理不当（CWE-703）
- 可能导致本地信息泄露或权限提升

**影响范围**

- 所有启用 pKVM 的 ARM64 Android 设备
- CVSS 评分：4.0（中等）
- 攻击需要本地访问，但无需额外权限

**修复方案**

补丁确保 protected vCPU 在运行前必须处于有效的可运行状态：

- https://android.googlesource.com/kernel/common/+/1a3366f0d3d9b94a8c025d9863edc3b427435c4c
- https://android.googlesource.com/kernel/common/+/add3d68602a0c48ed2d5659f0cf26d869776ab35

此案例说明即使是高度安全的 hypervisor 实现，状态管理逻辑仍是重要的审计目标。

## 6. 典型使用场景

- 高价值密钥与加密操作
- 生物识别相关逻辑
- 机密 AI 推理（Confidential AI）
- 需要处理不可信输入但希望更强隔离的组件

## 7. 研究与排查切入点

### 7.1 确认设备是否启用 pKVM

**检查内核命令行**

```bash
adb shell cat /proc/cmdline | grep kvm-arm
```

输出解读：

- `kvm-arm.mode=protected`：pKVM 已启用（保护模式）
- `kvm-arm.mode=nvhe`：KVM 运行在非保护模式
- `kvm-arm.mode=none`：KVM 已禁用

**检查系统属性**

```bash
adb shell getprop ro.boot.hypervisor.protected_vm.supported
adb shell getprop ro.boot.hypervisor.vm.supported
```

**检查 KVM 设备节点**

```bash
adb shell ls -la /dev/kvm
```

### 7.2 边界面（host/guest 交互）

- guest 暴露的接口集合
- 共享内存/虚拟设备的数据契约
- 权限与身份如何在边界上传递

### 7.3 日志与状态检查

**Host 侧日志**

```bash
adb logcat -b all | grep -i "virtualization\|pkvm\|microdroid"
```

**Kernel 日志**

```bash
adb shell dmesg | grep -i kvm
```

**VM 状态**

```bash
adb shell dumpsys virtualdevice
```

### 7.4 常见配置问题

- **设备不支持**：部分旧设备或非 ARM64 设备不支持 pKVM
- **固件配置**：需要 bootloader 启用 hypervisor 支持
- **SELinux 策略**：VirtualizationService 需要正确的 SELinux 上下文
- **内存不足**：pVM 需要预留足够的内存资源

## 参考

### AOSP 官方文档
- https://source.android.com/docs/core/virtualization — AVF 总览与关键组件术语（pKVM、Microdroid、VirtualizationService 等）
- https://source.android.com/docs/core/virtualization/whyavf — AVF 的需求背景与"为何需要比应用沙盒更强隔离"的动机说明
- https://source.android.com/docs/core/virtualization/microdroid — Microdroid 的定位与运行形态说明
- https://source.android.com/docs/core/virtualization/architecture — AVF 架构详解

### 安全认证
- https://security.googleblog.com/2025/08/Android-pKVM-Certified-SESIP-Level-5.html — pKVM SESIP Level 5 认证公告
- https://www.dekra.com/en/dekra-conducts-the-world-s-first-sesip-level-5-evaluation-for-google-pkvm-hypervisor/ — DEKRA 认证详情

### 技术深入
- https://lwn.net/Articles/996916/ — pKVM EL2 架构与 stage-2 页表管理
- https://source.android.com/docs/security/bulletin/2025-03-01 — Android 安全公告（含 CVE-2025-22413）
