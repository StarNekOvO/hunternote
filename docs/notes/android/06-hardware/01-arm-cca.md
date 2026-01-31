# 6x01 - ARM CCA (Confidential Compute Architecture)

ARM CCA 是 ARMv9 引入的机密计算架构，核心目标是在不假设更高权限软件层完全可信的前提下提供更强的隔离。

CCA 的核心变化是：在传统的 REE/TEE/Hypervisor 模型之外，引入一种更强的隔离域，使得即使是更高权限的软件层也无法直接窥视某些隔离域内的数据。

## 1. 架构概述

### 1.1 从 TrustZone 到 CCA

**传统 TrustZone 模型**：
```
┌─────────────────────────────────────────────────────┐
│                    Normal World                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   App       │  │   App       │  │   App       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│  ┌─────────────────────────────────────────────────┐│
│  │              Linux Kernel / Hypervisor          ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
                         │
                    SMC (切换)
                         │
┌─────────────────────────────────────────────────────┐
│                    Secure World                      │
│  ┌─────────────┐  ┌─────────────┐                   │
│  │  TA (DRM)   │  │  TA (Pay)   │                   │
│  └─────────────┘  └─────────────┘                   │
│  ┌─────────────────────────────────────────────────┐│
│  │              Secure OS (OP-TEE/QSEE)            ││
│  └─────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────┐│
│  │              Secure Monitor (EL3)               ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘

问题：Hypervisor/Host 可以读取 Guest 的所有内存
```

**ARM CCA 模型 (ARMv9)**：
```
┌─────────────────────────────────────────────────────────────────┐
│ Normal World          │ Realm World           │ Secure World    │
│                       │                       │                 │
│ ┌─────┐ ┌─────┐      │ ┌─────────────────┐   │ ┌─────┐         │
│ │ VM  │ │ VM  │      │ │   Realm VM      │   │ │ TA  │         │
│ │Guest│ │Guest│      │ │ (机密计算)       │   │ │     │         │
│ └──┬──┘ └──┬──┘      │ └────────┬────────┘   │ └──┬──┘         │
│    │       │         │          │            │    │             │
│ ┌──▼───────▼──┐      │ ┌────────▼────────┐   │ ┌──▼──┐         │
│ │ Host/pKVM   │      │ │ Realm Manager   │   │ │S-EL1│         │
│ │ (不可读Realm)│      │ │ (RMM)           │   │ │     │         │
│ └──────┬──────┘      │ └────────┬────────┘   │ └──┬──┘         │
└────────┼─────────────┴──────────┼────────────┴────┼─────────────┘
         │                        │                  │
         └────────────────────────┼──────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │      Root World (EL3)     │
                    │   Monitor + Granule Mgmt  │
                    └───────────────────────────┘
```

### 1.2 四个安全世界

| 世界 | 异常级别 | 用途 | 谁可访问 |
|------|----------|------|----------|
| Normal | NS-EL0/1/2 | 普通 OS、应用 | 所有高级别 |
| Secure | S-EL0/1/2 | TEE、可信应用 | Secure Monitor |
| Realm | R-EL0/1/2 | 机密 VM | 仅 Realm 自身 |
| Root | EL3 | Monitor、RME 管理 | 硬件强制 |

## 2. Realm Management Extension (RME)

### 2.1 核心概念

**Granule (颗粒)**：
```c
// 内存管理的基本单位，通常是 4KB 页面
// 每个 Granule 有一个安全状态标签

enum granule_state {
    GRANULE_STATE_NS,      // Normal World
    GRANULE_STATE_SECURE,  // Secure World  
    GRANULE_STATE_REALM,   // Realm World
    GRANULE_STATE_ROOT     // Root World (EL3)
};

// 状态转换必须通过 RMM 和硬件验证
// Host 无法直接将 Realm 内存映射到自己的地址空间
```

**Granule Protection Check (GPC)**：
```
硬件级内存访问检查：

1. CPU 发起内存访问
2. MMU 完成地址翻译
3. GPC 检查：访问者的安全状态 vs 内存的安全状态
4. 不匹配 → 硬件异常

示例：
- Host (NS-EL2) 访问 Realm 内存 → GPC 拒绝
- Realm (R-EL1) 访问 Realm 内存 → GPC 允许
```

### 2.2 Realm Management Monitor (RMM)

RMM 是运行在 R-EL2 的固件，负责管理 Realm：

```c
// RMM 主要功能

// 1. Realm 创建与销毁
RMI_REALM_CREATE     // 创建新 Realm
RMI_REALM_DESTROY    // 销毁 Realm
RMI_REALM_ACTIVATE   // 激活 Realm

// 2. 内存管理
RMI_DATA_CREATE      // 创建 Realm 数据页
RMI_DATA_DESTROY     // 销毁数据页
RMI_GRANULE_DELEGATE // 将 NS 内存委托给 Realm

// 3. vCPU 管理
RMI_REC_CREATE       // 创建 Realm Execution Context
RMI_REC_ENTER        // 进入 Realm 执行
RMI_REC_EXIT         // 退出 Realm

// 4. 远程证明
RMI_REALM_CONFIG     // 配置 Realm 测量
RMI_ATTESTATION_TOKEN_INIT   // 初始化证明
RMI_ATTESTATION_TOKEN_CONTINUE // 继续证明流程
```

### 2.3 内存委托流程

```
Normal World 内存 → Realm 内存的转换过程：

1. Host (pKVM) 调用 RMI_GRANULE_DELEGATE
   ┌─────────────────────────────────────────┐
   │ Host: "我要把这页内存给 Realm 用"        │
   │ 参数: 物理地址, 目标 Realm ID            │
   └─────────────────────────────────────────┘
                    │
                    ▼
2. RMM 验证请求
   ┌─────────────────────────────────────────┐
   │ - 检查内存当前状态 (必须是 NS)            │
   │ - 检查内存未被其他实体使用                 │
   │ - 记录新的所有者                          │
   └─────────────────────────────────────────┘
                    │
                    ▼
3. 硬件更新 Granule 状态
   ┌─────────────────────────────────────────┐
   │ GPT (Granule Protection Table) 更新:     │
   │ 该页面状态: NS → REALM                   │
   │ Host 后续访问将触发 GPC 异常             │
   └─────────────────────────────────────────┘
                    │
                    ▼
4. Realm 可以使用该内存
```

## 3. 远程证明 (Attestation)

### 3.1 证明架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Relying Party                             │
│                  (验证方/服务提供商)                          │
└──────────────────────────┬──────────────────────────────────┘
                           │ 4. 验证 Token
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Verifier Service                          │
│                   (证明验证服务)                              │
└──────────────────────────┬──────────────────────────────────┘
                           │ 3. 发送 Attestation Token
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      Realm                                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 2. 请求证明 Token                                        ││
│  │    - 包含 Realm 测量值                                   ││
│  │    - 包含 Platform 测量值                                ││
│  │    - 由 RMM 和硬件签名                                   ││
│  └─────────────────────────────────────────────────────────┘│
│                           │                                  │
│  ┌────────────────────────▼────────────────────────────────┐│
│  │ 1. 启动时测量                                            ││
│  │    - 初始内存内容 hash                                   ││
│  │    - 配置参数                                            ││
│  │    - 扩展测量 (可选)                                     ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Attestation Token 结构

```c
// CCA Attestation Token (基于 EAT/CWT 格式)
struct cca_attestation_token {
    // Platform 证明
    struct {
        uint8_t implementation_id[32];  // 实现标识
        uint8_t platform_hash[64];      // 平台测量
        uint8_t platform_config[64];    // 平台配置
        uint8_t security_lifecycle;     // 安全生命周期
        // ...
    } platform_token;
    
    // Realm 证明
    struct {
        uint8_t realm_id[64];           // Realm 标识
        uint8_t rpv[64];                // Realm Personalization Value
        uint8_t rim[64];                // Realm Initial Measurement
        uint8_t rem[4][64];             // Realm Extensible Measurements
        uint8_t challenge[64];          // 挑战值 (防重放)
        // ...
    } realm_token;
};

// Token 由硬件密钥签名，不可伪造
```

## 4. 对 Android 的影响

### 4.1 与 pKVM/AVF 集成

```
Android Virtualization Framework + CCA:

┌─────────────────────────────────────────────────────────────┐
│                    Android Host                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Android Apps                          ││
│  │         (不能访问 pVM/Realm 内存)                        ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Android OS                            ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │         pKVM (Protected KVM) - EL2                       ││
│  │  - 启用 CCA 后，pVM 可以作为 Realm 运行                   ││
│  │  - Host 无法读取 pVM 内存                                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │    RMM      │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌────▼────┐ ┌─────▼─────┐
        │ Microdroid │ │ pVM 2  │ │  pVM 3   │
        │ (Realm)    │ │(Realm) │ │ (Realm)  │
        └───────────┘ └─────────┘ └──────────┘
```

### 4.2 用例场景

**机密计算用例**：
```
1. 隐私保护 ML 推理
   - 用户数据在 Realm 中处理
   - 即使设备 root 也无法窃取数据

2. 安全密钥管理
   - 密钥只在 Realm 中解密使用
   - Host 无法提取密钥

3. DRM 内容保护
   - 解密后的媒体内容在 Realm 中渲染
   - 防止屏幕录制/内存转储

4. 企业数据隔离
   - 工作数据在独立 Realm 中运行
   - 个人 Android 系统无法访问
```

## 5. 安全研究视角

### 5.1 攻击面分析

| 攻击面 | 描述 | 研究方向 |
|--------|------|----------|
| RMM 固件 | 管理 Realm 的关键代码 | 固件漏洞、逻辑错误 |
| Host-Realm 通信 | 共享内存、virtio 设备 | 协议漏洞、TOCTOU |
| 证明协议 | Token 生成与验证 | 协议绕过、重放攻击 |
| Granule 管理 | 内存状态转换 | 状态机漏洞 |
| 侧信道 | 缓存、时序 | 即使隔离，侧信道仍可能存在 |

### 5.2 RMM 攻击向量

```c
// 潜在的 RMM 漏洞类型

// 1. 输入验证不足
RMI_DATA_CREATE(realm_id, addr, src_addr);
// 如果 src_addr 验证不严，可能读取其他 Realm 数据

// 2. 状态机混乱
// Realm 在某些中间状态可能暴露数据
REALM_STATE_NEW → REALM_STATE_ACTIVE → REALM_STATE_DESTROYED
// 状态转换期间的竞争条件？

// 3. 证明绕过
// 如果 RMM 测量计算有误，可能伪造证明
// 或者 Token 生成存在时序问题

// 4. 内存别名
// 物理内存是否能同时出现在多个安全状态？
// GPT 更新与实际访问之间的竞争？
```

### 5.3 DevLore: 设备访问攻击研究

2024 年研究 (DevLore) 指出的问题：

```
问题：CCA 最初主要考虑 CPU 和内存的隔离
      对于集成设备 (GPU、DMA 引擎) 的访问控制较弱

攻击场景：
1. 恶意 Host 配置 GPU 直接访问 Realm 内存
2. 即使 CPU 访问被 GPC 阻止，GPU DMA 可能绕过
3. 中断注入也可能泄露信息

DevLore 的解决方案：
- 扩展 RMM 管理设备访问
- 虚拟化 SMMU 配置
- 隔离中断路由
```

### 5.4 研究工具

**OpenCCA 框架**：
```bash
# 用于在普通 ARMv8 硬件上研究 CCA
# https://github.com/ArmCCA/OpenCCA

# 组件：
# - 修改的 QEMU 模拟 RME
# - 参考 RMM 实现
# - 测试用 Realm 负载

git clone https://github.com/ArmCCA/OpenCCA
cd OpenCCA
./build.sh  # 构建模拟环境

# 运行示例 Realm
./run.sh --realm example_realm.bin
```

## 6. 当前状态与未来

### 6.1 部署状态 (2025)

| 方面 | 状态 |
|------|------|
| 硬件支持 | Cortex-X4/A720 等 ARMv9.2+ SoC 开始支持 |
| Android 支持 | Android 15+ 开始集成 CCA 支持 |
| 设备可用性 | 少数旗舰设备 (2024-2025 发布) |
| 成熟度 | 早期阶段，API 和实现仍在演进 |

### 6.2 研究优先级

```
高优先级：
1. RMM 形式化验证状态 (Coq 证明进行中)
2. Host-Realm 通信协议审计
3. 证明生成与验证流程

中优先级：
4. 设备 DMA 隔离 (DevLore 方向)
5. 侧信道缓解有效性
6. 性能开销测量

低优先级 (当前)：
7. 实际漏洞挖掘 (硬件稀少)
8. 大规模部署问题
```

## 7. 参考资源

### ARM 官方文档
- [ARM CCA Documentation](https://developer.arm.com/documentation/den0126/latest)
- [RME System Architecture](https://developer.arm.com/documentation/DEN0129)
- [RMM Specification](https://developer.arm.com/documentation/DEN0137)

### 研究论文
- [Enabling Realms with ARM CCA](https://www.usenix.org/publications/loginonline/enabling-realms-arm-confidential-compute-architecture) - USENIX
- [DevLore: Extending ARM CCA to Integrated Devices](https://arxiv.org/html/2408.05835v1)
- [OpenCCA: An Open Framework](https://arxiv.org/pdf/2506.05129)

### Android 文档
- [Android Virtualization Framework](https://source.android.com/docs/core/virtualization)
- [Android Security Features](https://source.android.com/docs/security/features)

### 实践资源
- [ARM CCA Ecosystem](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
- [Linux Kernel CCA Support](https://www.kernel.org/doc/html/next/arch/arm64/arm-cca.html)
