# Part 3: System Services

在 Android 中，大部分核心功能（如安装应用、启动 Activity、管理窗口）都不是由应用自己完成的，而是通过 IPC 请求 **System Services** 来实现的。这些服务大多运行在 `system_server` 进程中。

## 1. 为什么系统服务是核心攻击面？

1.  **高权限**：`system_server` 拥有极高的权限（UID 1000, system），可以访问几乎所有的硬件和敏感数据。
2.  **逻辑复杂**：AMS、PMS 等服务包含数百万行 Java 代码，逻辑极其复杂，容易出现状态机错误或权限校验漏洞。
3.  **跨进程交互**：所有应用都能通过 Binder 与这些服务通信，提供了巨大的攻击入口。

## 2. Canyie (残页) 相关 CVE 速查

> GitHub: https://github.com/canyie | Blog: https://blog.canyie.top
>
> Canyie 是 Google Bug Hunters Android Program #4 的安全研究员，以下是她在系统服务层发现的部分漏洞：

| CVE | 类型 | 模块 | 章节 |
|-----|------|------|------|
| **CVE-2024-0044** | EoP/High | PMS (packages.list) | [02-pms](/notes/android/03-services/02-pms) |
| CVE-2024-43080 | EoP/High | Framework | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2024-43081 | EoP/High | Framework | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2024-49733 | EoP/High | Framework | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2024-49744 | EoP/High | Framework | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2025-22432 | EoP/High | System | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2025-26464 | EoP/High | AppSearch | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2025-32323 | EoP/High | DocumentsUI | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2025-48535 | EoP/High | Settings | [00-system-server](/notes/android/03-services/00-system-server) |
| CVE-2025-48554 | DoS/High | Framework | [00-system-server](/notes/android/03-services/00-system-server) |

> **CVE-2024-0044** 有完整的 PoC 与技术分析，**强烈推荐深入学习**。

## 参考（AOSP）

- 架构概览（系统服务、system_server、原生守护进程层级）：https://source.android.com/docs/core/architecture
- AIDL 概览（平台 IPC 抽象，对照 service/dumpsys）：https://source.android.com/docs/core/architecture/aidl
- 应用签名（签名方案 v1/v2/v3/v4、shared UID 废弃口径）：https://source.android.com/docs/security/features/apksigning
- 媒体（Stagefright/媒体模块/强化）：https://source.android.com/docs/core/media
