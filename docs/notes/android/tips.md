# Android 安全研究学习指南

**内部参考文档**：Android 漏洞研究的学习路径与资源指引。

## Android 漏洞研究培训生态

### 全栈平台
- [Mobile Hacking Lab](https://mobilehackinglab.com) — Android 全栈平台

### App 层
- [hextree](https://hextree.io) — Android App 安全 (Google 合作)

### Framework & Logic 层
- [Project Zero Blog](https://projectzero.google)
- [AOSP 源码审计](https://source.android.com)
- [Google VRP 历年报告](https://bughunters.google.com)

### HAL & TEE 层
- [Quarkslab Blog](https://blog.quarkslab.com) — 硬件安全研究

### Kernel 层
- [pwn.college](https://pwn.college) — 系统化 PWN 基础 (x64)
- [ctf.show](https://ctf.show) (x86)
- [Azeria Labs](https://azeria-labs.com) (arm)


## 参考（AOSP）

- 现代实现对照入口：https://source.android.com/docs
- 架构概览：https://source.android.com/docs/core/architecture
- 应用沙盒（含 UID/DAC、SELinux 隔离演进、seccomp 相关描述）：https://source.android.com/docs/security/app-sandbox
- SELinux（含 enforcing/permissive、Treble 相关影响）：https://source.android.com/docs/security/features/selinux
- Verified Boot / AVB：https://source.android.com/docs/security/features/verifiedboot
- 月度安全公告（ASB）：https://source.android.com/docs/security/bulletin
- 构建与版本生命周期：https://source.android.com/docs/setup/build
