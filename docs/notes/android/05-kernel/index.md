# Part 5: Kernel Security

Android 内核基于 Linux，但增加了许多特有的驱动（如 Binder, Ashmem）和安全增强（如 SELinux）。
因此，内核层的安全研究既要关注传统 Linux 漏洞，也要重视 Android 特有的攻击面。

## 参考（AOSP）
- https://source.android.com/docs/core/architecture/kernel — Android 内核/ACK/GKI 的官方入口。
- https://source.android.com/docs/security/overview/kernel-security — Android 内核安全总览入口。
