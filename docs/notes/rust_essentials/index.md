# Rust Essentials for Android Development

Rust 语言教程，为 Android 内存安全组件开发打基础。

## 为什么学 Rust

| Android 组件 | 语言 | 示例 |
|-------------|------|------|
| 安全关键组件 | Rust | Keystore2, UWB |
| Binder | Rust | Binder Rust 驱动 |
| 网络安全 | Rust | DNS over HTTPS |
| 内核模块 | Rust | Kernel Rust (实验) |

> [!TIP]
> Rust 使 Android 内存安全漏洞从 76% (2019) → <20% (2025)

## 目录

- [00 - 基础语法](./00-basics.md)
- [01 - 所有权](./01-ownership.md)
- [02 - 类型系统](./02-types.md)
- [03 - 错误处理](./03-error.md)
- [04 - 并发编程](./04-concurrency.md)
- [05 - Unsafe Rust](./05-unsafe.md)
- [06 - AOSP Rust](./06-android-rust.md)
- [07 - Magisk Rust](./07-magisk-rust.md)

## 相关 CVE (2025)

| CVE | 组件 | 类型 |
|-----|------|------|
| CVE-2025-48530 | CrabbyAVIF | 缓冲区溢出 (unsafe，发布前修复) |
| CVE-2025-68260 | Binder Rust | 竞态条件 (**首个内核 Rust CVE**) |

> Rust 使内存安全漏洞：76% (2019) → <20% (2025)
