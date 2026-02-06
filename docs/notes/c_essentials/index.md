# C Essentials for Android Development

C 语言速查与实战教程，为 Android 内核、驱动、Native 层开发打基础。

## 为什么学 C

| Android 组件 | 语言 | 示例 |
|-------------|------|------|
| Linux Kernel | C | 驱动、Binder 内核端 |
| Native Daemons | C/C++ | init, logd, adbd |
| Bionic | C | Android libc |
| HAL | C/C++ | 硬件抽象层 |

## 目录

- [00 - 基础语法](./00-basics.md)
- [01 - 指针与内存](./01-pointers.md)
- [02 - 内存管理](./02-memory.md)
- [03 - 结构体](./03-structures.md)
- [04 - 预处理器](./04-preprocessor.md)
- [05 - 内核开发](./05-kernel-style.md)
- [06 - 驱动开发](./06-driver-dev.md)
- [07 - KernelSU/Magisk](./07-ksu-magisk-native.md)

## 相关 CVE (2023-2025)

| CVE | 组件 | 类型 |
|-----|------|------|
| CVE-2023-20938 | Binder driver | UAF (野外利用) |
| CVE-2023-21255 | Binder driver | UAF |
| CVE-2023-44095 | SurfaceFlinger | UAF |
| CVE-2024-36971 | Kernel 网络路由 | UAF (RCE) |
| CVE-2024-40660 | SurfaceFlinger | 逻辑错误 |
| CVE-2024-53104 | USB 驱动 | OOB Write |
| CVE-2025-27363 | FreeType | 代码执行 |
