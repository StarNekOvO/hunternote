# Part 4: Native Layer Security

Native 层是 Android 系统的基础，包括了 C 库、动态链接器、系统守护进程以及 Android 运行时（ART）。这里的漏洞通常是内存破坏型的，利用难度高但威力巨大。

## 1. 原生层的安全挑战

1.  **内存安全**：C/C++ 缺乏内存安全保证，溢出（Overflow）、释放后使用（UAF）是常客。
2.  **提权跳板**：许多 Native 进程以 root 或高权限 UID 运行，是实现沙箱逃逸的关键。

## 参考（AOSP）

- https://source.android.com/docs/core — AOSP Core 主题总览（runtime/media/permissions/virtualization 等入口）
- https://source.android.com/docs/core/architecture — Android 系统架构与关键组件概览
- https://source.android.com/docs/core/runtime — ART/Dalvik 与运行时相关机制的总览入口
- https://source.android.com/docs/core/architecture/vndk — system/vendor 边界、可链接库集合与相关术语（涉及 linker namespace）
