# ARM64 Assembly Essentials

Android 汇编速查与实战：从寄存器到 Exploit 开发

## 为什么要学汇编？

**安全研究绑定汇编的三个理由：**

1. **漏洞分析** — 理解 CVE 报告中的"越界写"到底写到了哪里
2. **Exploit 开发** — ROP chain、shellcode 都需要汇编思维
3. **逆向工程** — 没有源码时，汇编是唯一的真相

**一个真实场景：**

```
├── 漏洞成因: C 代码逻辑错误
├── 触发路径: ioctl 系统调用
└── 利用方式: ROP chain → 28 条 ARM64 gadget → root
```

如果看不懂这 28 条 gadget，就无法理解这个漏洞是如何变成 root 的。

## 学习路径

```
Week 1: 基础 (Chapter 00-02)
├── ARM64 寄存器和指令
├── 内存寻址
└── 调用约定

Week 2: 工具 (Chapter 03-04)
├── Inline 汇编
└── 调试技巧

Week 3-4: Exploit (Chapter 05-07)
├── Control Flow Hijack
├── Memory Corruption
└── 完整 Exploit 开发
```

**预计时间：** 20-30 小时（每天 1-2 小时，2-3 周）

## 前置要求

| 要求 | 程度 | 说明 |
|------|------|------|
| C 语言 | 必需 | 指针、内存布局 |
| Linux 命令行 | 必需 | GDB 基本操作 |
| Android 基础 | 推荐 | NDK、adb |
| x86 汇编 | 可选 | 有帮助但不必须 |

## ARM64 vs 其他架构

| 特性 | ARM64 (AArch64) | x86-64 | ARM32 |
|------|-----------------|--------|-------|
| 寄存器数量 | 31 通用 | 16 通用 | 16 通用 |
| 指令长度 | 固定 4 字节 | 变长 1-15 字节 | 固定 4 或 2 字节 |
| 字节序 | 小端 | 小端 | 可配置 |
| Android 使用 | 主流（64位设备）| 模拟器 | 旧设备 |
| 安全研究价值 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

**为什么 Android 用 ARM？**
- 功耗低（移动设备核心需求）
- 授权灵活（厂商可定制）
- 生态成熟

## 与其他语言笔记的关系

```
┌─────────────────────────────────────────────────────┐
│              Android Security Research              │
├───────────┬───────────┬───────────┬────────────────┤
│  C        │  Java     │  Rust     │  ARM64 Asm     │
│  Essentials│ Essentials│ Essentials│  Essentials    │
├───────────┼───────────┼───────────┼────────────────┤
│  内核     │  Framework│  新组件   │  Exploit       │
│  驱动     │  App 层   │  Keystore │  逆向          │
│  HAL      │  Xposed   │  Binder   │  漏洞分析      │
└───────────┴───────────┴───────────┴────────────────┘
```

**联系：**
- C 代码编译后就是汇编
- Java/ART 运行时也是 native 代码
- Rust 的 unsafe 最终也是汇编

## 推荐工具

### 必备

| 工具 | 用途 | 安装 |
|------|------|------|
| GDB + GEF | 调试 | `apt install gdb` + GEF 插件 |
| objdump | 反汇编 | 系统自带 |
| readelf | ELF 分析 | 系统自带 |

### 推荐

| 工具 | 用途 | 说明 |
|------|------|------|
| Ghidra | 逆向 | 免费，NSA 出品 |
| IDA Pro | 逆向 | 商业，行业标准 |
| ROPgadget | ROP 开发 | `pip install ropgadget` |
| pwntools | Exploit 开发 | `pip install pwntools` |
| Frida | 动态分析 | `pip install frida-tools` |

### Android 特定

```bash
# Android NDK (交叉编译)
# 下载: https://developer.android.com/ndk/downloads

# adb 调试
adb shell
adb push exploit /data/local/tmp/
```

## 快速开始（10 分钟）

### 1. 环境检查

```bash
# 确认有 aarch64 工具链
aarch64-linux-gnu-gcc --version

# 或使用 Android NDK
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang --version
```

### 2. Hello World

```asm
// hello.s
.global _start
.section .text

_start:
    // write(1, msg, 13)
    mov x0, #1          // fd = stdout
    adr x1, msg         // buf = msg
    mov x2, #13         // count = 13
    mov x8, #64         // syscall = write
    svc #0
    
    // exit(0)
    mov x0, #0          // status = 0
    mov x8, #93         // syscall = exit
    svc #0

.section .data
msg:
    .ascii "Hello ARM64\n"
```

### 3. 编译运行

```bash
# 编译
aarch64-linux-gnu-as -o hello.o hello.s
aarch64-linux-gnu-ld -o hello hello.o

# 在 ARM64 设备上运行
adb push hello /data/local/tmp/
adb shell chmod +x /data/local/tmp/hello
adb shell /data/local/tmp/hello
# 输出: Hello ARM64
```

### 4. 用 GDB 调试

```bash
# 在设备上启动 gdbserver
adb shell /data/local/tmp/gdbserver :1234 /data/local/tmp/hello

# 本地连接
adb forward tcp:1234 tcp:1234
aarch64-linux-gnu-gdb hello
(gdb) target remote :1234
(gdb) break _start
(gdb) continue
(gdb) info registers
```

## 章节目录

### 基础篇

| 章节 | 内容 | 难度 |
|------|------|------|
| [00 - ARM64 基础](./00-arm64-basics.md) | 寄存器、指令、架构 | ⭐ |
| [01 - 内存寻址](./01-memory-addressing.md) | 寻址模式、对齐、Cache | ⭐⭐ |
| [02 - 调用约定](./02-calling-conventions.md) | AAPCS64、栈帧、参数传递 | ⭐⭐ |
| [03 - Inline 汇编](./03-inline-asm.md) | GCC/Clang inline asm | ⭐⭐ |
| [04 - 调试技巧](./04-debugging-asm.md) | GDB、Ghidra、crash 分析 | ⭐⭐⭐ |

### Exploit 篇

| 章节 | 内容 | 难度 |
|------|------|------|
| [05 - 控制流劫持](./05-control-flow-hijack.md) | ROP、JOP、ret2libc | ⭐⭐⭐⭐ |
| [06 - 内存破坏](./06-memory-corruption.md) | 栈溢出、堆溢出、UAF | ⭐⭐⭐⭐ |
| [07 - Exploit 开发](./07-exploit-development.md) | 完整 exploit、shellcode | ⭐⭐⭐⭐⭐ |

## 相关 CVE 速览

本系列会分析以下真实漏洞：

| CVE | 类型 | 章节 |
|-----|------|------|
| [CVE-2021-0920](../../cves/entries/CVE-2021-0920.md) | socket UAF | 06 |
| [CVE-2022-20186](../../cves/entries/CVE-2022-20186.md) | GPU 驱动 | 06 |
| [CVE-2023-20938](../../cves/entries/CVE-2023-20938.md) | Binder UAF | 05, 06 |

## 深入阅读

**官方资源：**
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Procedure Call Standard (AAPCS64)](https://github.com/ARM-software/abi-aa)

**推荐书籍：**
- *Blue Fox: Arm Assembly Internals & Reverse Engineering*
- *The Art of Exploitation*

**在线资源：**
- [Azeria Labs ARM Assembly](https://azeria-labs.com/writing-arm-assembly-part-1/)
- [ARM64 Syscall Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit)

## 下一步

[00 - ARM64 基础](./00-arm64-basics.md) — 从寄存器开始
