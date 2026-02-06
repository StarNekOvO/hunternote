# 00 - ARM64 基础

ARM64 架构、寄存器、基本指令。

## 概念速览

**ARM64 是什么？**
ARM 的 64 位指令集架构（也叫 AArch64），Android 主流处理器架构。

**为什么安全研究要学？**
- 所有 Android 漏洞最终都是汇编层面的内存破坏
- 理解寄存器才能构造 ROP chain
- 逆向 native 库必须读懂汇编

## 核心概念

### ARM64 vs ARM32 vs x86-64

| 特性 | ARM64 | ARM32 | x86-64 |
|------|-------|-------|--------|
| 别名 | AArch64 | AArch32/ARM | AMD64 |
| 位宽 | 64-bit | 32-bit | 64-bit |
| 通用寄存器 | 31 (X0-X30) | 16 (R0-R15) | 16 (RAX, RBX...) |
| 指令长度 | 固定 4 字节 | 4 字节 (ARM) / 2 字节 (Thumb) | 变长 1-15 字节 |
| 条件执行 | 条件分支 | 几乎所有指令 | 条件分支 |
| Android | 主流 | 旧设备 | 模拟器 |

**为什么固定长度指令更适合安全研究？**
- 反汇编确定性高
- ROP gadget 更容易定位
- 但 gadget 数量可能较少

### 寄存器详解

```
┌─────────────────────────────────────────────────────────┐
│                    通用寄存器                            │
├─────────────────────────────────────────────────────────┤
│ X0-X7    参数/返回值寄存器                               │
│ X8       间接结果位置寄存器 (用于返回大结构体)            │
│ X9-X15   临时寄存器 (caller-saved)                      │
│ X16-X17  临时寄存器 (用于过程链接)                       │
│ X18      平台寄存器 (Android: TLS)                      │
│ X19-X28  被调用者保存 (callee-saved)                    │
│ X29      帧指针 (FP)                                    │
│ X30      链接寄存器 (LR) - 保存返回地址                  │
├─────────────────────────────────────────────────────────┤
│                    特殊寄存器                            │
├─────────────────────────────────────────────────────────┤
│ SP       栈指针                                         │
│ PC       程序计数器 (不能直接访问)                       │
│ XZR/WZR  零寄存器 (读=0, 写=丢弃)                        │
├─────────────────────────────────────────────────────────┤
│                    状态寄存器                            │
├─────────────────────────────────────────────────────────┤
│ NZCV     条件标志 (Negative, Zero, Carry, oVerflow)     │
│ PSTATE   处理器状态                                     │
└─────────────────────────────────────────────────────────┘
```

**32 位视图：**
```
X0  [63:0]     完整 64 位
W0  [31:0]     低 32 位视图

例如:
X0 = 0x0000000012345678
W0 = 0x12345678
```

**安全研究中的关键寄存器：**

| 寄存器 | Exploit 用途 |
|--------|-------------|
| X0-X7 | 控制函数参数 |
| X30 (LR) | 返回地址 → ROP 起点 |
| SP | 栈地址 → 栈溢出控制 |
| X8 | syscall 号 |

### NZCV 标志

```
N (Negative): 结果为负
Z (Zero):     结果为零
C (Carry):    无符号溢出
V (oVerflow): 有符号溢出
```

```asm
// 设置标志
adds x0, x1, x2    // 更新标志
cmp x0, x1         // 比较 (等于 subs xzr, x0, x1)

// 条件分支
b.eq label         // if Z=1 (相等)
b.ne label         // if Z=0 (不等)
b.gt label         // if Z=0 && N=V (大于, 有符号)
b.lt label         // if N≠V (小于, 有符号)
b.hi label         // if C=1 && Z=0 (大于, 无符号)
b.lo label         // if C=0 (小于, 无符号)
```


## 基础指令

### 数据移动

```asm
// MOV - 移动数据
mov x0, #42          // 立即数
mov x0, x1           // 寄存器到寄存器
mov x0, xzr          // 清零

// MVN - 取反移动
mvn x0, x1           // x0 = ~x1

// MOVK/MOVZ/MOVN - 构造大立即数
movz x0, #0x1234             // x0 = 0x0000000000001234
movk x0, #0x5678, lsl #16    // x0 = 0x0000000056781234
```

**为什么需要 MOVZ/MOVK？**
ARM64 立即数受限，单条指令只能编码 16 位。构造 64 位值需要多条指令。

### 内存访问

```asm
// LDR - 加载
ldr x0, [x1]         // x0 = *(x1)
ldr x0, [x1, #8]     // x0 = *(x1 + 8)
ldr w0, [x1]         // 加载 32 位

// STR - 存储
str x0, [x1]         // *(x1) = x0
str x0, [x1, #8]     // *(x1 + 8) = x0

// LDP/STP - 成对加载/存储
ldp x0, x1, [sp]     // 同时加载两个寄存器
stp x29, x30, [sp, #-16]!  // 保存 FP 和 LR
```

### 算术运算

```asm
// 加法
add x0, x1, x2       // x0 = x1 + x2
add x0, x1, #100     // x0 = x1 + 100
adds x0, x1, x2      // 更新标志

// 减法
sub x0, x1, x2       // x0 = x1 - x2
subs x0, x1, x2      // 更新标志 (用于比较)

// 乘法
mul x0, x1, x2       // x0 = x1 * x2

// 除法
udiv x0, x1, x2      // 无符号除法
sdiv x0, x1, x2      // 有符号除法
```

### 逻辑运算

```asm
and x0, x1, x2       // 按位与
orr x0, x1, x2       // 按位或
eor x0, x1, x2       // 按位异或
bic x0, x1, x2       // x0 = x1 & ~x2

// 移位
lsl x0, x1, #4       // 逻辑左移
lsr x0, x1, #4       // 逻辑右移 (无符号)
asr x0, x1, #4       // 算术右移 (有符号)
ror x0, x1, #4       // 循环右移
```

### 控制流

```asm
// 无条件跳转
b label              // 直接跳转
bl function          // 跳转并保存返回地址到 LR
br x0                // 寄存器跳转
blr x0               // 寄存器调用
ret                  // 返回 (等于 br x30)

// 条件跳转
cmp x0, #0
b.eq zero_label      // if x0 == 0
b.ne nonzero_label   // if x0 != 0
b.gt positive_label  // if x0 > 0 (有符号)

// 比较并跳转 (一条指令完成)
cbz x0, label        // if x0 == 0
cbnz x0, label       // if x0 != 0
tbz x0, #3, label    // if bit 3 of x0 == 0
tbnz x0, #3, label   // if bit 3 of x0 != 0
```

### 系统调用

```asm
// Android/Linux ARM64 系统调用
mov x8, #64          // syscall 号 (write = 64)
mov x0, #1           // arg1: fd
adr x1, msg          // arg2: buf
mov x2, #13          // arg3: count
svc #0               // 触发系统调用
```

**常用 syscall：**

| 号码 | 名称 | 参数 |
|------|------|------|
| 64 | write | fd, buf, count |
| 93 | exit | status |
| 221 | execve | filename, argv, envp |
| 220 | clone | flags, stack, ... |
| 29 | ioctl | fd, cmd, arg |


## 实战场景

### Lab 1: Hello World

**目标：** 编写第一个 ARM64 汇编程序

```asm
// hello.s
.global _start
.section .text

_start:
    // write(1, msg, 12)
    mov x0, #1          // stdout
    adr x1, msg         // 消息地址
    mov x2, #12         // 长度
    mov x8, #64         // write syscall
    svc #0
    
    // exit(0)
    mov x0, #0
    mov x8, #93         // exit syscall
    svc #0

.section .rodata
msg:
    .ascii "Hello ARM64\n"
```

**编译运行：**
```bash
aarch64-linux-gnu-as -o hello.o hello.s
aarch64-linux-gnu-ld -o hello hello.o

# 本地运行 (需要 qemu-user)
qemu-aarch64 ./hello

# 或 Android 设备
adb push hello /data/local/tmp/
adb shell /data/local/tmp/hello
```

**输出：**
```
Hello ARM64
```

### Lab 2: GDB 调试

**目标：** 用 GDB 观察寄存器变化

```bash
# 安装 GEF (GDB 增强)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# 启动调试
qemu-aarch64 -g 1234 ./hello &
gdb-multiarch -ex "target remote :1234" -ex "file hello"
```

**GDB 命令：**
```
(gdb) break _start
(gdb) continue
(gdb) info registers
(gdb) stepi                    # 单步
(gdb) x/10i $pc                # 查看指令
(gdb) x/4gx $sp                # 查看栈
```

**输出示例：**
```
x0             0x1
x1             0x4001a8         <- msg 地址
x2             0xc              <- 长度 12
x8             0x40             <- syscall 64
```

### Lab 3: 简单函数

**目标：** 编写一个计算函数并调用

```asm
// add.s
.global add_numbers
.global _start
.section .text

// int add_numbers(int a, int b)
add_numbers:
    add x0, x0, x1       // x0 = a + b
    ret

_start:
    mov x0, #10          // a = 10
    mov x1, #20          // b = 20
    bl add_numbers       // call
    
    // x0 现在是 30
    // 退出
    mov x8, #93
    svc #0
```

**验证：**
```bash
aarch64-linux-gnu-as -o add.o add.s
aarch64-linux-gnu-ld -o add add.o
qemu-aarch64 ./add ; echo $?
# 输出: 30
```


## 常见陷阱

### ❌ 陷阱 1: 立即数范围

```asm
// 错误：立即数太大
mov x0, #0x123456789    // 编译错误！

// 正确：分步构造
movz x0, #0x6789
movk x0, #0x2345, lsl #16
movk x0, #0x0001, lsl #32
```

**调试技巧：** 汇编器会报错 "immediate out of range"

### ❌ 陷阱 2: 32 位 vs 64 位

```asm
// 错误：混用 W 和 X 可能导致高位被清零
mov w0, #-1            // W0 = 0xFFFFFFFF
                       // X0 = 0x00000000FFFFFFFF (高位清零！)

// 如果需要 64 位 -1
mov x0, #-1            // X0 = 0xFFFFFFFFFFFFFFFF
```

**安全影响：** 这类错误可能导致整数溢出漏洞

### ❌ 陷阱 3: LR 被覆盖

```asm
_start:
    bl func1
    bl func2            // func1 的返回地址丢失了！
    ret                 // 返回到错误的地方

// 正确：保存 LR
_start:
    stp x29, x30, [sp, #-16]!
    bl func1
    bl func2
    ldp x29, x30, [sp], #16
    ret
```

**真实案例：** 这是栈溢出利用的基础 — 覆盖保存的 LR

### ❌ 陷阱 4: 栈对齐

```asm
// 错误：栈未 16 字节对齐
sub sp, sp, #12
str x0, [sp]           // 可能崩溃或性能差

// 正确：保持 16 字节对齐
sub sp, sp, #16
str x0, [sp]
```

**原因：** ARM64 要求 SP 在函数调用时 16 字节对齐


## Android 场景

### libc 函数调用

```asm
// 调用 libc 的 printf
.global main
.extern printf

main:
    stp x29, x30, [sp, #-16]!
    
    adr x0, fmt
    mov x1, #42
    bl printf
    
    mov x0, #0
    ldp x29, x30, [sp], #16
    ret

fmt:
    .asciz "Value: %d\n"
```

### 反汇编 Android 库

```bash
# 从设备获取 libc
adb pull /system/lib64/libc.so

# 反汇编
aarch64-linux-gnu-objdump -d libc.so | head -100

# 或用 Ghidra
ghidra libc.so
```

**真实 libc.so 片段：**
```
0000000000022180 <write>:
   22180: d28008e8  mov x8, #0x47
   22184: d4000001  svc #0x0
   22188: b140041f  cmn x0, #0x1, lsl #12
   2218c: 54000062  b.cs 22198 <write+0x18>
   22190: d65f03c0  ret
```


## 深入阅读

**推荐资源：**
- [ARM64 Instruction Set Quick Reference](https://developer.arm.com/documentation/102374/latest)
- [Linux ARM64 Syscall Table](https://arm64.syscall.sh/)

**相关章节：**
- [01 - 内存寻址](./01-memory-addressing.md) - 寻址模式详解
- [02 - 调用约定](./02-calling-conventions.md) - 函数调用深入


## 下一步

[01 - 内存寻址](./01-memory-addressing.md) — 理解 ARM64 内存访问方式
