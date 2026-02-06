# 02 - 调用约定

AAPCS64 详解、栈帧结构、参数传递。


## 概念速览

**调用约定是什么？**
函数调用时寄存器和栈的使用规则，让编译器生成的代码能正确互操作。

**安全研究为什么要精通？**
- Hook 函数需要知道参数在哪里
- ROP chain 需要控制参数
- 逆向分析函数边界和参数


## 核心概念

### AAPCS64 (ARM 过程调用标准)

| 寄存器 | 用途 | 保存责任 |
|--------|------|----------|
| X0-X7 | 参数/返回值 | Caller-saved |
| X8 | 间接结果位置 | Caller-saved |
| X9-X15 | 临时寄存器 | Caller-saved |
| X16-X17 | 过程间临时 | Caller-saved |
| X18 | 平台寄存器 | 特殊 (Android: TLS) |
| X19-X28 | 被调用者保存 | Callee-saved |
| X29 (FP) | 帧指针 | Callee-saved |
| X30 (LR) | 链接寄存器 | Callee-saved |
| SP | 栈指针 | Callee-saved |

### 参数传递

**规则：**
1. 前 8 个参数用 X0-X7
2. 超过 8 个的参数放在栈上
3. 返回值用 X0 (大结构体用 X0-X1 或 X8 指向的内存)

```c
// C 函数
long add(long a, long b, long c, long d,
         long e, long f, long g, long h,
         long i);  // 第 9 个参数
```

```asm
// 调用约定
// a → X0, b → X1, c → X2, d → X3
// e → X4, f → X5, g → X6, h → X7
// i → 栈

// 调用前准备
mov x0, #1           // a
mov x1, #2           // b
mov x2, #3           // c
mov x3, #4           // d
mov x4, #5           // e
mov x5, #6           // f
mov x6, #7           // g
mov x7, #8           // h
str x9, [sp, #-16]!  // i 放入栈 (保持对齐)
bl add
add sp, sp, #16      // 清理栈
```

### 返回值

```asm
// 简单返回值
// return value → X0
long foo() { return 42; }
// 编译为: mov x0, #42; ret

// 128 位返回值
// return value → X0:X1
__int128 big() { ... }
// X0 = 低 64 位, X1 = 高 64 位

// 大结构体返回
// 调用者提供内存地址在 X8
struct large big_struct();
// X8 → 结构体存储位置
```

### 栈帧结构

```
高地址
┌─────────────────────────┐
│      Caller's frame     │
├─────────────────────────┤
│  Stack arguments (if >8)│
├─────────────────────────┤ ← 进入函数时的 SP
│      Saved LR (X30)     │
├─────────────────────────┤
│      Saved FP (X29)     │
├─────────────────────────┤ ← X29 (FP) 指向这里
│      Local variables    │
├─────────────────────────┤
│  Callee-saved regs      │
│      (X19-X28)          │
├─────────────────────────┤
│     Outgoing args       │
│     (if calling)        │
├─────────────────────────┤ ← SP (16-byte aligned)
│          ...            │
低地址
```

### 函数序言和尾声

```asm
// 典型的 prologue (序言)
my_function:
    stp x29, x30, [sp, #-32]!  // 保存 FP, LR，分配栈空间
    mov x29, sp                 // 设置新的 FP
    stp x19, x20, [sp, #16]    // 保存需要保留的寄存器
    
    // ... 函数体 ...
    
    // 典型的 epilogue (尾声)
    ldp x19, x20, [sp, #16]    // 恢复保留寄存器
    ldp x29, x30, [sp], #32    // 恢复 FP, LR，释放栈空间
    ret
```

### Leaf vs Non-leaf 函数

**Leaf 函数** (不调用其他函数):
```asm
leaf_add:
    add x0, x0, x1        // 直接操作，不需要保存 LR
    ret
```

**Non-leaf 函数** (调用其他函数):
```asm
non_leaf_func:
    stp x29, x30, [sp, #-16]!   // 必须保存 LR
    mov x29, sp
    
    bl some_other_func          // 调用会覆盖 LR
    
    ldp x29, x30, [sp], #16     // 恢复
    ret
```


## 进阶用法

### Variadic 函数 (可变参数)

```c
// C
int printf(const char *fmt, ...);
```

```asm
// 调用 printf("%d %d", 10, 20)
adr x0, fmt_str       // 格式字符串
mov x1, #10           // 第一个可变参数
mov x2, #20           // 第二个可变参数
bl printf
```

### 浮点参数

```asm
// 浮点用 V0-V7 (也叫 D0-D7, S0-S7)
// double add(double a, double b)
fadd d0, d0, d1       // a 在 D0, b 在 D1, 结果返回 D0
ret
```

### 混合参数

```c
// void mix(int a, double b, int c, double d);
```

```asm
// a → W0 (整数寄存器)
// b → D0 (浮点寄存器)
// c → W1 (整数寄存器)
// d → D1 (浮点寄存器)
// 各走各的通道！
```


## 实战场景

### Lab 1: 手写汇编函数

**目标：** 编写 C 可调用的汇编函数

```asm
// mylib.s
.global my_add
.global my_strlen

// long my_add(long a, long b)
my_add:
    add x0, x0, x1
    ret

// size_t my_strlen(const char *s)
my_strlen:
    mov x1, x0           // 保存起始地址
.Lloop:
    ldrb w2, [x0], #1    // 读取字符并前进
    cbnz w2, .Lloop      // 如果不为 0，继续
    sub x0, x0, x1       // 计算长度
    sub x0, x0, #1       // 减去结尾的 null
    ret
```

**C 调用：**
```c
// main.c
extern long my_add(long a, long b);
extern size_t my_strlen(const char *s);

int main() {
    printf("3 + 4 = %ld\n", my_add(3, 4));
    printf("strlen = %zu\n", my_strlen("hello"));
    return 0;
}
```

**编译链接：**
```bash
aarch64-linux-gnu-as -o mylib.o mylib.s
aarch64-linux-gnu-gcc -o main main.c mylib.o
```

### Lab 2: Hook 函数读取参数

**目标：** 用 Frida hook open() 并读取参数

```javascript
// hook_open.js
Interceptor.attach(Module.getExportByName("libc.so", "open"), {
    onEnter: function(args) {
        // open(const char *pathname, int flags)
        // pathname → X0, flags → X1
        var pathname = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt32();
        console.log("open(" + pathname + ", " + flags + ")");
    },
    onLeave: function(retval) {
        // 返回值在 X0
        console.log("  → fd = " + retval);
    }
});
```

**运行：**
```bash
frida -U -l hook_open.js com.target.app
```

### Lab 3: 分析栈帧

**目标：** 用 GDB 观察栈帧

```asm
// stackframe.s
.global _start

_start:
    mov x0, #1
    mov x1, #2
    bl level1
    
    mov x8, #93
    svc #0

level1:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    mov x0, #3
    bl level2
    
    ldp x29, x30, [sp], #16
    ret

level2:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x0, [sp, #16]     // 保存参数
    
    // 断点在这里观察栈
    nop
    
    ldp x29, x30, [sp], #32
    ret
```

**GDB 分析：**
```
(gdb) break level2
(gdb) continue
(gdb) info frame
(gdb) x/8gx $sp
(gdb) backtrace
```

**栈布局：**
```
┌──────────────┐
│  _start LR   │
├──────────────┤
│ _start FP    │
├──────────────┤ ← level1 FP
│  level1 LR   │
├──────────────┤
│ level1 FP ───│──┘
├──────────────┤ ← level2 FP (current)
│  local var   │
├──────────────┤ ← SP
```


## 常见陷阱

### ❌ 陷阱 1: 忘记保存 LR

```asm
// 错误
non_leaf:
    bl other_func      // LR 被覆盖！
    ret                // 返回到错误地址

// 正确
non_leaf:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    bl other_func
    ldp x29, x30, [sp], #16
    ret
```

**安全影响：** 这是栈溢出利用的基础

### ❌ 陷阱 2: 栈未对齐

```asm
// 错误：分配奇数大小
sub sp, sp, #24         // SP 不再 16 字节对齐
bl some_func            // 可能崩溃！

// 正确
sub sp, sp, #32         // 向上对齐到 16
```

### ❌ 陷阱 3: Caller-saved 被覆盖

```asm
// 错误
mov x0, #important_value
bl some_func            // X0 可能被覆盖！
use x0                  // 使用了错误值

// 正确：保存到 callee-saved 寄存器
mov x19, #important_value
bl some_func
mov x0, x19             // X19 被保留
```

### ❌ 陷阱 4: 多返回值参数

```c
// 返回两个值的函数
struct pair { long a; long b; };
struct pair get_pair();
```

```asm
// 小结构体 (≤16 字节) 可用寄存器返回
// get_pair() 返回:
//   X0 = pair.a
//   X1 = pair.b

// 大结构体需要 X8
// void get_large(struct large *result)
// X8 = 调用者提供的地址
```


## Android 场景

### libc 函数调用分析

```asm
// mmap(addr, length, prot, flags, fd, offset)
// 6 个参数: X0-X5

// 实际调用
mov x0, xzr             // addr = NULL
mov x1, #0x1000         // length = 4096
mov x2, #3              // prot = PROT_READ|PROT_WRITE
mov x3, #0x22           // flags = MAP_PRIVATE|MAP_ANONYMOUS
mov x4, #-1             // fd = -1
mov x5, xzr             // offset = 0
bl mmap
// 返回地址在 X0
```

### Binder 调用

```asm
// ioctl(fd, BINDER_WRITE_READ, &bwr)
mov x0, x19             // Binder fd
mov x1, #BINDER_WRITE_READ
mov x2, x20             // bwr 结构体地址
bl ioctl
```

### JNI 调用约定

```c
// JNI 函数总是有两个隐含参数
// jstring Java_pkg_Class_method(JNIEnv *env, jobject thiz, ...)
```

```asm
// env → X0
// thiz → X1
// 用户参数从 X2 开始
// 或者 this 用 X1 (non-static), class 用 X1 (static)
```


## 深入阅读

**推荐资源：**
- [AAPCS64 Specification](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
- [ARM64 Calling Convention](https://developer.arm.com/documentation/102374/latest/Procedure-Call-Standard)

**相关章节：**
- [00 - ARM64 基础](./00-arm64-basics.md) - 寄存器基础
- [05 - 控制流劫持](./05-control-flow-hijack.md) - 利用返回地址


## 下一步

[03 - Inline 汇编](./03-inline-asm.md) — 在 C/Rust 中使用汇编
