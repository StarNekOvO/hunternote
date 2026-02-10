# 01 - 内存寻址

ARM64 寻址模式、内存对齐、Cache 行为。

## 概念速览

**寻址模式是什么？**
CPU 计算内存地址的方式。ARM64 提供灵活的寻址模式，是高效代码和漏洞利用的基础。

**安全研究为什么要关心？**
- 理解越界访问的本质
- 构造堆喷射需要精确的内存布局
- ROP gadget 经常使用复杂寻址

## 核心概念

### 寻址模式总览

| 模式 | 语法 | 计算 | 用途 |
|------|------|------|------|
| 基址 | `[base]` | `addr = base` | 简单访问 |
| 偏移 | `[base, #imm]` | `addr = base + imm` | 结构体字段 |
| 寄存器偏移 | `[base, Xn]` | `addr = base + Xn` | 数组索引 |
| 预索引 | `[base, #imm]!` | `base += imm; addr = base` | 栈操作 |
| 后索引 | `[base], #imm` | `addr = base; base += imm` | 循环遍历 |
| 扩展寄存器 | `[base, Wn, SXTW]` | `addr = base + sign_extend(Wn)` | 32位索引 |

### 基址寻址

```asm
// 简单基址
ldr x0, [x1]           // x0 = *(x1)

// 立即数偏移 (±4096 字节)
ldr x0, [x1, #8]       // x0 = *(x1 + 8)
ldr x0, [x1, #-8]      // x0 = *(x1 - 8)

// 常用于结构体访问
// struct foo { long a; long b; };  // a at offset 0, b at offset 8
ldr x0, [x1]           // x0 = foo->a
ldr x2, [x1, #8]       // x2 = foo->b
```

**内存布局：**
```
x1 指向 ──► ┌──────────┐ offset 0
            │    a     │
            ├──────────┤ offset 8
            │    b     │
            └──────────┘
```

### 寄存器偏移

```asm
// 寄存器作为偏移
ldr x0, [x1, x2]       // x0 = *(x1 + x2)

// 带移位 (适合数组访问)
ldr x0, [x1, x2, lsl #3]  // x0 = *(x1 + x2*8)
                          // 相当于 array[index]，每元素 8 字节
```

**数组访问示例：**
```asm
// long array[10];
// long value = array[i];
//
// x1 = array 基址
// x2 = i (索引)
ldr x0, [x1, x2, lsl #3]   // x0 = array[i]
```

### 预索引 (Pre-indexed)

```asm
// 先更新基址，再访问
ldr x0, [x1, #16]!     // x1 += 16; x0 = *x1

// 典型用法：栈分配
sub sp, sp, #32        // 分配 32 字节
stp x29, x30, [sp]     // 保存 FP, LR

// 更简洁的写法：
stp x29, x30, [sp, #-32]!  // 一条指令完成
```

**执行流程：**
```
Before:  sp = 0x1000
Execute: stp x29, x30, [sp, #-32]!
After:   sp = 0x0FE0, *(0x0FE0) = x29, *(0x0FE8) = x30
```

### 后索引 (Post-indexed)

```asm
// 先访问，再更新基址
ldr x0, [x1], #8       // x0 = *x1; x1 += 8

// 典型用法：遍历链表或数组
loop:
    ldr x0, [x1], #8   // 读取并移动到下一个
    cbnz x0, process
    b done
```

**执行流程：**
```
Before:  x1 = 0x1000
Execute: ldr x0, [x1], #8
After:   x0 = *(0x1000), x1 = 0x1008
```

### 扩展寄存器寻址

```asm
// 32 位索引符号扩展
ldr x0, [x1, w2, SXTW]       // x0 = *(x1 + sign_extend(w2))
ldr x0, [x1, w2, SXTW #3]    // x0 = *(x1 + sign_extend(w2) * 8)

// 32 位索引零扩展
ldr x0, [x1, w2, UXTW #3]    // x0 = *(x1 + zero_extend(w2) * 8)
```

**为什么需要扩展？**
- C 代码中 `array[int_index]` 的 index 可能是 32 位
- 需要正确扩展到 64 位地址计算
- 符号扩展错误可能导致越界访问

## 内存对齐

### 对齐要求

| 数据大小 | 对齐要求 | 违反后果 |
|----------|----------|----------|
| 字节 (1B) | 1 字节 | 无 |
| 半字 (2B) | 2 字节 | 可能慢 |
| 字 (4B) | 4 字节 | 可能崩溃 |
| 双字 (8B) | 8 字节 | 可能崩溃 |
| 四字 (16B) | 16 字节 | 崩溃 |

### 未对齐访问

```asm
// 假设 x1 = 0x1001 (未对齐地址)

// 在 Android 上，这可能崩溃：
ldr x0, [x1]           // SIGBUS!

// 安全的未对齐访问：
ldrb w0, [x1]          // 读取单字节，然后组合
ldrb w2, [x1, #1]
orr w0, w0, w2, lsl #8
// ...
```

**Android 行为：**
- 用户态：通常陷入内核处理，性能差
- 内核态：直接崩溃 (SIGBUS)

### 栈对齐

```asm
// ARM64 ABI 要求：SP 必须 16 字节对齐

// 错误：
sub sp, sp, #12        // SP 不再 16 字节对齐
bl some_func           // 可能崩溃！

// 正确：
sub sp, sp, #16        // 保持对齐
bl some_func
```

## 实战场景

### Lab 1: 数组遍历

**目标：** 使用后索引遍历数组

```asm
// array_sum.s
.global _start
.section .text

_start:
    adr x1, array        // 数组地址
    mov x2, #5           // 元素数量
    mov x0, #0           // 累加器

loop:
    ldr x3, [x1], #8     // 读取并移动到下一个
    add x0, x0, x3       // 累加
    subs x2, x2, #1      // 计数器减一
    b.ne loop            // 如果不为零，继续

    // x0 现在是总和 (1+2+3+4+5 = 15)
    mov x8, #93
    svc #0

.section .data
array:
    .quad 1, 2, 3, 4, 5
```

**编译运行：**
```bash
aarch64-linux-gnu-as -o array_sum.o array_sum.s
aarch64-linux-gnu-ld -o array_sum array_sum.o
qemu-aarch64 ./array_sum ; echo $?
# 输出: 15
```

### Lab 2: 结构体访问

**目标：** 模拟结构体字段访问

```asm
// struct_access.s
// 模拟:
// struct person {
//     long age;      // offset 0
//     long height;   // offset 8
//     long weight;   // offset 16
// };

.global _start
.section .text

_start:
    adr x1, person

    // 读取所有字段
    ldr x2, [x1]         // age
    ldr x3, [x1, #8]     // height
    ldr x4, [x1, #16]    // weight
    
    // 计算 age + height + weight
    add x0, x2, x3
    add x0, x0, x4
    
    // 退出 (返回值 = 25 + 170 + 70 = 265)
    mov x8, #93
    svc #0

.section .data
person:
    .quad 25             // age
    .quad 170            // height
    .quad 70             // weight
```

### Lab 3: 矩阵元素访问

**目标：** 计算二维数组偏移

```asm
// matrix.s
// 访问 matrix[row][col]
// matrix 是 4x4 的 long 数组

.global _start
.section .text

_start:
    adr x0, matrix       // 基址
    mov x1, #2           // row = 2
    mov x2, #3           // col = 3
    
    // 计算偏移: (row * 4 + col) * 8
    mov x3, #4           // 列数
    mul x4, x1, x3       // row * 4
    add x4, x4, x2       // + col
    ldr x0, [x0, x4, lsl #3]  // *(base + offset * 8)
    
    // x0 = matrix[2][3] = 11
    mov x8, #93
    svc #0

.section .data
matrix:
    .quad 0, 1, 2, 3     // row 0
    .quad 4, 5, 6, 7     // row 1
    .quad 8, 9, 10, 11   // row 2
    .quad 12, 13, 14, 15 // row 3
```

## 常见陷阱

### ❌ 陷阱 1: 偏移范围

```asm
// 错误：立即数偏移超出范围
ldr x0, [x1, #5000]    // 错误！超过 4096

// 正确：使用寄存器偏移
mov x2, #5000
ldr x0, [x1, x2]
```

### ❌ 陷阱 2: 符号扩展错误

```asm
// C 代码: array[i] 其中 i 是 signed int

// 错误：使用零扩展
ldr x0, [x1, w2, UXTW #3]   // 如果 i < 0，会变成大正数！

// 正确：使用符号扩展
ldr x0, [x1, w2, SXTW #3]   // 正确处理负索引
```

**安全影响：** 这类错误可能导致越界读写

### ❌ 陷阱 3: 后索引误用

```asm
// 错误理解：后索引
ldr x0, [x1, #8]       // x0 = *(x1+8), x1 不变
ldr x0, [x1], #8       // x0 = *(x1), x1 += 8  ← 不同！

// 如果误用，会访问错误地址
```

### ❌ 陷阱 4: 成对加载对齐

```asm
// ldp 要求 16 字节对齐
ldp x0, x1, [x2]       // x2 必须 16 字节对齐

// 如果 x2 = 0x1008 (8 字节对齐但非 16 字节)
// 可能崩溃
```

## Android 场景

### Binder 结构体访问

```c
// kernel/drivers/android/binder.c
struct binder_transaction_data {
    union {
        __u32 handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;  // offset 8
    __u32 code;               // offset 16
    // ...
};
```

**反汇编：**
```asm
ldr x0, [x19]          // transaction->target
ldr x1, [x19, #8]      // transaction->cookie
ldr w2, [x19, #16]     // transaction->code
```

### CVE 相关

## 深入阅读

**推荐资源：**
- [ARM64 Addressing Modes](https://developer.arm.com/documentation/102374/latest/Loads-and-stores---addressing)
- ARM Architecture Reference Manual - Chapter C1.4

**相关章节：**
- [00 - ARM64 基础](./00-arm64-basics.md) - 基本指令
- [02 - 调用约定](./02-calling-conventions.md) - 栈帧中的内存访问

## 下一步

[02 - 调用约定](./02-calling-conventions.md) — 理解函数调用机制
