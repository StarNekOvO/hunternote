# 03 - Inline 汇编

在 C 和 Rust 中嵌入 ARM64 汇编。


## 概念速览

**为什么需要 Inline 汇编？**
- 访问特殊寄存器 (CPSR, 系统寄存器)
- 实现原子操作
- 性能关键路径优化
- 绕过编译器优化

**安全研究场景：**
- 编写 exploit 中的关键片段
- 访问处理器特性 (PAC, BTI)
- Hook 代码中的原子操作


## GCC 扩展汇编语法

### 基本格式

```c
asm [volatile] (
    "assembly template"
    : output operands    /* 可选 */
    : input operands     /* 可选 */
    : clobbers           /* 可选 */
);
```

### 最简单的例子

```c
// 空操作
asm("nop");

// 多条指令
asm(
    "add x0, x0, #1\n\t"
    "add x1, x1, #1"
);
```

### 输出操作数

```c
int result;

asm(
    "mov %0, #42"        // %0 → result
    : "=r"(result)       // output: r=寄存器, =表示只写
);

printf("%d\n", result);  // 42
```

**约束符：**

| 约束 | 含义 |
|------|------|
| `r` | 通用寄存器 |
| `m` | 内存位置 |
| `i` | 立即数 |
| `=` | 只写 |
| `+` | 读写 |
| `&` | 早期覆盖 |

### 输入操作数

```c
int a = 10, b = 20, sum;

asm(
    "add %0, %1, %2"
    : "=r"(sum)          // 输出
    : "r"(a), "r"(b)     // 输入
);

printf("%d\n", sum);     // 30
```

### 读写操作数

```c
int value = 5;

asm(
    "add %0, %0, #10"    // value += 10
    : "+r"(value)        // + 表示读写
);

printf("%d\n", value);   // 15
```

### Clobber 列表

```c
int result;

asm(
    "mov x1, #100\n\t"   // 使用了 x1
    "add %0, x1, #5"
    : "=r"(result)
    :
    : "x1"               // 告诉编译器 x1 被修改
);
```

**常用 clobber：**

| Clobber | 含义 |
|---------|------|
| `"memory"` | 内存被修改 |
| `"cc"` | 条件码被修改 |
| `"x0"` - `"x30"` | 特定寄存器 |

### volatile

```c
// 防止编译器优化掉
asm volatile("nop");

// 副作用明确时必须使用
asm volatile(
    "str %1, [%0]"
    :
    : "r"(addr), "r"(value)
    : "memory"
);
```


## 实用案例

### 读取系统寄存器

```c
// 读取 MIDR_EL1 (Main ID Register)
static inline uint64_t read_midr(void) {
    uint64_t midr;
    asm("mrs %0, midr_el1" : "=r"(midr));
    return midr;
}

// 读取当前异常级别
static inline uint64_t get_current_el(void) {
    uint64_t el;
    asm("mrs %0, CurrentEL" : "=r"(el));
    return (el >> 2) & 3;
}
```

### 原子操作

```c
// 原子加法 (使用 LDXR/STXR)
static inline int atomic_add(int *ptr, int val) {
    int result, tmp;
    
    asm volatile(
        "1: ldxr    %w0, [%2]\n"       // 独占加载
        "   add     %w0, %w0, %w3\n"   // 加法
        "   stxr    %w1, %w0, [%2]\n"  // 独占存储
        "   cbnz    %w1, 1b"           // 如果失败，重试
        : "=&r"(result), "=&r"(tmp)
        : "r"(ptr), "r"(val)
        : "memory"
    );
    
    return result;
}
```

### CAS (Compare-And-Swap)

```c
static inline int cas(int *ptr, int old, int new) {
    int result, tmp;
    
    asm volatile(
        "1: ldxr    %w0, [%2]\n"
        "   cmp     %w0, %w3\n"
        "   b.ne    2f\n"
        "   stxr    %w1, %w4, [%2]\n"
        "   cbnz    %w1, 1b\n"
        "2:"
        : "=&r"(result), "=&r"(tmp)
        : "r"(ptr), "r"(old), "r"(new)
        : "memory", "cc"
    );
    
    return result;
}
```

### 内存屏障

```c
// 数据内存屏障
static inline void dmb(void) {
    asm volatile("dmb sy" ::: "memory");
}

// 数据同步屏障
static inline void dsb(void) {
    asm volatile("dsb sy" ::: "memory");
}

// 指令同步屏障
static inline void isb(void) {
    asm volatile("isb" ::: "memory");
}
```


## Rust asm!

### 基本语法

```rust
use std::arch::asm;

fn main() {
    let result: u64;
    
    unsafe {
        asm!(
            "mov {}, #42",
            out(reg) result,
        );
    }
    
    println!("{}", result);  // 42
}
```

### 输入输出

```rust
fn add(a: u64, b: u64) -> u64 {
    let result: u64;
    
    unsafe {
        asm!(
            "add {0}, {1}, {2}",
            out(reg) result,
            in(reg) a,
            in(reg) b,
        );
    }
    
    result
}
```

### 指定寄存器

```rust
fn syscall_exit(code: u64) -> ! {
    unsafe {
        asm!(
            "svc #0",
            in("x8") 93u64,    // exit syscall
            in("x0") code,
            options(noreturn),
        );
    }
}
```

### 原子操作

```rust
fn atomic_add(ptr: *mut i32, val: i32) -> i32 {
    let result: i32;
    let tmp: i32;
    
    unsafe {
        asm!(
            "2:",
            "   ldxr {result:w}, [{ptr}]",
            "   add {result:w}, {result:w}, {val:w}",
            "   stxr {tmp:w}, {result:w}, [{ptr}]",
            "   cbnz {tmp:w}, 2b",
            result = out(reg) result,
            tmp = out(reg) tmp,
            ptr = in(reg) ptr,
            val = in(reg) val,
            options(nostack),
        );
    }
    
    result
}
```


## 实战场景

### Lab 1: 读取 CPU 特性

**目标：** 读取 ARM64 CPU 特性

```c
// cpu_features.c
#include <stdio.h>
#include <stdint.h>

static inline uint64_t read_id_aa64isar0(void) {
    uint64_t val;
    asm("mrs %0, id_aa64isar0_el1" : "=r"(val));
    return val;
}

int main() {
    uint64_t isar0 = read_id_aa64isar0();
    
    // 检查 AES 支持
    int aes = (isar0 >> 4) & 0xF;
    printf("AES support: %d\n", aes);
    
    // 检查 SHA 支持
    int sha1 = (isar0 >> 8) & 0xF;
    printf("SHA1 support: %d\n", sha1);
    
    return 0;
}
```

**编译：**
```bash
aarch64-linux-gnu-gcc -o cpu_features cpu_features.c
```

### Lab 2: 自旋锁实现

**目标：** 使用 inline asm 实现自旋锁

```c
// spinlock.c
#include <stdint.h>

typedef struct {
    volatile uint32_t lock;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock) {
    uint32_t tmp;
    
    asm volatile(
        "   sevl\n"
        "1: wfe\n"
        "   ldaxr   %w0, [%1]\n"
        "   cbnz    %w0, 1b\n"
        "   stxr    %w0, %w2, [%1]\n"
        "   cbnz    %w0, 1b"
        : "=&r"(tmp)
        : "r"(&lock->lock), "r"(1)
        : "memory"
    );
}

static inline void spin_unlock(spinlock_t *lock) {
    asm volatile(
        "stlr   wzr, [%0]"
        :
        : "r"(&lock->lock)
        : "memory"
    );
}
```

### Lab 3: Rust 系统调用

**目标：** 在 Rust 中直接发起系统调用

```rust
// syscall.rs
use std::arch::asm;

fn write(fd: u64, buf: *const u8, count: u64) -> i64 {
    let result: i64;
    
    unsafe {
        asm!(
            "svc #0",
            in("x8") 64u64,    // write syscall number
            in("x0") fd,
            in("x1") buf,
            in("x2") count,
            lateout("x0") result,
            options(nostack),
        );
    }
    
    result
}

fn main() {
    let msg = b"Hello from Rust asm!\n";
    let ret = write(1, msg.as_ptr(), msg.len() as u64);
    println!("write returned: {}", ret);
}
```


## 常见陷阱

### ❌ 陷阱 1: 忘记 volatile

```c
// 错误：可能被优化掉
int x = 0;
for (int i = 0; i < 1000; i++) {
    asm("nop");  // 可能被删除！
}

// 正确
for (int i = 0; i < 1000; i++) {
    asm volatile("nop");
}
```

### ❌ 陷阱 2: 忘记 memory clobber

```c
// 错误：编译器可能重排内存访问
*ptr = 1;
asm("dmb sy");   // 没有 memory clobber
value = *other_ptr;  // 可能在 dmb 之前执行！

// 正确
*ptr = 1;
asm volatile("dmb sy" ::: "memory");
value = *other_ptr;  // 保证在 dmb 之后
```

### ❌ 陷阱 3: 约束符错误

```c
// 错误：同一寄存器用于输出和 clobber
int result;
asm(
    "mov %0, x0"
    : "=r"(result)
    :
    : "x0"  // 可能和 %0 冲突！
);

// 正确：使用 early clobber
asm(
    "mov x0, #42\n\t"
    "mov %0, x0"
    : "=&r"(result)  // & = early clobber
    :
    : "x0"
);
```

### ❌ 陷阱 4: 寄存器大小不匹配

```c
int32_t val;

// 错误：用 w 寄存器写 64 位
asm("ldr %0, [%1]"  // 默认是 x 寄存器
    : "=r"(val)     // 但 val 是 32 位
    : "r"(ptr));

// 正确：指定 w 寄存器
asm("ldr %w0, [%1]"
    : "=r"(val)
    : "r"(ptr));
```


## Android 场景

### Bionic 原子操作

```c
// bionic/libc/arch-arm64/bionic/atomics.h
static inline int __bionic_cmpxchg(int32_t old_value,
                                    int32_t new_value,
                                    volatile int32_t *ptr) {
    int32_t prev;
    int status;
    
    __asm__ __volatile__(
        "   prfm    pstl1strm, [%3]\n"
        "1: ldxr    %w0, [%3]\n"
        "   cmp     %w0, %w4\n"
        "   b.ne    2f\n"
        "   stxr    %w1, %w5, [%3]\n"
        "   cbnz    %w1, 1b\n"
        "2:"
        : "=&r"(prev), "=&r"(status), "+m"(*ptr)
        : "r"(ptr), "Ir"(old_value), "r"(new_value)
        : "cc"
    );
    
    return prev != old_value;
}
```

### 内核屏障

```c
// arch/arm64/include/asm/barrier.h
#define smp_mb()    asm volatile("dmb ish" ::: "memory")
#define smp_wmb()   asm volatile("dmb ishst" ::: "memory")
#define smp_rmb()   asm volatile("dmb ishld" ::: "memory")
```


## 深入阅读

**推荐资源：**
- [GCC Inline Assembly HOWTO](https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html)
- [Rust asm! Documentation](https://doc.rust-lang.org/reference/inline-assembly.html)

**相关章节：**
- [02 - 调用约定](./02-calling-conventions.md) - 寄存器使用
- [06 - 内存破坏](./06-memory-corruption.md) - 原子操作漏洞


## 下一步

[04 - 调试技巧](./04-debugging-asm.md) — 用 GDB 和 Ghidra 分析汇编
