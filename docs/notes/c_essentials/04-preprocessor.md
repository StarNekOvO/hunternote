# 04 - 预处理器

编译前的文本处理：宏、条件编译、文件包含。

---

## 概念速览

**预处理器是什么？**
编译器的第一阶段，在真正编译前进行文本替换。

**为什么需要它？**
- 代码复用（宏定义）
- 跨平台兼容（条件编译）
- 模块化（头文件包含）

**预处理 vs 编译：**

```
源代码.c
    ↓ 预处理 (cpp)
展开后的代码.i    ← 所有 #define, #include 已处理
    ↓ 编译 (cc1)
汇编代码.s
```

```bash
# 只做预处理，查看结果
gcc -E file.c -o file.i
```

---

## 核心概念

### #define 宏

```c
// 简单宏
#define PI 3.14159
#define MAX_SIZE 1024

// 使用
double area = PI * r * r;
char buffer[MAX_SIZE];
```

**预处理后：**
```c
double area = 3.14159 * r * r;
char buffer[1024];
```

### 带参数的宏

```c
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE(x) ((x) * (x))

int m = MAX(3, 5);  // → ((3) > (5) ? (3) : (5))
```

> [!CAUTION]
> **为什么要加这么多括号？**

```c
#define BAD_SQUARE(x) x * x

int a = BAD_SQUARE(1 + 2);
// 展开为: 1 + 2 * 1 + 2 = 5 (错误！)

int b = SQUARE(1 + 2);
// 展开为: ((1 + 2) * (1 + 2)) = 9 (正确)
```

### 宏的副作用

```c
#define DOUBLE(x) ((x) + (x))

int i = 5;
int j = DOUBLE(i++);
// 展开为: ((i++) + (i++))
// i 被递增两次！j 的值是 11，i 的值是 7
```

> [!WARNING]
> 宏参数有副作用时非常危险。

### 内联函数 vs 宏

**C99 引入 `inline`，很多情况下替代宏：**

```c
// 宏版本
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// 内联函数版本
static inline int max(int a, int b) {
    return a > b ? a : b;
}
```

| 特性 | 宏 | inline 函数 |
|------|-----|------------|
| 类型检查 | ✗ | ✓ |
| 调试 | 困难 | 正常 |
| 副作用 | 危险 | 安全 |
| 适用范围 | 更广（任意类型）| 需要特定类型 |

---

## 基础用法

### 字符串化 (#)

```c
#define STRINGIFY(x) #x
#define PRINT_VAR(x) printf(#x " = %d\n", x)

int count = 42;
PRINT_VAR(count);  // → printf("count" " = %d\n", count);
// 输出: count = 42
```

### 连接 (##)

```c
#define CONCAT(a, b) a##b

int xy = 42;
printf("%d\n", CONCAT(x, y));  // → printf("%d\n", xy);
// 输出: 42

// 常见用途：生成函数名
#define DECLARE_LIST(type) \
    struct type##_list { \
        type *head; \
        int count; \
    }

DECLARE_LIST(int);  // 生成 struct int_list
```

### 条件编译

```c
#define DEBUG 1

#if DEBUG
    printf("Debug: x = %d\n", x);
#endif

// 或者
#ifdef DEBUG
    printf("Debug mode\n");
#else
    printf("Release mode\n");
#endif

// 未定义检查
#ifndef BUFFER_SIZE
    #define BUFFER_SIZE 1024
#endif
```

### 头文件保护

```c
// header.h
#ifndef HEADER_H
#define HEADER_H

// 头文件内容

#endif  // HEADER_H
```

**或者使用（非标准但广泛支持）：**
```c
#pragma once

// 头文件内容
```

---

## 进阶用法

### 多行宏

```c
#define SWAP(a, b) do { \
    typeof(a) _tmp = (a); \
    (a) = (b);            \
    (b) = _tmp;           \
} while (0)

// 使用
int x = 1, y = 2;
SWAP(x, y);  // x=2, y=1
```

**为什么用 `do { } while (0)`？**

```c
if (condition)
    SWAP(x, y);  // 如果没有 do-while 包装，分号会导致问题
else
    other_code();
```

### 可变参数宏

```c
#define LOG(fmt, ...) printf("[LOG] " fmt "\n", ##__VA_ARGS__)

LOG("Hello");           // → printf("[LOG] " "Hello" "\n");
LOG("x = %d", x);       // → printf("[LOG] " "x = %d" "\n", x);
```

> [!NOTE]
> `##__VA_ARGS__` 使得当可变参数为空时，移除前面的逗号。

### 预定义宏

| 宏 | 含义 |
|-----|------|
| `__FILE__` | 当前文件名 |
| `__LINE__` | 当前行号 |
| `__func__` | 当前函数名 |
| `__DATE__` | 编译日期 |
| `__TIME__` | 编译时间 |

```c
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERT failed: %s at %s:%d\n", \
                #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

ASSERT(x > 0);
// 输出: ASSERT failed: x > 0 at test.c:42
```

---

## 实战场景

### Lab 1: 通用容器宏

```c
// Linux 内核风格：获取包含结构体
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

struct item {
    int data;
    struct list_head node;
};

struct list_head *pos = get_some_node();
struct item *item = container_of(pos, struct item, node);
```

**这是 Linux 内核最重要的宏之一！**

### Lab 2: 内核 printk 级别

```c
// 简化版内核日志
#define KERN_ERR    "<3>"
#define KERN_INFO   "<6>"
#define KERN_DEBUG  "<7>"

#define pr_err(fmt, ...)   printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)  printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)

// 使用
pr_err("Error: %d\n", code);
```

### Lab 3: 条件编译跨平台

```c
#ifdef __linux__
    #include <linux/types.h>
    #define OS_NAME "Linux"
#elif defined(__ANDROID__)
    #include <android/log.h>
    #define OS_NAME "Android"
#elif defined(_WIN32)
    #include <windows.h>
    #define OS_NAME "Windows"
#else
    #define OS_NAME "Unknown"
#endif

printf("Running on %s\n", OS_NAME);
```

### Lab 4: 编译时断言

```c
// C11 引入 _Static_assert
_Static_assert(sizeof(int) == 4, "int must be 4 bytes");

// 旧代码的技巧
#define COMPILE_TIME_ASSERT(cond) \
    typedef char static_assertion_##__LINE__[(cond) ? 1 : -1]

COMPILE_TIME_ASSERT(sizeof(int) == 4);
// 如果条件为假，数组大小为 -1，编译失败
```

---

## 常见陷阱

### ❌ 陷阱 1: 宏参数未加括号

```c
#define DOUBLE(x) x * 2

int a = DOUBLE(1 + 2);  // 1 + 2 * 2 = 5 (错误)
```

### ❌ 陷阱 2: 副作用多次求值

```c
#define ABS(x) ((x) < 0 ? -(x) : (x))

int a = ABS(i++);  // i 可能递增两次
```

### ❌ 陷阱 3: 头文件循环包含

```c
// a.h
#include "b.h"

// b.h
#include "a.h"  // 循环！
```

**解决：使用头文件保护 + 前向声明**

### ❌ 陷阱 4: 分号问题

```c
#define LOG(x) printf("%d\n", x);  // 尾部分号

if (condition)
    LOG(x);  // 展开后有两个分号
else
    other();  // 编译错误！
```

---

## 深入阅读

**推荐资源：**
- [GCC Preprocessor](https://gcc.gnu.org/onlinedocs/cpp/)
- [Linux Kernel Macros](https://www.kernel.org/doc/html/latest/process/coding-style.html#macros-enums-and-rtl)

**相关章节：**
- [05 - 内核开发](./05-kernel-style.md) - 内核常用宏

---

## 下一步

[05 - 内核开发](./05-kernel-style.md) - 进入 Linux 内核世界
