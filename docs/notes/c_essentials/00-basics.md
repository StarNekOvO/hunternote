# 00 - 基础语法

C 语言核心语法快速回顾，为后续深入学习打基础。

---

## 概念速览

**C 是什么？**
1972 年诞生的系统编程语言，Unix/Linux/Android 的基石。

**为什么学 C？**
- Android 内核、驱动、HAL 全是 C
- 理解底层是安全研究的前提
- 其他语言的运行时也是 C 写的

**与 Python 的关键区别：**

| 特性 | Python | C |
|------|--------|---|
| 类型 | 动态 | 静态 |
| 内存 | 自动 GC | 手动管理 |
| 编译 | 解释执行 | 编译为机器码 |
| 速度 | 慢 | 快 |

---

## 核心概念

### 编译流程

```
源代码 (.c)
    ↓  预处理 (cpp)
预处理后代码 (.i)
    ↓  编译 (cc1)
汇编代码 (.s)
    ↓  汇编 (as)
目标文件 (.o)
    ↓  链接 (ld)
可执行文件
```

```bash
# 一步完成
gcc hello.c -o hello

# 分步执行
gcc -E hello.c -o hello.i  # 预处理
gcc -S hello.i -o hello.s  # 编译
gcc -c hello.s -o hello.o  # 汇编
gcc hello.o -o hello       # 链接
```

### 为什么 C 需要编译？

**对比 Python：**
```python
# Python: 解释执行
x = 1 + 2  # 运行时才知道 x 是什么类型
```

```c
// C: 编译时确定一切
int x = 1 + 2;  // 编译器生成直接操作寄存器的代码
```

**编译的好处：**
1. **速度**：直接执行机器码，无运行时开销
2. **优化**：编译器可以做大量优化
3. **类型安全**：编译期发现类型错误

---

## 基础用法

### 数据类型

```c
// 整数类型
char    c = 'A';        // 1 byte, -128 ~ 127
short   s = 100;        // 2 bytes
int     i = 42;         // 4 bytes (通常)
long    l = 100000L;    // 4 或 8 bytes (平台相关)

// 浮点类型
float   f = 3.14f;      // 4 bytes
double  d = 3.14159;    // 8 bytes

// 无符号
unsigned int ui = 4294967295U;  // 0 ~ 4,294,967,295
```

**为什么有这么多类型？**

C 设计目标是**接近硬件**，不同类型对应不同寄存器大小：
- `char`: 8 位寄存器
- `int`: CPU 最高效的整数大小
- `long`: 指针大小（32 位或 64 位）

### 固定宽度类型 (推荐)

```c
#include <stdint.h>

int8_t   i8  = -128;
uint8_t  u8  = 255;
int32_t  i32 = -2147483648;
uint32_t u32 = 4294967295U;
int64_t  i64 = -9223372036854775808LL;
```

> [!TIP]
> 在 Android/内核代码中，推荐使用 `int32_t` 等固定宽度类型，避免跨平台问题。

### 变量与常量

```c
// 变量
int count = 0;
count = 10;  // 可修改

// 常量
const int MAX_SIZE = 100;
// MAX_SIZE = 200;  // 编译错误！

// 宏常量
#define BUFFER_SIZE 1024
```

**`const` vs `#define`：**

| 特性 | const | #define |
|------|-------|---------|
| 类型检查 | ✓ | ✗ |
| 调试可见 | ✓ | ✗ |
| 作用域 | 有 | 无 |

### 控制流

```c
// if-else
if (x > 0) {
    printf("positive\n");
} else if (x < 0) {
    printf("negative\n");
} else {
    printf("zero\n");
}

// switch
switch (value) {
    case 1:
        printf("one\n");
        break;
    case 2:
    case 3:  // fall-through
        printf("two or three\n");
        break;
    default:
        printf("other\n");
}
```

> [!CAUTION]
> 忘记 `break` 是常见 bug！会导致意外的 fall-through。

### 循环

```c
// for 循环
for (int i = 0; i < 10; i++) {
    printf("%d\n", i);
}

// while 循环
int i = 0;
while (i < 10) {
    printf("%d\n", i);
    i++;
}

// do-while (至少执行一次)
do {
    printf("执行至少一次\n");
} while (0);  // 条件为假，只执行一次
```

### 函数

```c
// 函数定义
int add(int a, int b) {
    return a + b;
}

// 无返回值
void print_hello(void) {
    printf("Hello\n");
}

// void 参数表示无参数（C 语言中重要！）
void foo(void);   // 不接受参数
void bar();       // 接受任意参数 (危险!)
```

**为什么 `void` 很重要？**

```c
// 在 C 中 (不是 C++)
void foo() { }      // 可以传任意参数
void bar(void) { }  // 严格不接受参数

foo(1, 2, 3);  // 编译通过！
bar(1, 2, 3);  // 编译错误
```

---

## 进阶用法

### 作用域与存储类

```c
int global_var = 0;              // 全局变量，整个程序可见

static int file_scope = 0;       // 静态全局，仅本文件可见

void func(void) {
    int local = 0;               // 局部变量，栈上
    static int persistent = 0;   // 静态局部，保持值
    
    persistent++;  // 每次调用递增
    printf("%d\n", persistent);  // 1, 2, 3, ...
}
```

### 类型转换

```c
// 隐式转换 (小 → 大)
int i = 10;
double d = i;  // OK, 10.0

// 显式转换 (可能丢失精度)
double pi = 3.14159;
int truncated = (int)pi;  // 3

// 危险转换
unsigned int u = -1;  // 变成 4294967295！
```

> [!WARNING]
> 有符号与无符号混用是 bug 温床，也是安全漏洞来源。

---

## 实战场景

### Lab 1: Hello World

```c
#include <stdio.h>

int main(void) {
    printf("Hello, Android Security!\n");
    return 0;
}
```

**编译运行：**
```bash
gcc hello.c -o hello
./hello
```

### Lab 2: 命令行参数

```c
#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("参数个数: %d\n", argc);
    
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    
    return 0;
}
```

```bash
./program arg1 arg2 arg3
# 输出:
# 参数个数: 4
# argv[0] = ./program
# argv[1] = arg1
# argv[2] = arg2
# argv[3] = arg3
```

### Lab 3: 简单计算器

```c
#include <stdio.h>

int main(void) {
    char op;
    double a, b, result;
    
    printf("输入表达式 (如 3 + 4): ");
    scanf("%lf %c %lf", &a, &op, &b);
    
    switch (op) {
        case '+': result = a + b; break;
        case '-': result = a - b; break;
        case '*': result = a * b; break;
        case '/':
            if (b != 0) {
                result = a / b;
            } else {
                printf("除零错误!\n");
                return 1;
            }
            break;
        default:
            printf("未知运算符\n");
            return 1;
    }
    
    printf("%.2f %c %.2f = %.2f\n", a, op, b, result);
    return 0;
}
```

---

## 常见陷阱

### ❌ 陷阱 1: 整数溢出

```c
int a = 2147483647;  // INT_MAX
int b = a + 1;       // 溢出！变成 -2147483648
```

**安全问题：** 整数溢出是 CVE 常见原因。

### ❌ 陷阱 2: 有符号/无符号混用

```c
unsigned int u = 1;
int s = -1;

if (s < u) {
    printf("s < u\n");
} else {
    printf("s >= u\n");  // 实际输出这个！
}
// -1 被转换为 unsigned int = 4294967295
```

### ❌ 陷阱 3: 忘记初始化

```c
int x;
printf("%d\n", x);  // 未定义行为！可能是任意值
```

### ❌ 陷阱 4: 数组越界

```c
int arr[5];
arr[5] = 0;  // 越界！但 C 不检查
```

---

## 深入阅读

**推荐资源：**
- [Beej's Guide to C](https://beej.us/guide/bgc/) - 最佳入门
- [C Programming Language (K&R)](https://en.wikipedia.org/wiki/The_C_Programming_Language) - 经典

**相关章节：**
- [01 - 指针与内存](./01-pointers.md) - C 的核心
- [02 - 内存管理](./02-memory.md) - 堆栈与动态分配

---

## 下一步

[01 - 指针与内存](./01-pointers.md) - C 语言的灵魂
