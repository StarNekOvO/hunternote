# 01 - 指针与内存

指针是 C 语言的灵魂，也是理解内核代码和安全漏洞的关键。

---

## 概念速览

**指针是什么？** 存储内存地址的变量。

**为什么需要它？**
- 直接操作内存（OS/驱动必需）
- 函数间高效传递大数据
- 动态数据结构（链表、树）

**Android 场景：**
```c
// Binder 通信的核心：指针传递数据
binder_transaction_data *tr = &bwr->tr;
```

---

## 核心概念

### 什么是指针

指针是一个变量，它的值是另一个变量的**内存地址**。

```
┌──────────────┐     ┌──────────────┐
│   ptr        │ ──→ │   value      │
│  0x7ffd1234  │     │     42       │
│  (8 bytes)   │     │  (4 bytes)   │
└──────────────┘     └──────────────┘
   地址: 0x100          地址: 0x7ffd1234
```

```c
int value = 42;
int *ptr = &value;  // ptr 存储 value 的地址

printf("value = %d\n", value);    // 42
printf("&value = %p\n", &value);  // 0x7ffd1234
printf("ptr = %p\n", ptr);        // 0x7ffd1234 (相同)
printf("*ptr = %d\n", *ptr);      // 42 (解引用)
```

### 为什么 C 需要指针？

**对比其他语言：**

| 语言 | 内存访问 | 特点 |
|------|----------|------|
| **C** | 裸指针 | 完全控制，完全责任 |
| **Java** | 引用（隐藏指针） | 安全但不能直接操作内存 |
| **Python** | 引用（更隐藏） | 一切皆对象，无法接触地址 |
| **Rust** | 引用 + 所有权 | 编译期安全检查 |

**为什么 C 选择暴露指针？**

1. **历史背景**：C 诞生于 1972 年，目标是写 Unix 内核
2. **设计哲学**：程序员知道自己在做什么
3. **性能需求**：零抽象开销

**Android Native 层为什么离不开指针？**

```c
// 1. 与硬件直接交互
volatile uint32_t *reg = (uint32_t *)0xFE200000;
*reg = 0x01;  // 直接写寄存器

// 2. 高效传递大结构
void handle_transaction(binder_transaction_data *tr) {
    // 传指针 (8 bytes) vs 传结构体 (几百 bytes)
}

// 3. 内核/用户态数据传递
copy_from_user(kernel_buf, user_ptr, size);
```

### 解引用：`*` 的含义

```c
int value = 42;
int *ptr = &value;
int got = *ptr;  // 解引用：取 ptr 指向地址的值
```

**底层原理：**
```
*ptr 对应汇编：
    ldr r0, [r1]   ; ARM: 从 r1 存的地址读取值到 r0
```

> [!TIP]
> `*` 读作"取值"——去这个地址，取出里面的值。

### 指针 vs C++ 引用 vs Rust 引用

| 特性 | C 指针 | C++ 引用 | Rust 引用 |
|------|--------|----------|-----------|
| 可空 | ✓ (NULL) | ✗ | ✗ |
| 可重新赋值 | ✓ | ✗ | ✓ |
| 运算 | ✓ (+, -) | ✗ | ✗ |
| 安全检查 | ✗ | 部分 | ✓ (编译期) |

---

## 基础用法

### 声明与初始化

```c
int value = 42;
int *ptr;           // 声明（未初始化，危险！）
ptr = &value;       // 赋值

// 更好的写法：声明时初始化
int *ptr2 = &value;
int *ptr3 = NULL;   // 明确初始化为空
```

> [!CAUTION]
> 未初始化的指针是**野指针**，解引用会导致未定义行为。

### 指针运算

C 的特色：指针可以做算术运算。

```c
int arr[5] = {10, 20, 30, 40, 50};
int *p = arr;  // p 指向 arr[0]

printf("%d\n", *p);       // 10
printf("%d\n", *(p + 1)); // 20
printf("%d\n", *(p + 2)); // 30

p++;  // p 移动 sizeof(int) = 4 字节
printf("%d\n", *p);  // 20
```

**为什么 `p + 1` 不是移动 1 字节？**

编译器知道 `p` 是 `int *`，所以 `p + 1` 自动乘以 `sizeof(int)`。

```c
// 等价于
(char *)p + 1 * sizeof(int)
```

**这个设计的好处：**
- 遍历数组时不用关心元素大小
- 代码更简洁、更不易出错

### 数组与指针的关系

```c
int arr[5] = {1, 2, 3, 4, 5};

// 以下三种等价
printf("%d\n", arr[2]);
printf("%d\n", *(arr + 2));
printf("%d\n", 2[arr]);  // 合法！但别这么写
```

**为什么 `2[arr]` 合法？**

C 标准定义 `a[i]` 等价于 `*(a + i)`，而加法是交换的。

> [!NOTE]
> 数组名是**常量指针**，指向首元素。不能 `arr = something`。

### 函数参数传递

```c
// 值传递（失败）
void swap_wrong(int a, int b) {
    int tmp = a;
    a = b;
    b = tmp;
}  // a, b 是副本，原值不变

// 指针传递（成功）
void swap_right(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int x = 1, y = 2;
swap_wrong(x, y);   // x=1, y=2 (没变)
swap_right(&x, &y); // x=2, y=1 (交换了)
```

---

## 进阶用法

### 多级指针

**二级指针：指向指针的指针**

```c
int value = 42;
int *p = &value;
int **pp = &p;

printf("%d\n", **pp);  // 42
```

**什么时候需要二级指针？**

当你需要在函数中**修改指针本身**时：

```c
// 场景：让函数分配内存并返回
void allocate(int **ptr) {
    *ptr = malloc(sizeof(int));
    **ptr = 100;
}

int main() {
    int *p = NULL;
    allocate(&p);     // 传 p 的地址
    printf("%d\n", *p);  // 100
    free(p);
}
```

**Android 内核中的例子：**

```c
// drivers/android/binder.c
int binder_alloc_buf(struct binder_alloc *alloc,
                     struct binder_buffer **buffer,  // 二级指针
                     size_t size) {
    *buffer = kzalloc(sizeof(**buffer), GFP_KERNEL);
    // ...
}
```

### 函数指针

**声明语法：**

```c
// 返回类型 (*指针名)(参数类型)
int (*func_ptr)(int, int);
```

**使用示例：**

```c
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }

int (*op)(int, int);  // 声明函数指针

op = add;
printf("%d\n", op(3, 2));  // 5

op = sub;
printf("%d\n", op(3, 2));  // 1
```

**实际应用：回调函数**

```c
// Linux 内核：驱动注册操作函数
struct file_operations {
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    int (*open)(struct inode *, struct file *);
    // ...
};

// 驱动实现自己的函数
static ssize_t my_read(struct file *f, char __user *buf, ...) {
    // 具体实现
}

// 注册
static struct file_operations my_fops = {
    .read = my_read,  // 函数指针赋值
    // ...
};
```

### void 指针

**通用指针类型：** 可以指向任何类型。

```c
void *vp;
int i = 42;
float f = 3.14;

vp = &i;  // OK
vp = &f;  // OK

// 使用前必须转换
int *ip = (int *)vp;
printf("%d\n", *ip);
```

**典型用途：`malloc` 返回 `void *`**

```c
int *arr = (int *)malloc(10 * sizeof(int));
```

---

## 实战场景

### Lab 1: 实现字符串长度函数

```c
size_t my_strlen(const char *s) {
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return p - s;  // 指针相减 = 元素个数
}

// 测试
printf("%zu\n", my_strlen("hello"));  // 5
```

**要点：**
- `const char *` 表示不会修改内容
- 指针相减得到距离（自动除以元素大小）

### Lab 2: 简单链表

```c
struct node {
    int data;
    struct node *next;  // 自引用
};

struct node *create_node(int value) {
    struct node *n = malloc(sizeof(struct node));
    n->data = value;
    n->next = NULL;
    return n;
}

void print_list(struct node *head) {
    struct node *current = head;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

// 使用
struct node *head = create_node(1);
head->next = create_node(2);
head->next->next = create_node(3);
print_list(head);  // 1 -> 2 -> 3 -> NULL
```

**Android 连接：** Binder 使用类似的链表管理事务。

### Lab 3: 模拟 UAF 漏洞

**什么是 Use-After-Free？**

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *p = malloc(sizeof(int));
    *p = 42;
    printf("Before free: %d\n", *p);  // 42
    
    free(p);  // 释放内存
    
    // 危险！p 仍然指向已释放的内存
    printf("After free: %d\n", *p);   // 未定义行为！
    
    // 如果这块内存被复用...
    int *q = malloc(sizeof(int));
    *q = 999;
    printf("After realloc: %d\n", *p);  // 可能是 999！
    
    return 0;
}
```

**编译并用 ASAN 检测：**

```bash
gcc -fsanitize=address -g uaf_demo.c -o uaf_demo
./uaf_demo
```

输出：
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free
READ of size 4 at 0x602000000010
...
```

> [!CAUTION]
> **CVE-2023-20938** (Binder driver) 就是 UAF 漏洞，攻击者可利用它获取内核权限。

---

## 常见陷阱

### ❌ 陷阱 1: 空指针解引用

```c
int *p = NULL;
*p = 42;  // 崩溃！
```

**为什么会发生：**
- 忘记初始化
- 函数返回 NULL 但未检查
- 条件分支遗漏

**如何避免：**
```c
// 1. 总是检查
if (p != NULL) {
    *p = 42;
}

// 2. 使用断言（调试期）
assert(p != NULL);

// 3. 养成习惯：声明时初始化
int *p = NULL;  // 或直接赋有效值
```

### ❌ 陷阱 2: 野指针

```c
int *p;          // 未初始化
*p = 42;         // 写到随机地址！

// 或者
int *p = malloc(sizeof(int));
free(p);
*p = 42;         // UAF
```

**调试技巧：**
```bash
# Valgrind 检测
valgrind --leak-check=full ./program

# ASAN
gcc -fsanitize=address program.c
```

### ❌ 陷阱 3: 返回局部变量地址

```c
int *bad_function() {
    int local = 42;
    return &local;  // 危险！local 在函数返回后失效
}

int main() {
    int *p = bad_function();
    printf("%d\n", *p);  // 未定义行为
}
```

**编译器通常会警告：**
```
warning: function returns address of local variable
```

**正确做法：**
```c
int *good_function() {
    int *p = malloc(sizeof(int));
    *p = 42;
    return p;  // 堆上分配，调用者负责 free
}
```

### ❌ 陷阱 4: 数组越界

```c
int arr[5];
arr[5] = 0;   // 越界写！
arr[-1] = 0;  // 也是越界！
```

**从指针角度理解：**
```c
arr[5]  ==  *(arr + 5)  // 超出分配范围
```

---

## 深入阅读

**推荐资源：**
- [Beej's Guide to C - Pointers](https://beej.us/guide/bgc/html/split/pointers.html)
- [The Linux Kernel - Data Structures](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html)

**相关章节：**
- [02 - 内存管理](./02-memory.md) - 堆栈、动态分配
- [05 - 内核开发](./05-kernel-style.md) - kmalloc、内核指针

**Android 相关：**
- Binder 使用指针传递事务数据
- JNI 中 `jclass`, `jobject` 本质是指针
- Native 层大量使用智能指针 (`sp<>`, `wp<>`)

---

## 下一步

[02 - 内存管理](./02-memory.md) - 深入理解栈与堆、动态分配、内存安全
