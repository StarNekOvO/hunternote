# 02 - 内存管理

理解内存布局和动态分配是分析内存安全漏洞的基础。


## 概念速览

**为什么要学内存管理？**
- 70% 的安全漏洞与内存相关
- 理解 UAF、堆溢出需要这些基础
- Android 内核/Native 层必备技能

**与 Java/Python 的区别：**

| 语言 | 内存管理 | 责任 |
|------|----------|------|
| Python | 引用计数 + GC | 语言运行时 |
| Java | GC | JVM |
| C | 手动 malloc/free | 程序员 |
| Rust | 所有权系统 | 编译器 |


## 核心概念

### 进程内存布局

```
高地址 ┌─────────────────────┐
      │       Stack         │ ← 局部变量，向下增长 ↓
      │         ↓           │
      ├─────────────────────┤
      │     (空闲空间)       │
      ├─────────────────────┤
      │         ↑           │
      │        Heap         │ ← malloc/free，向上增长 ↑
      ├─────────────────────┤
      │        BSS          │ ← 未初始化全局变量
      ├─────────────────────┤
      │        Data         │ ← 已初始化全局变量
      ├─────────────────────┤
      │        Text         │ ← 代码段 (只读)
低地址 └─────────────────────┘
```

**验证实验：**
```c
#include <stdio.h>
#include <stdlib.h>

int global_init = 42;     // Data 段
int global_uninit;        // BSS 段

int main(void) {
    int local = 0;                    // 栈
    static int static_local = 0;      // Data 段
    int *heap_ptr = malloc(sizeof(int)); // 堆
    
    printf("代码:      main     = %p\n", main);
    printf("Data:      global   = %p\n", &global_init);
    printf("BSS:       uninit   = %p\n", &global_uninit);
    printf("堆:        heap_ptr = %p\n", heap_ptr);
    printf("栈:        local    = %p\n", &local);
    
    free(heap_ptr);
    return 0;
}
```

### 栈 (Stack)

**特点：**
- 自动分配/释放
- 后进先出 (LIFO)
- 大小有限 (通常 8MB)
- 速度快

**栈帧结构：**

```c
void func(int arg1, int arg2) {
    int local1;
    char buffer[16];
}
```

```
高地址 ┌─────────────────────┐
      │      arg2           │ ← 参数 (从右向左入栈)
      │      arg1           │
      ├─────────────────────┤
      │   Return Address    │ ← 函数返回后执行的地址
      ├─────────────────────┤
      │   Saved RBP         │ ← 保存的帧指针
      ├─────────────────────┤ ← RBP (当前帧指针)
      │      local1         │
      │   buffer[0-15]      │ ← 局部变量
低地址 └─────────────────────┘ ← RSP (栈指针)
```

**为什么栈向低地址增长？**

1. **历史原因**：早期计算机的约定
2. **安全影响**：栈溢出会覆盖返回地址
3. **利用原理**：覆盖返回地址 → 控制执行流

### 堆 (Heap)

**特点：**
- 手动分配/释放
- 大小灵活
- 速度较慢（需要分配器管理）
- 容易出错

**分配器：**
- glibc: ptmalloc2
- Android: jemalloc / scudo
- 内核: slab, slub


## 基础用法

### malloc / free

```c
#include <stdlib.h>

// 分配 10 个 int
int *arr = (int *)malloc(10 * sizeof(int));

if (arr == NULL) {
    // 分配失败处理
    perror("malloc failed");
    return -1;
}

// 使用
for (int i = 0; i < 10; i++) {
    arr[i] = i;
}

// 释放
free(arr);
arr = NULL;  // 防止野指针
```

> [!CAUTION]
> `malloc` 返回的内存**未初始化**，可能包含垃圾数据。

### calloc (分配并清零)

```c
// 分配 10 个 int，全部清零
int *arr = (int *)calloc(10, sizeof(int));
// arr[0] == arr[1] == ... == 0
```

### realloc (调整大小)

```c
int *arr = malloc(10 * sizeof(int));

// 扩展到 20 个
int *new_arr = realloc(arr, 20 * sizeof(int));

if (new_arr == NULL) {
    // realloc 失败，原 arr 仍有效
    free(arr);
    return -1;
}

arr = new_arr;  // 原 arr 可能已失效
```

> [!WARNING]
> `realloc` 可能移动内存块！不要保留旧指针。


## 进阶用法

### 内存对齐

```c
struct example {
    char a;     // 1 byte
    int b;      // 4 bytes
    char c;     // 1 byte
};

printf("sizeof = %zu\n", sizeof(struct example));
// 输出: 12, 不是 6!
```

**内存布局：**
```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ a │pad│pad│pad│      b        │ c │pad│pad│pad│
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

**为什么需要对齐？**
- CPU 访问对齐地址更快
- 某些架构不对齐会崩溃

### aligned_alloc

```c
// 分配 16 字节对齐的内存
void *ptr = aligned_alloc(16, 1024);
// ptr 的地址是 16 的倍数
```

### mmap (内存映射)

```c
#include <sys/mman.h>

// 分配可执行内存
void *code = mmap(NULL, 4096,
                  PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS,
                  -1, 0);

// Android/内核常用于驱动内存映射
```


## 实战场景

### Lab 1: 观察栈生长方向

```c
#include <stdio.h>

void func(int depth) {
    int local;
    printf("depth %d: &local = %p\n", depth, &local);
    
    if (depth < 5) {
        func(depth + 1);
    }
}

int main(void) {
    func(0);
    return 0;
}
```

**输出示例：**
```
depth 0: &local = 0x7ffd12345678
depth 1: &local = 0x7ffd12345658  ← 地址减小
depth 2: &local = 0x7ffd12345638
...
```

### Lab 2: 堆内存布局探索

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    void *p1 = malloc(16);
    void *p2 = malloc(16);
    void *p3 = malloc(16);
    
    printf("p1 = %p\n", p1);
    printf("p2 = %p\n", p2);
    printf("p3 = %p\n", p3);
    
    // 观察分配顺序
    printf("p2 - p1 = %ld\n", (char *)p2 - (char *)p1);
    
    free(p1);
    free(p2);
    free(p3);
    return 0;
}
```

### Lab 3: 检测内存问题

```bash
# 编译时启用 ASAN
gcc -fsanitize=address -g memory_test.c -o test

# 运行
./test
```

**ASAN 可检测：**
- Use-After-Free
- Buffer Overflow
- Memory Leak
- Double Free


## 常见漏洞类型

### ❌ Use-After-Free (UAF)

```c
int *p = malloc(sizeof(int));
*p = 42;
free(p);

// 危险！p 仍然指向已释放内存
*p = 100;  // UAF 写
int x = *p; // UAF 读
```

**攻击原理：**
1. 释放对象 A
2. 分配新对象 B，占用 A 的位置
3. 通过 A 的指针访问 B 的数据

> [!NOTE]
> **[CVE-2023-20938](../../cves/entries/CVE-2023-20938.md)** (Binder UAF) 就是这类漏洞。

### ❌ Double-Free

```c
int *p = malloc(sizeof(int));
free(p);
free(p);  // Double-free！可能导致堆损坏
```

### ❌ 堆溢出

```c
char *buf = malloc(16);
strcpy(buf, "This string is way too long!");  // 溢出！
```

### ❌ 栈溢出

```c
void vulnerable(char *input) {
    char buffer[16];
    strcpy(buffer, input);  // 如果 input > 16 字节就溢出
}
```

**可能覆盖返回地址 → RCE**


## 常见陷阱

### ❌ 陷阱 1: 忘记检查 malloc 返回值

```c
// 错误
int *p = malloc(huge_size);
*p = 42;  // 如果 malloc 失败，这里崩溃

// 正确
int *p = malloc(huge_size);
if (p == NULL) {
    // 错误处理
    return -1;
}
*p = 42;
```

### ❌ 陷阱 2: 内存泄漏

```c
void leak() {
    int *p = malloc(100);
    // 忘记 free(p)
}  // p 超出作用域，内存泄漏
```

**检测：**
```bash
valgrind --leak-check=full ./program
```

### ❌ 陷阱 3: free 后使用

```c
free(p);
// ... 其他代码 ...
*p = 42;  // 如果 p 没有置 NULL，编译器不会报错
```

**最佳实践：**
```c
free(p);
p = NULL;
```


## 深入阅读

**推荐资源：**
- [A Memory Allocator](http://gee.cs.oswego.edu/dl/html/malloc.html) - Doug Lea 的经典文章
- [Linux Kernel Memory Management](https://www.kernel.org/doc/html/latest/core-api/memory-allocation.html)

**相关章节：**
- [05 - 内核开发](./05-kernel-style.md) - kmalloc/vmalloc
- [Android CVE 分析](/notes/android/08-practical/04-cve-studies) - 实际漏洞案例


## 下一步

[03 - 结构体](./03-structures.md) - struct、union、位域
