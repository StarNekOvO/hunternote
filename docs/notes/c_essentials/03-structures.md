# 03 - 结构体

复合数据类型：将相关数据组织在一起。


## 概念速览

**struct 是什么？**
用户自定义的复合数据类型，将多个变量组合成一个整体。

**为什么需要它？**
- 表示复杂实体（设备、进程、网络包）
- Android/内核到处都是 struct
- C 没有 class，struct 是核心抽象工具

**与 Java class 的区别：**

| 特性 | C struct | Java class |
|------|----------|------------|
| 方法 | ✗ | ✓ |
| 继承 | ✗ | ✓ |
| 访问控制 | ✗ | ✓ (public/private) |
| 内存布局 | 可预测 | JVM 管理 |


## 核心概念

### 基本定义

```c
// 定义结构体
struct point {
    int x;
    int y;
};

// 声明变量
struct point p1;
p1.x = 10;
p1.y = 20;

// 初始化
struct point p2 = {30, 40};
struct point p3 = {.y = 60, .x = 50};  // 指定成员
```

### typedef 简化

```c
// 每次都写 struct 很烦
typedef struct {
    int x;
    int y;
} Point;

Point p1 = {10, 20};  // 不用写 struct
```

### 为什么内核代码不用 typedef？

```c
// Linux 内核风格：显式写 struct
struct file_operations {
    ssize_t (*read)(struct file *, ...);
};

// 不推荐
typedef struct file_operations fops_t;
```

**理由（来自 Linux CodingStyle）：**
1. `struct tag` 明确表示这是结构体
2. 更容易 grep 搜索
3. 避免隐藏复杂性


## 基础用法

### 访问成员

```c
struct person {
    char name[32];
    int age;
};

struct person p = {"Alice", 25};

// 直接访问
printf("%s is %d years old\n", p.name, p.age);

// 通过指针访问
struct person *pp = &p;
printf("%s is %d years old\n", pp->name, pp->age);
// pp->age 等价于 (*pp).age
```

### 嵌套结构体

```c
struct address {
    char city[32];
    char street[64];
};

struct person {
    char name[32];
    int age;
    struct address addr;  // 嵌套
};

struct person p = {
    .name = "Bob",
    .age = 30,
    .addr = {
        .city = "Beijing",
        .street = "Zhongguancun"
    }
};

printf("%s lives in %s\n", p.name, p.addr.city);
```

### 结构体数组

```c
struct point points[100];

for (int i = 0; i < 100; i++) {
    points[i].x = i;
    points[i].y = i * 2;
}
```


## 进阶用法

### 内存对齐

```c
struct example1 {
    char a;     // 1 byte
    int b;      // 4 bytes
    char c;     // 1 byte
};
// sizeof = 12 (有 padding)

struct example2 {
    char a;     // 1 byte
    char c;     // 1 byte
    int b;      // 4 bytes
};
// sizeof = 8 (优化后)
```

**内存布局对比：**

```
example1 (12 bytes):
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ a │pad│pad│pad│      b        │ c │pad│pad│pad│
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘

example2 (8 bytes):
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ a │ c │pad│pad│      b        │
└───┴───┴───┴───┴───┴───┴───┴───┘
```

> [!TIP]
> **最佳实践：** 将相同大小的成员放在一起，最大的放最后。

### 位域 (Bit Fields)

```c
struct flags {
    unsigned int readable  : 1;  // 1 bit
    unsigned int writable  : 1;  // 1 bit
    unsigned int executable: 1;  // 1 bit
    unsigned int reserved  : 29; // 29 bits
};

struct flags f = {.readable = 1, .writable = 1};

if (f.readable) {
    printf("Can read\n");
}
```

**用途：**
- 硬件寄存器定义
- 节省内存
- 网络协议头

**Android 内核示例：**
```c
// include/linux/fs.h
struct inode {
    umode_t         i_mode;     // 权限位
    unsigned int    i_flags;    // 各种标志
    // ...
};
```

### union (联合体)

**特点：** 所有成员共享同一块内存。

```c
union data {
    int i;
    float f;
    char str[4];
};

union data d;
d.i = 42;
printf("int: %d\n", d.i);    // 42
printf("float: %f\n", d.f);  // 垃圾值（同一内存的不同解释）

d.f = 3.14;
printf("float: %f\n", d.f);  // 3.14
printf("int: %d\n", d.i);    // 垃圾值
```

**典型用途：类型双关（Type Punning）**

```c
// 查看 float 的二进制表示
union {
    float f;
    uint32_t i;
} u;

u.f = 3.14;
printf("3.14 的二进制表示: 0x%08X\n", u.i);
// 输出: 0x4048F5C3
```

### 灵活数组成员 (FAM)

```c
struct buffer {
    size_t len;
    char data[];  // 灵活数组，必须是最后一个成员
};

// 分配
struct buffer *buf = malloc(sizeof(struct buffer) + 100);
buf->len = 100;
strcpy(buf->data, "Hello");
```


## 实战场景

### Lab 1: 内核风格的链表

```c
// Linux 内核的链表节点
struct list_head {
    struct list_head *prev;
    struct list_head *next;
};

// 嵌入到数据结构中
struct task {
    int pid;
    char name[16];
    struct list_head list;  // 链表节点嵌入
};

// 初始化
#define LIST_HEAD_INIT(name) { &(name), &(name) }

// 从 list_head 获取包含它的结构体
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
```

**这就是 Linux 内核的链表实现原理！**

### Lab 2: Binder 数据结构

```c
// Android Binder 核心结构 (简化版)
struct binder_transaction_data {
    __u32 code;         // 事务代码
    __u32 flags;        // 标志
    
    union {
        __u32 handle;   // 作为 client
        __u32 ref;      // 作为 server
    } target;
    
    size_t data_size;   // 数据大小
    size_t offsets_size;
    // ...
};
```

### Lab 3: 计算结构体偏移

```c
#include <stddef.h>

struct example {
    char a;
    int b;
    char c;
    double d;
};

int main(void) {
    printf("offsetof(a) = %zu\n", offsetof(struct example, a));
    printf("offsetof(b) = %zu\n", offsetof(struct example, b));
    printf("offsetof(c) = %zu\n", offsetof(struct example, c));
    printf("offsetof(d) = %zu\n", offsetof(struct example, d));
    printf("sizeof = %zu\n", sizeof(struct example));
    return 0;
}
```

**输出（64 位系统）：**
```
offsetof(a) = 0
offsetof(b) = 4
offsetof(c) = 8
offsetof(d) = 16
sizeof = 24
```


## 常见陷阱

### ❌ 陷阱 1: 结构体赋值是浅拷贝

```c
struct data {
    int *ptr;
};

struct data a, b;
a.ptr = malloc(sizeof(int));
*a.ptr = 42;

b = a;  // 浅拷贝！b.ptr 和 a.ptr 指向同一内存

free(a.ptr);
// 现在 b.ptr 是野指针！
```

### ❌ 陷阱 2: 值传递的开销

```c
struct big_data {
    char buffer[1024];
};

// 错误：每次调用复制 1024 字节
void process(struct big_data d) { ... }

// 正确：传指针
void process(struct big_data *d) { ... }
```

### ❌ 陷阱 3: 对齐问题

```c
// 网络协议：期望紧凑布局
struct packet {
    uint8_t type;
    uint32_t length;
} __attribute__((packed));  // 禁用对齐
```

> [!WARNING]
> `packed` 可能导致未对齐访问，在某些架构上崩溃。

### ❌ 陷阱 4: 忘记初始化

```c
struct data d;
// d 的成员是未定义值！

// 正确
struct data d = {0};  // 全部清零
```


## 深入阅读

**推荐资源：**
- [Linux Kernel Linked List](https://kernelnewbies.org/FAQ/LinkedLists)
- [Data Structure Alignment](https://en.wikipedia.org/wiki/Data_structure_alignment)

**相关章节：**
- [05 - 内核开发](./05-kernel-style.md) - 内核数据结构风格
- [02 - Binder 解析](/notes/android/02-ipc/00-binder-deep-dive) - Binder 结构详解


## 下一步

[04 - 预处理器](./04-preprocessor.md) - 宏、条件编译
