# 05 - 内核开发

从用户态 C 到 Linux 内核开发的跨越。

---

## 概念速览

**为什么学内核开发？**
- Android 底层就是 Linux 内核
- 内核漏洞 = 最高权限
- 理解 Binder、驱动的前提

**内核 vs 用户态：**

| 特性 | 用户态 | 内核态 |
|------|--------|--------|
| 权限 | 受限 | 完全 |
| 出错后果 | 进程崩溃 | 系统崩溃 |
| 内存分配 | malloc | kmalloc/vmalloc |
| 输出 | printf | printk |
| 标准库 | libc | 无，只有内核 API |

---

## 核心概念

### 为什么没有标准库？

**内核不能用 libc：**
1. libc 需要系统调用，但内核是系统调用的提供者
2. 浮点运算在内核中被禁用（保存浮点寄存器代价高）
3. 内存管理由内核自己实现

**对比：**
```c
// 用户态
#include <stdio.h>
#include <stdlib.h>
printf("Hello\n");
char *buf = malloc(1024);

// 内核态
#include <linux/kernel.h>
#include <linux/slab.h>
printk(KERN_INFO "Hello\n");
char *buf = kmalloc(1024, GFP_KERNEL);
```

### 内核编码风格

**缩进（8 空格 Tab）：**
```c
if (condition) {
        do_something();  // Tab, 不是空格
}
```

**命名（全小写，下划线）：**
```c
int my_variable;
void my_function(void);
struct my_struct { };

#define MY_CONSTANT 100  // 宏全大写
```

**大括号（函数特殊）：**
```c
// 函数：左括号换行
int function(void)
{
        return 0;
}

// 控制语句：同行
if (condition) {
        // ...
}
```

> [!TIP]
> 使用 `checkpatch.pl` 检查代码风格：
> ```bash
> ./scripts/checkpatch.pl -f your_code.c
> ```

---

## 基础用法

### kmalloc / kfree

```c
#include <linux/slab.h>

// 分配
void *ptr = kmalloc(size, GFP_KERNEL);
if (!ptr)
        return -ENOMEM;

// 分配并清零
void *ptr2 = kzalloc(size, GFP_KERNEL);

// 释放
kfree(ptr);
```

**GFP 标志详解：**

| 标志 | 场景 | 说明 |
|------|------|------|
| `GFP_KERNEL` | 进程上下文 | 可睡眠等待内存 |
| `GFP_ATOMIC` | 中断/原子上下文 | 不可睡眠 |
| `GFP_DMA` | DMA 操作 | 低端内存 |
| `GFP_USER` | 用户空间内存 | 可能失败 |

**为什么区分这么多？**
- 内核代码可能在中断中运行，不能睡眠
- 不同场景对失败的容忍度不同
- DMA 有地址限制

### vmalloc

```c
#include <linux/vmalloc.h>

// 分配大块虚拟连续内存
void *ptr = vmalloc(large_size);

// 释放
vfree(ptr);
```

**kmalloc vs vmalloc：**

| 特性 | kmalloc | vmalloc |
|------|---------|---------|
| 物理连续 | ✓ | ✗ |
| 速度 | 快 | 慢 |
| 最大大小 | 小(通常128KB) | 大 |
| 用途 | 小块频繁分配 | 大块内存 |

### printk

```c
#include <linux/kernel.h>

// 传统方式
printk(KERN_INFO "Info message\n");
printk(KERN_ERR "Error: %d\n", code);

// 现代方式（推荐）
pr_info("Info message\n");
pr_err("Error: %d\n", code);
pr_debug("Debug message\n");  // 需要开启 DEBUG
```

**日志级别：**

| 级别 | 宏 | 说明 |
|------|-----|------|
| 0 | KERN_EMERG | 系统挂了 |
| 1 | KERN_ALERT | 必须立即处理 |
| 2 | KERN_CRIT | 严重错误 |
| 3 | KERN_ERR | 错误 |
| 4 | KERN_WARNING | 警告 |
| 5 | KERN_NOTICE | 正常但重要 |
| 6 | KERN_INFO | 信息 |
| 7 | KERN_DEBUG | 调试 |

```bash
# 查看内核日志
dmesg
# 或
cat /var/log/kern.log
```

---

## 进阶用法

### 可加载内核模块 (LKM)

**最小模块：**

```c
// hello.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Hello World Module");

static int __init hello_init(void)
{
        pr_info("Hello, kernel!\n");
        return 0;
}

static void __exit hello_exit(void)
{
        pr_info("Goodbye, kernel!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

**Makefile：**

```makefile
obj-m += hello.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
        make -C $(KDIR) M=$(PWD) modules

clean:
        make -C $(KDIR) M=$(PWD) clean
```

**编译与加载：**

```bash
make
sudo insmod hello.ko   # 加载
lsmod | grep hello     # 查看
dmesg | tail           # 查看输出
sudo rmmod hello       # 卸载
```

### 模块参数

```c
static int debug_level = 0;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0-3)");

static int __init my_init(void)
{
        if (debug_level > 0)
                pr_info("Debug mode enabled: %d\n", debug_level);
        return 0;
}
```

```bash
sudo insmod mymodule.ko debug_level=2
```

### 错误处理模式

内核中大量使用 goto 进行清理：

```c
static int my_init(void)
{
        struct resource *res1 = NULL, *res2 = NULL;
        int ret;

        res1 = allocate_resource1();
        if (!res1) {
                ret = -ENOMEM;
                goto err_res1;
        }

        res2 = allocate_resource2();
        if (!res2) {
                ret = -ENOMEM;
                goto err_res2;
        }

        return 0;

err_res2:
        free_resource1(res1);
err_res1:
        return ret;
}
```

> [!NOTE]
> 这种 goto 用法在内核中是**推荐的**，比嵌套 if 更清晰。

---

## 实战场景

### Lab 1: 带参数的模块

```c
#include <linux/init.h>
#include <linux/module.h>

static char *name = "World";
static int count = 1;

module_param(name, charp, 0644);
module_param(count, int, 0644);

static int __init hello_init(void)
{
        int i;
        for (i = 0; i < count; i++)
                pr_info("Hello, %s!\n", name);
        return 0;
}

static void __exit hello_exit(void)
{
        pr_info("Goodbye!\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
```

```bash
sudo insmod hello.ko name="Android" count=3
dmesg | tail
# Hello, Android!
# Hello, Android!
# Hello, Android!
```

### Lab 2: procfs 接口

```c
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int my_show(struct seq_file *m, void *v)
{
        seq_printf(m, "Hello from kernel!\n");
        return 0;
}

static int my_open(struct inode *inode, struct file *file)
{
        return single_open(file, my_show, NULL);
}

static const struct proc_ops my_ops = {
        .proc_open = my_open,
        .proc_read = seq_read,
        .proc_lseek = seq_lseek,
        .proc_release = single_release,
};

static int __init my_init(void)
{
        proc_create("my_entry", 0, NULL, &my_ops);
        return 0;
}

module_init(my_init);
```

```bash
cat /proc/my_entry
# Hello from kernel!
```

### Lab 3: Binder 驱动入口

```c
// 简化的 Binder 驱动结构
static const struct file_operations binder_fops = {
        .owner = THIS_MODULE,
        .open = binder_open,
        .release = binder_release,
        .mmap = binder_mmap,
        .unlocked_ioctl = binder_ioctl,
};

static struct miscdevice binder_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "binder",
        .fops = &binder_fops,
};

static int __init binder_init(void)
{
        return misc_register(&binder_miscdev);
}

module_init(binder_init);
```

> [!NOTE]
> **CVE-2023-20938** 就发生在 Binder 驱动中，因 `binder_node` 的 UAF 导致。

---

## 常见陷阱

### ❌ 陷阱 1: 忘记检查返回值

```c
// 错误
void *ptr = kmalloc(size, GFP_KERNEL);
*ptr = something;  // 如果分配失败就崩溃

// 正确
void *ptr = kmalloc(size, GFP_KERNEL);
if (!ptr)
        return -ENOMEM;
```

### ❌ 陷阱 2: 中断上下文睡眠

```c
// 中断处理函数
irqreturn_t my_irq_handler(int irq, void *dev_id)
{
        // 错误！GFP_KERNEL 可能睡眠
        void *ptr = kmalloc(size, GFP_KERNEL);
        
        // 正确
        void *ptr = kmalloc(size, GFP_ATOMIC);
}
```

### ❌ 陷阱 3: 用户空间指针

```c
// 错误：直接访问用户空间指针
void kernel_func(void __user *user_ptr)
{
        int val = *(int *)user_ptr;  // 危险！
}

// 正确
void kernel_func(void __user *user_ptr)
{
        int val;
        if (copy_from_user(&val, user_ptr, sizeof(val)))
                return -EFAULT;
}
```

### ❌ 陷阱 4: 忘记释放资源

```c
// 使用 devm_* 系列自动管理
struct device *dev;
void *ptr = devm_kmalloc(dev, size, GFP_KERNEL);
// 设备卸载时自动释放
```

---

## 深入阅读

**推荐资源：**
- [Linux Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg/)
- [Kernel Newbies](https://kernelnewbies.org/)
- [LWN.net](https://lwn.net/) - 权威内核新闻

**相关章节：**
- [06 - 驱动开发](./06-driver-dev.md) - 字符设备、ioctl
- [Android 内核安全](/notes/android/05-kernel/) - 内核攻击面

---

## 下一步

[06 - 驱动开发](./06-driver-dev.md) - 字符设备、ioctl、HAL
