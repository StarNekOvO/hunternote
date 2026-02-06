# 06 - 驱动开发

字符设备、设备模型、ioctl、HAL 和 GKI。


## 概念速览

**为什么学驱动开发？**
- Android 设备大量定制驱动
- 驱动是攻击面（CVE 高发区）
- 理解 HAL、Binder、传感器的前提

**驱动在系统中的位置：**

```
┌─────────────────────────────────────┐
│           用户空间 App              │
├─────────────────────────────────────┤
│          Framework (Java)           │
├─────────────────────────────────────┤
│            HAL (C/C++)              │
├─────────────────────────────────────┤
│          Kernel Drivers             │ ← 驱动
├─────────────────────────────────────┤
│             Hardware                │
└─────────────────────────────────────┘
```


## 核心概念

### Linux 设备类型

| 类型 | 文件 | 特点 | 例子 |
|------|------|------|------|
| 字符设备 | `/dev/xxx` | 顺序访问 | 串口、键盘、Binder |
| 块设备 | `/dev/sdX` | 随机访问 | 硬盘、SD卡 |
| 网络设备 | - | 套接字接口 | eth0, wlan0 |

**Android 特有设备：**
- `/dev/binder` - Binder IPC
- `/dev/ashmem` - 匿名共享内存
- `/dev/ion` - 内存分配器

### 主/次设备号

每个设备由两个数字标识：
- **主设备号**：标识驱动程序
- **次设备号**：标识具体设备

```bash
ls -l /dev/null
# crw-rw-rw- 1 root root 1, 3 Jan 1 00:00 /dev/null
#                        ^  ^
#                        主 次
```

### file_operations

驱动的核心：提供一组操作函数。

```c
#include <linux/fs.h>

static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
    .mmap = my_mmap,
};
```

| 函数 | 触发时机 |
|------|----------|
| open | `open("/dev/xxx", ...)` |
| release | `close(fd)` |
| read | `read(fd, buf, count)` |
| write | `write(fd, buf, count)` |
| unlocked_ioctl | `ioctl(fd, cmd, arg)` |
| mmap | `mmap(...)` |


## 基础用法

### 字符设备完整示例

```c
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "mychardev"
#define BUF_SIZE 1024

static dev_t dev_num;
static struct cdev my_cdev;
static struct class *my_class;
static char device_buffer[BUF_SIZE];

static int my_open(struct inode *inode, struct file *file)
{
    pr_info("Device opened\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
    pr_info("Device closed\n");
    return 0;
}

static ssize_t my_read(struct file *file, char __user *buf,
                       size_t count, loff_t *ppos)
{
    size_t len = min(count, (size_t)(BUF_SIZE - *ppos));
    
    if (len == 0)
        return 0;
    
    if (copy_to_user(buf, device_buffer + *ppos, len))
        return -EFAULT;
    
    *ppos += len;
    return len;
}

static ssize_t my_write(struct file *file, const char __user *buf,
                        size_t count, loff_t *ppos)
{
    size_t len = min(count, (size_t)BUF_SIZE);
    
    if (copy_from_user(device_buffer, buf, len))
        return -EFAULT;
    
    return len;
}

static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
};

static int __init my_init(void)
{
    int ret;
    
    // 1. 分配设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0)
        return ret;
    
    // 2. 初始化 cdev
    cdev_init(&my_cdev, &my_fops);
    my_cdev.owner = THIS_MODULE;
    
    // 3. 添加 cdev
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0)
        goto err_cdev;
    
    // 4. 创建设备类
    my_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(my_class)) {
        ret = PTR_ERR(my_class);
        goto err_class;
    }
    
    // 5. 创建设备节点
    device_create(my_class, NULL, dev_num, NULL, DEVICE_NAME);
    
    pr_info("Device registered: major=%d\n", MAJOR(dev_num));
    return 0;

err_class:
    cdev_del(&my_cdev);
err_cdev:
    unregister_chrdev_region(dev_num, 1);
    return ret;
}

static void __exit my_exit(void)
{
    device_destroy(my_class, dev_num);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);
    pr_info("Device unregistered\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
```

### ioctl 实现

```c
// ioctl 命令定义
#define MY_IOC_MAGIC 'k'
#define MY_IOCTL_RESET     _IO(MY_IOC_MAGIC, 0)
#define MY_IOCTL_GET_VALUE _IOR(MY_IOC_MAGIC, 1, int)
#define MY_IOCTL_SET_VALUE _IOW(MY_IOC_MAGIC, 2, int)

static int current_value = 0;

static long my_ioctl(struct file *file, unsigned int cmd,
                     unsigned long arg)
{
    int tmp;
    
    switch (cmd) {
    case MY_IOCTL_RESET:
        current_value = 0;
        break;
        
    case MY_IOCTL_GET_VALUE:
        if (copy_to_user((int __user *)arg, &current_value, sizeof(int)))
            return -EFAULT;
        break;
        
    case MY_IOCTL_SET_VALUE:
        if (copy_from_user(&tmp, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        current_value = tmp;
        break;
        
    default:
        return -ENOTTY;
    }
    
    return 0;
}
```

**ioctl 命令宏：**

| 宏 | 含义 |
|-----|------|
| `_IO(type, nr)` | 无数据传输 |
| `_IOR(type, nr, datatype)` | 从驱动读取 |
| `_IOW(type, nr, datatype)` | 写入驱动 |
| `_IOWR(type, nr, datatype)` | 双向传输 |


## 进阶用法

### 用户空间使用驱动

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define MY_IOC_MAGIC 'k'
#define MY_IOCTL_SET_VALUE _IOW(MY_IOC_MAGIC, 2, int)
#define MY_IOCTL_GET_VALUE _IOR(MY_IOC_MAGIC, 1, int)

int main(void)
{
    int fd = open("/dev/mychardev", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // 写数据
    int value = 42;
    ioctl(fd, MY_IOCTL_SET_VALUE, &value);
    
    // 读数据
    int result;
    ioctl(fd, MY_IOCTL_GET_VALUE, &result);
    printf("Got: %d\n", result);
    
    close(fd);
    return 0;
}
```

### misc_device (简化版)

很多 Android 驱动使用 misc 设备：

```c
#include <linux/miscdevice.h>

static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = my_ioctl,
};

static struct miscdevice my_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "mymisc",
    .fops = &my_fops,
};

static int __init my_init(void)
{
    return misc_register(&my_miscdev);
}

static void __exit my_exit(void)
{
    misc_deregister(&my_miscdev);
}
```

**优点：** 无需手动分配设备号、创建类等。


## 实战场景

### Lab 1: Binder 驱动结构

```c
// drivers/android/binder.c (简化版)

static const struct file_operations binder_fops = {
    .owner = THIS_MODULE,
    .poll = binder_poll,
    .unlocked_ioctl = binder_ioctl,
    .mmap = binder_mmap,
    .open = binder_open,
    .release = binder_release,
};

// Binder 核心操作
static long binder_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long arg)
{
    switch (cmd) {
    case BINDER_WRITE_READ:
        // 处理读写请求
        break;
    case BINDER_SET_CONTEXT_MGR:
        // 设置为 ServiceManager
        break;
    }
    return 0;
}
```

### Lab 2: CVE-2024-53104 分析

USB Video Class 驱动的 OOB 写漏洞：

```c
// 简化的漏洞模式
static void vulnerrable_parse(struct uvc_device *dev,
                              unsigned char *data, int len)
{
    // 错误：未验证 data[0] 的范围
    int index = data[0];
    
    // 如果 index 超出数组范围...
    dev->formats[index].type = data[1];  // OOB 写！
}
```

> [!CAUTION]
> ioctl 和解析函数是驱动漏洞高发区，必须严格验证输入。

### Lab 3: Android HAL 接口

```c
// HAL 模块结构 (hardware/libhardware)
typedef struct {
    struct hw_module_t common;
    int (*get_value)(struct custom_hw_device *dev, int *value);
    int (*set_value)(struct custom_hw_device *dev, int value);
} custom_hw_module_t;

// 实现
static int custom_get_value(struct custom_hw_device *dev, int *value)
{
    // 调用驱动
    int fd = open("/dev/mychardev", O_RDONLY);
    ioctl(fd, MY_IOCTL_GET_VALUE, value);
    close(fd);
    return 0;
}
```


## Android GKI

### 什么是 GKI？

**Generic Kernel Image** - Android 12 引入的统一内核。

```
传统模式：
  每个厂商一个定制内核 → 碎片化严重

GKI 模式：
  Google 提供通用内核 + 厂商提供模块
```

**架构：**

```
┌────────────────────────────────┐
│         Google GKI Kernel      │ ← 统一，Google 维护
├────────────────────────────────┤
│    Vendor Kernel Modules       │ ← 厂商驱动模块
└────────────────────────────────┘
```

### 对开发者的影响

1. 内核接口稳定化 (KMI)
2. 不能随意修改核心内核
3. 驱动必须以模块形式


## 常见陷阱

### ❌ 陷阱 1: 未验证用户输入

```c
// 错误
static long my_ioctl(struct file *file, unsigned int cmd,
                     unsigned long arg)
{
    char buf[256];
    // 直接使用用户指针大小
    if (copy_from_user(buf, (void __user *)arg, 1000))  // 溢出！
        return -EFAULT;
}

// 正确
if (copy_from_user(buf, (void __user *)arg, sizeof(buf)))
```

### ❌ 陷阱 2: 竞态条件

```c
static int counter = 0;

static ssize_t my_write(struct file *file, ...)
{
    counter++;  // 非原子操作！多线程会出问题
}

// 正确
static atomic_t counter = ATOMIC_INIT(0);
atomic_inc(&counter);
```

### ❌ 陷阱 3: 忘记错误路径清理

使用 goto 模式或 devm_* API。

### ❌ 陷阱 4: ioctl 命令冲突

不同驱动使用相同的 magic number 和命令号。


## 深入阅读

**推荐资源：**
- [Linux Device Drivers, 3rd Edition](https://lwn.net/Kernel/LDD3/)
- [Android GKI](https://source.android.com/devices/architecture/kernel/generic-kernel-image)

**相关章节：**
- [Binder 深度解析](/notes/android/02-ipc/00-binder-deep-dive)
- [Android 内核安全](/notes/android/05-kernel/)


## 下一步

[07 - KernelSU/Magisk](./07-ksu-magisk-native.md) - Root 工具的内核实现
