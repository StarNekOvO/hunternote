# 5x00 - Android Kernel Overview

Android 内核虽然基于 Linux LTS (Long Term Support)，但为了适配移动设备的特殊需求，引入了许多特有的改动。

从安全研究视角，Android 内核可以分成三块：

- **上游 Linux 基础能力**：内存管理、调度、VFS、网络栈
- **Android 特有/强化能力**：Binder、LMKD/内存管理策略、部分安全特性集成
- **厂商驱动与定制**：SoC/外设驱动、显示/相机/基带相关，漏洞与差异最大的部分

## 1. Android 特有内核组件
- **Binder**: 核心 IPC 驱动，负责进程间通信。
- **Ashmem (Anonymous Shared Memory)**: 匿名共享内存，支持内存回收机制。
- **Low Memory Killer (LMK)**: 在内存不足时，根据 OOM Score 杀死进程。
- **Energy Aware Scheduling (EAS)**: 优化能效比的调度算法。

补充说明：

- Ashmem 在新系统上逐步由 `memfd` 等主线机制替代，但遗留兼容仍可能存在。
- LMK 在 Android 上常与用户态守护进程（LMKD）协作，策略层与内核层共同影响进程生存。

## 2. GKI (Generic Kernel Image)
从 Android 12 开始，Google 对发布时搭载 5.10+ 内核的新设备逐步落地并要求使用 GKI，以缓解内核碎片化问题。
- **核心思想**: 将核心内核与供应商驱动（Vendor Modules）分离。
- **安全意义**: Google 可以直接推送内核安全补丁，而无需等待 OEM 厂商适配。

补充：实际能否"直接推补丁"取决于设备的 ACK/GKI/KMI 约束与厂商模块情况；研究/复现时仍需以目标设备的内核分支与补丁级别为准。

## 3. Android 内核的"分区化"现实

即使 GKI 推进，安全研究仍然需要面对：

- 同一 Android 版本在不同机型上，vendor module 差异很大
- 漏洞往往集中在驱动与 ioctl 接口，而非主线通用代码

因此复现/验证时，必须明确：

- 目标设备内核版本与补丁级别
- 是否使用 GKI、是否加载特定 vendor 模块

## 4. 调试与观测

### 4.1 快速确认内核版本与构建信息

```bash
# 内核版本
adb shell uname -a
# Linux localhost 5.10.101-android12-9-00001-... #1 SMP PREEMPT ...

# 详细版本信息
adb shell cat /proc/version

# 内核配置（如果可用）
adb shell zcat /proc/config.gz | grep CONFIG_DEBUG
```

### 4.2 内核日志与事件

```bash
# 内核环形缓冲区日志
adb shell dmesg | head -100
adb shell dmesg | tail -f  # 实时跟踪

# 通过 logcat 查看内核日志（部分设备支持）
adb logcat -b kernel

# 清空后重新采集
adb shell dmesg -c && adb shell dmesg
```

### 4.3 常见接口面盘点

- `/proc`：进程、内存、调度等状态
- `/sys`：设备、驱动、cgroup、调参接口
- `/dev`：设备节点（驱动 ioctl 的入口）

## 5. 内核调试环境搭建

### 5.1 printk 调试

printk 是最基础也最常用的内核调试方式，无需特殊环境配置。

```c
// 在驱动代码中添加
printk(KERN_INFO "mydriver: value=%d, ptr=%p\n", val, ptr);
printk(KERN_ERR "mydriver: error at %s:%d\n", __func__, __LINE__);

// 使用 pr_* 宏（推荐）
pr_info("entering %s\n", __func__);
pr_err("allocation failed\n");
pr_debug("debug info: %d\n", data);  // 需要开启 DEBUG 宏
```

查看 printk 输出：

```bash
# 调整日志级别（0-7，数字越小级别越高）
adb shell "echo 8 > /proc/sys/kernel/printk"

# 实时查看
adb shell dmesg -w

# 过滤特定驱动日志
adb shell dmesg | grep "mydriver"
```

### 5.2 ftrace 动态追踪

ftrace 是 Linux 内核内置的追踪框架，可以追踪函数调用、事件、延迟等。

```bash
# 检查 ftrace 是否可用
adb shell ls /sys/kernel/debug/tracing/

# 挂载 debugfs（如未挂载）
adb shell mount -t debugfs none /sys/kernel/debug

# 查看可用的 tracer
adb shell cat /sys/kernel/debug/tracing/available_tracers
# nop function function_graph ...

# 查看可追踪的函数
adb shell cat /sys/kernel/debug/tracing/available_filter_functions | wc -l
```

追踪特定函数：

```bash
# 设置 function tracer
adb shell "echo function > /sys/kernel/debug/tracing/current_tracer"

# 过滤只追踪 binder 相关函数
adb shell "echo 'binder_*' > /sys/kernel/debug/tracing/set_ftrace_filter"

# 开启追踪
adb shell "echo 1 > /sys/kernel/debug/tracing/tracing_on"

# 执行触发操作...

# 关闭追踪并查看结果
adb shell "echo 0 > /sys/kernel/debug/tracing/tracing_on"
adb shell cat /sys/kernel/debug/tracing/trace
```

追踪 ioctl 调用：

```bash
# 追踪所有 ioctl 系统调用
adb shell "echo 'do_vfs_ioctl' > /sys/kernel/debug/tracing/set_ftrace_filter"

# 使用 function_graph 查看调用栈
adb shell "echo function_graph > /sys/kernel/debug/tracing/current_tracer"
adb shell "echo do_vfs_ioctl > /sys/kernel/debug/tracing/set_graph_function"

# 追踪特定进程
adb shell "echo $PID > /sys/kernel/debug/tracing/set_ftrace_pid"
```

### 5.3 KGDB 内核调试器

KGDB 允许使用 GDB 远程调试内核，需要内核编译时开启支持。

检查内核配置：

```bash
adb shell zcat /proc/config.gz | grep -E "CONFIG_KGDB|CONFIG_DEBUG_INFO"
# CONFIG_KGDB=y
# CONFIG_KGDB_SERIAL_CONSOLE=y
# CONFIG_DEBUG_INFO=y
```

通过串口连接 KGDB：

```bash
# 在目标设备上启用 KGDB
adb shell "echo ttyMSM0 > /sys/module/kgdboc/parameters/kgdboc"

# 触发断点进入调试
adb shell "echo g > /proc/sysrq-trigger"

# 在主机上使用 GDB 连接
# 需要带符号的 vmlinux
gdb vmlinux
(gdb) target remote /dev/ttyUSB0
(gdb) bt
(gdb) info registers
(gdb) list *0xffffff8008xxxxxx
```

模拟器环境调试（推荐入门）：

```bash
# 启动带调试支持的模拟器
emulator -avd <avd_name> -kernel /path/to/kernel-qemu \
    -show-kernel -qemu -s -S

# -s: 在 1234 端口启动 gdbserver
# -S: 启动时暂停等待调试器连接

# 连接 GDB
aarch64-linux-gnu-gdb vmlinux
(gdb) target remote :1234
(gdb) break start_kernel
(gdb) continue
```

### 5.4 kprobes 动态探针

kprobes 允许在运行时动态插入探针，无需重新编译内核。

```bash
# 检查 kprobes 支持
adb shell cat /sys/kernel/debug/kprobes/list

# 使用 perf 配合 kprobes
adb shell perf probe --add 'do_sys_open filename:string'
adb shell perf record -e probe:do_sys_open -a sleep 5
adb shell perf script
```

## 6. 驱动审计方法与 Checklist

### 6.1 定位攻击面

```bash
# 列出所有字符设备
adb shell ls -la /dev/ | grep "^c"

# 查看设备权限与 SELinux 标签
adb shell ls -laZ /dev/

# 找出可被应用访问的设备
adb shell find /dev -type c -perm -o+r 2>/dev/null
adb shell find /dev -type c -perm -o+w 2>/dev/null

# 列出加载的内核模块
adb shell lsmod
adb shell cat /proc/modules

# 查看模块参数
adb shell ls /sys/module/*/parameters/
```

### 6.2 ioctl 接口审计

ioctl 是驱动漏洞的重灾区，审计要点：

```bash
# 查找驱动源码中的 ioctl 定义
grep -rn "\.unlocked_ioctl\|\.compat_ioctl" drivers/

# 查找 ioctl 命令定义
grep -rn "_IOW\|_IOR\|_IOWR\|_IO(" include/ drivers/

# 提取 ioctl 命令号
grep -rE "#define.*_IO[WR]*\(" include/uapi/ | head -50
```

ioctl 命令号结构：

```c
// ioctl 命令号由四部分组成：type(8) | nr(8) | dir(2) | size(14)
// _IO(type, nr)       - 无数据传输
// _IOR(type, nr, dt)  - 从内核读取
// _IOW(type, nr, dt)  - 写入内核
// _IOWR(type, nr, dt) - 双向传输

// 解析命令号
#define _IOC_TYPE(nr)   (((nr) >> 8) & 0xFF)
#define _IOC_NR(nr)     ((nr) & 0xFF)
#define _IOC_DIR(nr)    (((nr) >> 30) & 0x3)
#define _IOC_SIZE(nr)   (((nr) >> 16) & 0x3FFF)
```

### 6.3 ioctl 枚举脚本

```python
#!/usr/bin/env python3
"""
ioctl_fuzzer.py - 枚举设备支持的 ioctl 命令
"""
import os
import sys
import fcntl
import struct
import errno

def make_ioctl_cmd(dir, type, nr, size):
    """构造 ioctl 命令号"""
    return (dir << 30) | (size << 16) | (type << 8) | nr

def probe_ioctl(device, cmd):
    """测试单个 ioctl 命令"""
    try:
        fd = os.open(device, os.O_RDWR | os.O_NONBLOCK)
    except OSError as e:
        if e.errno == errno.EACCES:
            fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
        else:
            return None
    
    buf = b'\x00' * 4096
    try:
        result = fcntl.ioctl(fd, cmd, buf)
        return ('OK', result)
    except OSError as e:
        if e.errno == errno.ENOTTY:
            return None  # 不支持此命令
        elif e.errno == errno.EINVAL:
            return ('EINVAL', e.errno)  # 命令存在但参数无效
        elif e.errno == errno.EFAULT:
            return ('EFAULT', e.errno)  # 命令存在，地址无效
        else:
            return (e.strerror, e.errno)
    finally:
        os.close(fd)

def enum_ioctl(device, type_byte, max_nr=256):
    """枚举指定 type 的所有 ioctl 命令"""
    found = []
    for dir in [0, 1, 2, 3]:  # none, write, read, rw
        for nr in range(max_nr):
            for size in [0, 4, 8, 16, 32, 64, 128, 256, 512, 1024]:
                cmd = make_ioctl_cmd(dir, type_byte, nr, size)
                result = probe_ioctl(device, cmd)
                if result:
                    found.append({
                        'cmd': hex(cmd),
                        'dir': dir,
                        'type': type_byte,
                        'nr': nr,
                        'size': size,
                        'result': result
                    })
    return found

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <device> <type_byte>")
        print(f"Example: {sys.argv[0]} /dev/binder 0x62")
        sys.exit(1)
    
    device = sys.argv[1]
    type_byte = int(sys.argv[2], 0)
    
    print(f"[*] Probing {device} with type=0x{type_byte:02x}")
    results = enum_ioctl(device, type_byte)
    
    for r in results:
        print(f"  {r['cmd']}: dir={r['dir']} nr={r['nr']} "
              f"size={r['size']} -> {r['result']}")
```

### 6.4 驱动审计 Checklist

**输入验证**

- [ ] ioctl cmd 是否有 switch-case default 处理
- [ ] copy_from_user 前是否校验 size 参数
- [ ] 用户传入的指针是否经过 access_ok 检查
- [ ] 数组索引是否有边界检查
- [ ] 整数运算是否可能溢出

**内存安全**

- [ ] kmalloc/kzalloc 大小是否受用户控制
- [ ] 是否存在 use-after-free（检查 kfree 后的引用）
- [ ] 是否存在 double-free
- [ ] 堆喷射可控性（分配大小、内容、时机）

**竞态条件**

- [ ] 多个 ioctl 并发调用是否安全
- [ ] 引用计数操作是否原子
- [ ] file->private_data 的生命周期管理
- [ ] TOCTOU (Time-of-check to time-of-use) 问题

**信息泄露**

- [ ] copy_to_user 是否可能泄露未初始化内存
- [ ] 结构体是否有 padding 字节未清零
- [ ] 错误码是否泄露内核地址

**权限检查**

- [ ] 敏感操作是否检查 CAP_SYS_ADMIN 等能力
- [ ] 是否正确使用 ns_capable 而非 capable
- [ ] SELinux 标签是否正确配置

## 7. /proc 接口安全分析

### 7.1 关键 /proc 接口

```bash
# 进程信息
/proc/[pid]/maps        # 内存映射，可用于绕过 ASLR
/proc/[pid]/mem         # 进程内存（需要 ptrace 权限）
/proc/[pid]/cmdline     # 命令行参数
/proc/[pid]/environ     # 环境变量
/proc/[pid]/fd/         # 打开的文件描述符
/proc/[pid]/task/       # 线程信息

# 系统信息
/proc/kallsyms          # 内核符号表（KASLR 绕过关键）
/proc/modules           # 加载的模块及地址
/proc/iomem             # 物理内存映射
/proc/slabinfo          # SLAB 分配器信息

# 内核参数
/proc/sys/kernel/       # 内核配置
/proc/sys/vm/           # 虚拟内存参数
```

### 7.2 安全相关检查

```bash
# 检查 KASLR 相关
adb shell cat /proc/kallsyms | head -5
# 若显示 0000000000000000 表示受限

# 检查 kptr_restrict
adb shell cat /proc/sys/kernel/kptr_restrict
# 0: 不限制
# 1: 非特权用户看不到地址
# 2: 所有用户都看不到

# 检查 dmesg_restrict
adb shell cat /proc/sys/kernel/dmesg_restrict
# 1: 非特权用户无法读取 dmesg

# 检查 perf_event_paranoid
adb shell cat /proc/sys/kernel/perf_event_paranoid
# -1: 不限制
# 0: 允许访问 CPU 事件
# 1: 不允许 CPU 事件
# 2: 只允许用户空间测量
# 3: 完全禁用
```

### 7.3 /proc 信息泄露利用

```bash
# 获取内核基址（需要 root 或 kptr_restrict=0）
adb shell cat /proc/kallsyms | grep " T _text"
adb shell cat /proc/kallsyms | grep "commit_creds"

# 获取模块基址
adb shell cat /proc/modules | head -10

# 获取堆信息
adb shell cat /proc/slabinfo | grep kmalloc
adb shell cat /proc/buddyinfo

# 通过 maps 泄露地址布局
adb shell cat /proc/self/maps
```

## 8. /sys 接口安全分析

### 8.1 关键 /sys 接口

```bash
# 设备与驱动
/sys/class/             # 设备类
/sys/devices/           # 设备树
/sys/module/            # 内核模块参数

# 调试接口
/sys/kernel/debug/      # debugfs（需要 mount）
/sys/kernel/tracing/    # ftrace 接口

# 安全相关
/sys/fs/selinux/        # SELinux 控制接口
/sys/kernel/security/   # LSM 接口
```

### 8.2 可写接口审计

```bash
# 查找全局可写的 sysfs 文件
adb shell find /sys -type f -perm -o+w 2>/dev/null

# 查找 group 可写
adb shell find /sys -type f -perm -g+w 2>/dev/null

# 检查 SELinux 上下文
adb shell ls -laZ /sys/class/
adb shell ls -laZ /sys/devices/

# 检查敏感模块参数
adb shell cat /sys/module/*/parameters/* 2>/dev/null | head -50
```

### 8.3 常见攻击面

```bash
# GPU 驱动接口（高通 Adreno）
/sys/class/kgsl/kgsl-3d0/

# 显示驱动
/sys/class/graphics/fb0/

# 电源管理
/sys/class/power_supply/

# USB Gadget
/sys/kernel/config/usb_gadget/

# 蓝牙
/sys/class/bluetooth/
```

## 9. 实际调试命令示例

### 9.1 追踪特定驱动的 ioctl 调用

```bash
# 方法1: 使用 ftrace
adb shell "echo 0 > /sys/kernel/debug/tracing/tracing_on"
adb shell "echo > /sys/kernel/debug/tracing/trace"
adb shell "echo function_graph > /sys/kernel/debug/tracing/current_tracer"

# 假设要追踪 binder 驱动
adb shell "echo 'binder_ioctl' > /sys/kernel/debug/tracing/set_graph_function"
adb shell "echo 1 > /sys/kernel/debug/tracing/tracing_on"

# 执行触发 binder 操作
adb shell am start -a android.intent.action.MAIN

adb shell "echo 0 > /sys/kernel/debug/tracing/tracing_on"
adb shell cat /sys/kernel/debug/tracing/trace | head -100
```

### 9.2 使用 strace 追踪系统调用

```bash
# 追踪特定进程的 ioctl
adb shell strace -f -e ioctl -p $(pidof com.android.systemui) 2>&1 | head -50

# 追踪新启动进程
adb shell strace -f -e ioctl,openat /system/bin/app_process64 &

# 详细追踪包括参数
adb shell strace -v -s 256 -e ioctl cat /dev/binder
```

### 9.3 内存布局分析

```bash
# 查看进程内存布局
adb shell cat /proc/$(pidof zygote64)/maps

# 查看内核内存区域
adb shell cat /proc/iomem | head -30

# 查看 SLAB 分配情况
adb shell cat /proc/slabinfo | grep -E "^kmalloc|^filp"

# 查看页分配
adb shell cat /proc/pagetypeinfo | head -20
```

### 9.4 触发和观察崩溃

```bash
# 开启 kernel panic on oops
adb shell "echo 1 > /proc/sys/kernel/panic_on_oops"

# 查看 last_kmsg（需要支持 pstore）
adb shell cat /sys/fs/pstore/console-ramoops*

# 查看 tombstone
adb shell ls -la /data/tombstones/
adb shell cat /data/tombstones/tombstone_00

# 使用 crash 工具分析 vmcore（离线）
crash vmlinux vmcore
crash> bt
crash> log
crash> struct task_struct <addr>
```

### 9.5 使用 gdb 调试内核模块

```bash
# 获取模块加载地址
adb shell cat /proc/modules | grep mymodule
# mymodule 16384 0 - Live 0xffffff8001234000

# 加载模块符号到 gdb
(gdb) add-symbol-file mymodule.ko 0xffffff8001234000

# 设置断点
(gdb) break mymodule_ioctl
(gdb) continue

# 查看结构体
(gdb) p *(struct file *)$x0
(gdb) p ((struct my_private_data *)$x0->private_data)
```

### 9.6 实时监控 SELinux 拒绝

```bash
# 实时查看 avc 拒绝
adb shell dmesg -w | grep "avc:"

# 或使用 logcat
adb logcat -b events | grep avc

# 分析拒绝日志
adb shell cat /sys/fs/selinux/avc/cache_stats
```

## 10. 审计 checklist

1. 设备节点权限与 SELinux 标签是否合理（是否存在异常可写设备）
2. 驱动 ioctl 是否对调用方进行能力/权限校验
3. 用户态到内核态的数据结构拷贝是否严格检查长度与指针
4. 竞态风险点：引用计数、生命周期、锁顺序
5. /proc、/sys 可写接口是否过度暴露
6. 信息泄露：kallsyms、slabinfo、maps 访问控制

## 参考（AOSP）

- https://source.android.com/docs/core/architecture/kernel — AOSP 内核分层与术语（ACK/GKI/KMI）的官方入口，用于对齐"研究对象到底是哪一层"。
- https://source.android.com/docs/core/architecture/kernel/generic-kernel-image — GKI 的目标、KMI 稳定性与版本要求，用于校对"GKI 能解决什么/不能解决什么"。
- https://source.android.com/docs/security/overview/kernel-security — AOSP 从安全角度对内核攻击面与缓解方向的官方综述入口。
- https://www.kernel.org/doc/html/latest/trace/ftrace.html — Linux ftrace 官方文档
- https://www.kernel.org/doc/html/latest/dev-tools/kgdb.html — KGDB 官方文档
