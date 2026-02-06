# 04 - 调试技巧

GDB、Ghidra、crash dump 分析。


## 概念速览

**调试的核心能力：**
- 断点、单步、观察寄存器
- 读懂反汇编
- 分析 crash dump

**安全研究场景：**
- 复现和分析 CVE
- 开发 exploit 时调试
- 逆向闭源组件


## GDB 基础

### 启动调试

```bash
# 本地调试
gdb ./binary

# 远程调试 (Android)
adb forward tcp:1234 tcp:1234
adb shell gdbserver :1234 /data/local/tmp/binary
gdb-multiarch -ex "target remote :1234" ./binary

# 附加到进程
gdb -p <pid>
```

### 基本命令

| 命令 | 缩写 | 功能 |
|------|------|------|
| `break *0x400100` | `b` | 设置断点 |
| `continue` | `c` | 继续执行 |
| `stepi` | `si` | 单步 (进入函数) |
| `nexti` | `ni` | 单步 (跳过函数) |
| `info registers` | `i r` | 查看寄存器 |
| `x/10i $pc` | | 查看指令 |
| `x/10gx $sp` | | 查看栈 |
| `disassemble` | `disas` | 反汇编当前函数 |
| `backtrace` | `bt` | 调用栈 |

### 查看内存

```
(gdb) x/10gx $sp          # 10 个 64 位值
(gdb) x/10wx $sp          # 10 个 32 位值
(gdb) x/10bx $sp          # 10 个字节
(gdb) x/s $x0             # 字符串
(gdb) x/10i $pc           # 10 条指令
```

**格式说明：**
- `g` = giant (8 bytes)
- `w` = word (4 bytes)
- `b` = byte
- `x` = hex
- `d` = decimal
- `s` = string
- `i` = instruction

### 修改执行

```
(gdb) set $x0 = 0x1234    # 修改寄存器
(gdb) set *(int*)0x7fff = 42  # 修改内存
(gdb) jump *0x400200      # 跳转到地址
(gdb) return              # 强制从当前函数返回
```


## GEF (GDB 增强)

### 安装

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

### 常用功能

```
gef> context             # 显示上下文 (寄存器, 栈, 代码)
gef> vmmap               # 内存映射
gef> checksec            # 安全特性检查
gef> rop                 # 搜索 ROP gadget
gef> search-pattern      # 搜索模式
gef> heap                # 堆信息
```

### 效果

```
─────────────────────────────────── registers ────
$x0  : 0x0000000000000001
$x1  : 0x0000fffffffff230  →  "Hello"
$x2  : 0x0000000000000005
...
───────────────────────────────────── stack ──────
0x0000fffffffff200│+0x0000: 0x0000000000400580  ← $sp
0x0000fffffffff208│+0x0008: 0x0000000000400620
...
───────────────────────────────────── code ───────
 → 0x400580 <main+0>     stp    x29, x30, [sp, #-32]!
   0x400584 <main+4>     mov    x29, sp
```


## 反汇编工具

### objdump

```bash
# 反汇编全部
aarch64-linux-gnu-objdump -d binary

# 只反汇编某个函数
aarch64-linux-gnu-objdump -d binary | grep -A 50 "<main>:"

# 显示源码对应 (需要 -g 编译)
aarch64-linux-gnu-objdump -dS binary
```

### Ghidra

```bash
# 启动
ghidraRun

# 或命令行分析
analyzeHeadless /path/to/project ProjectName \
    -import binary \
    -postScript ExportAsm.java
```

**Ghidra 快捷键：**

| 快捷键 | 功能 |
|--------|------|
| `G` | 跳转到地址 |
| `L` | 重命名 |
| `;` | 添加注释 |
| `D` | 反汇编 |
| `F` | 创建函数 |
| `X` | 查找交叉引用 |

### IDA Pro

```
快捷键:
- G: 跳转
- N: 重命名
- X: Xrefs
- Space: 切换视图
- Tab: 伪代码
```


## Crash Dump 分析

### Android Tombstone

```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/...'
Abort message: 'stack corruption detected'
ABI: 'arm64'
pid: 1234, tid: 1234, name: target  >>> /data/local/tmp/target <<<
signal 6 (SIGABRT), code -1 (SI_QUEUE), fault addr --------
    x0  0000000000000000  x1  00000000000004d2  x2  0000000000000006
    x3  0000000000000008  x4  6562203a53444141  x5  7265747361206e20
    x6  0000000000000074  x7  0000007463617473  x8  00000000000000f0
    x9  0000000000000001  x10 0000000000000000  x11 0000000000000001
    ...
    sp  0000007fc5c2c870  lr  0000007fb7c12a80  pc  0000007fb7c12a88

backtrace:
      #00 pc 0000000000050a88  /apex/com.android.runtime/lib64/bionic/libc.so (abort+168)
      #01 pc 0000000000050b04  /apex/com.android.runtime/lib64/bionic/libc.so (__fortify_fatal+...)
      #02 pc 000000000004fa28  /apex/com.android.runtime/lib64/bionic/libc.so (__stack_chk_fail+...)
      #03 pc 0000000000001234  /data/local/tmp/target (vuln_func+100)
```

**分析要点：**
1. Signal 类型 (SIGSEGV, SIGABRT, ...)
2. PC 值 → 崩溃位置
3. 寄存器值 → 参数/状态
4. Backtrace → 调用链

### dmesg (内核日志)

```bash
adb shell dmesg | tail -50
```

```
[  123.456789] Unable to handle kernel paging request at virtual address dead000000000000
[  123.456790] Mem abort info:
[  123.456791]   ESR = 0x96000004
[  123.456792]   Exception class = DABT (current EL), IL = 32 bits
[  123.456793]   SET = 0, FnV = 0
[  123.456794]   EA = 0, S1PTW = 0
[  123.456795] Data abort info:
[  123.456796]   ISV = 0, ISS = 0x00000004
[  123.456797]   CM = 0, WnR = 0
[  123.456798] user pance:
[  123.456799] CPU: 0 PID: 1234 Comm: exploit
[  123.456800] pc : 0xffffffc000123456
[  123.456801] lr : 0xffffffc000123450
[  123.456802] sp : 0xffffffc012345670
```


## 实战场景

### Lab 1: 调试 Segfault

**目标：** 找到崩溃原因

```c
// crash.c
#include <string.h>

void crash_me(char *input) {
    char buf[16];
    strcpy(buf, input);  // 漏洞
}

int main(int argc, char **argv) {
    if (argc > 1) {
        crash_me(argv[1]);
    }
    return 0;
}
```

**调试过程：**
```bash
# 编译
aarch64-linux-gnu-gcc -g -fno-stack-protector -o crash crash.c

# 运行崩溃
qemu-aarch64 ./crash $(python3 -c "print('A'*100)")
# Segmentation fault

# GDB 调试
qemu-aarch64 -g 1234 ./crash $(python3 -c "print('A'*100)") &
gdb-multiarch -ex "target remote :1234" ./crash

(gdb) continue
# 停在崩溃点

(gdb) info registers
# 查看哪个寄存器包含 0x41414141 (AAAA)

(gdb) x/s $x30
# 查看返回地址是否被覆盖
```

### Lab 2: 分析 ROP Gadget

**目标：** 用 GDB 分析 gadget 行为

```bash
# 找 gadget
ROPgadget --binary /lib/aarch64-linux-gnu/libc.so.6 | grep "ldp x19, x20"

# 在 GDB 中验证
(gdb) break *0x7ffff7e12345
(gdb) continue
(gdb) x/5i $pc
(gdb) info registers x19 x20 x29 x30
(gdb) stepi
(gdb) info registers x19 x20 x29 x30
# 观察变化
```

### Lab 3: 逆向 Android Native 库

**目标：** 分析 JNI 函数

```bash
# 从设备提取
adb pull /data/app/com.target.app/.../lib/arm64/libnative.so

# Ghidra 分析
# 1. 导入文件
# 2. 搜索 "Java_" 找到 JNI 函数
# 3. 分析函数逻辑
```

**常见 JNI 模式：**
```asm
// JNIEnv 调用
ldr x8, [x0]              // vtable
ldr x8, [x8, #0x548]      // GetStringUTFChars offset
blr x8
```


## 常见陷阱

### ❌ 陷阱 1: PIE 地址变化

```bash
# 问题：每次运行地址都不同
(gdb) break *0x555555554000
# 断点可能不命中

# 解决：使用符号或偏移
(gdb) break main
(gdb) break *main+100
```

### ❌ 陷阱 2: 优化导致代码消失

```bash
# -O2 优化可能删除代码
# 解决：用 -O0 调试

# 或检查具体优化
aarch64-linux-gnu-gcc -O2 -S code.c
# 查看生成的汇编
```

### ❌ 陷阱 3: ASLR 干扰

```bash
# 临时禁用 ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Android 上
adb shell "echo 0 > /proc/sys/kernel/randomize_va_space"
```

### ❌ 陷阱 4: 断点在循环外

```bash
# 可能断点设错位置
# 使用条件断点
(gdb) break *0x400100 if $x0 == 42
```


## Android 调试

### 调试 Native 代码

```bash
# 1. 启动调试服务
adb shell "su -c 'gdbserver64 :1234 --attach <pid>'"

# 2. 连接
adb forward tcp:1234 tcp:1234
gdb-multiarch
(gdb) target remote :1234
(gdb) set solib-search-path /path/to/symbols
```

### 调试 init 进程

```bash
# 需要 userdebug/eng 编译
adb shell setprop ro.debuggable 1
adb shell stop
adb shell start
```

### 使用 LLDB

```bash
# Android 偏好 LLDB
lldb
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
(lldb) attach <pid>
```


## 深入阅读

**推荐资源：**
- [GDB Documentation](https://sourceware.org/gdb/documentation/)
- [Ghidra Wiki](https://github.com/NationalSecurityAgency/ghidra/wiki)
- [Azeria Labs Debugging](https://azeria-labs.com/debugging-arm-with-gdb/)

**相关章节：**
- [05 - 控制流劫持](./05-control-flow-hijack.md) - 调试 ROP chain
- [07 - Exploit 开发](./07-exploit-development.md) - 完整调试流程


## 下一步

[05 - 控制流劫持](./05-control-flow-hijack.md) — ROP、JOP、ret2libc
