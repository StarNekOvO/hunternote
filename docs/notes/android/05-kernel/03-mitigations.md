# 5x03 - Kernel Mitigations

为了对抗内核漏洞，Android 引入了多项硬件和软件缓解技术。

理解缓解的关键不是背缩写，而是把它们映射到"攻击链的哪个环节被打断"：

- 信息泄露是否更难
- 控制流劫持是否更难
- 内存破坏是否更容易被检测/终止

## 1. 软件缓解

### 1.1 KASLR (Kernel Address Space Layout Randomization)

内核地址空间布局随机化，每次启动时随机化内核代码和数据的加载地址。

**工作原理**：
```
// 内核启动时随机化基址
物理地址 = 固定基址 + 随机偏移 (通常 16-32 位熵)
虚拟地址 = 线性映射基址 + 物理偏移
```

**检查方法**：
```bash
# 查看内核配置 (需要 root)
adb shell zcat /proc/config.gz | grep RANDOMIZE
# CONFIG_RANDOMIZE_BASE=y
# CONFIG_RANDOMIZE_MODULE_REGION_FULL=y

# 多次重启比较内核符号地址
adb shell cat /proc/kallsyms | head -5
```

**Bypass 技术 (2024-2025)**：

| 技术 | 原理 | 代表性研究 |
|------|------|------------|
| Linear Map 非随机化 | Pixel 设备的线性映射和物理内存加载地址缺乏充分随机化 | Project Zero 2025 |
| Cache Timing Attack | 通过 prefetch 指令测量访问时间推断内核地址 | kaslr-bypass-via-prefetch |
| EntryBleed (CVE-2022-4543) | 利用 KPTI 的 syscall/interrupt 处理例外泄露地址 | USENIX Security 2023 |
| Side-channel via /proc | 某些 /proc 接口泄露内核指针 | 各种信息泄露 CVE |

**实际 Bypass 示例**：
```c
// Prefetch 侧信道攻击伪代码
#include <x86intrin.h>

uint64_t probe_address(void *addr) {
    uint64_t start, end;
    _mm_mfence();
    start = __rdtsc();
    _mm_prefetch(addr, _MM_HINT_T0);  // 预取目标地址
    _mm_mfence();
    end = __rdtsc();
    return end - start;  // 已映射地址访问更快
}

// 扫描可能的内核基址范围
for (uint64_t base = 0xffff800000000000; base < 0xffffffff00000000; base += 0x200000) {
    if (probe_address((void *)base) < THRESHOLD) {
        printf("Potential kernel base: 0x%lx\n", base);
    }
}
```

### 1.2 CFI (Control Flow Integrity)

控制流完整性，Android 内核使用 Clang kCFI 实现，限制间接调用目标集合。

**工作原理**：
```c
// 编译器为每个函数签名生成类型哈希
// 间接调用前验证目标函数的类型哈希

// 原始代码
void (*callback)(int, char *);
callback(1, "test");

// CFI 保护后 (伪代码)
if (__cfi_check(callback, TYPE_HASH_void_int_charptr) != VALID) {
    __cfi_fail();  // 触发内核 panic
}
callback(1, "test");
```

**检查方法**：
```bash
# 查看内核配置
adb shell zcat /proc/config.gz | grep CFI
# CONFIG_CFI_CLANG=y
# CONFIG_CFI_PERMISSIVE=n  # 生产环境应为 n

# 检查内核符号是否包含 CFI 检查函数
adb shell cat /proc/kallsyms | grep __cfi
```

**Bypass 策略**：

1. **寻找未保护路径**：第三方驱动可能未启用 CFI
   ```bash
   # 检查加载的模块是否有 CFI
   adb shell lsmod
   # 厂商模块可能编译时未启用 CFI
   ```

2. **数据流攻击**：CFI 只保护控制流，不保护数据
   ```c
   // 通过修改关键数据结构提权，无需劫持控制流
   struct cred *cred = current->cred;
   cred->uid = 0;  // 直接修改 UID
   cred->gid = 0;
   cred->cap_effective = CAP_FULL_SET;  // 修改 capabilities
   ```

3. **类型混淆**：找到签名兼容但功能不同的函数
   ```c
   // 如果两个函数签名相同，CFI 无法区分
   void legitimate_func(struct file *f);
   void gadget_func(struct file *f);  // 可被滥用的函数
   // 两者 CFI 哈希相同，可互换调用
   ```

### 1.3 SCS (Shadow Call Stack)

影子调用栈，将返回地址保存在独立的影子栈中，防止栈溢出覆盖返回地址。

**工作原理**：
```asm
// ARM64 SCS 实现
// x18 寄存器专门用于影子栈指针

function_prologue:
    str x30, [x18], #8    // 返回地址存入影子栈
    stp x29, x30, [sp, #-16]!  // 正常栈操作

function_epilogue:
    ldr x30, [x18, #-8]!  // 从影子栈恢复返回地址
    ldp x29, x30, [sp], #16  // (这个 x30 不使用)
    ret  // 使用影子栈的 x30
```

**检查方法**：
```bash
# 查看内核配置
adb shell zcat /proc/config.gz | grep SHADOW_CALL_STACK
# CONFIG_SHADOW_CALL_STACK=y

# 反汇编验证 (需要内核符号)
# 检查函数是否使用 x18 操作影子栈
```

**绕过条件**：
- 需要任意写原语同时修改主栈和影子栈
- 或找到不使用 SCS 的代码路径 (汇编、第三方模块)

## 2. 硬件增强

### 2.1 PAN (Privileged Access Never)

禁止内核直接访问用户态内存，必须通过 `copy_from_user`/`copy_to_user`。

**检查方法**：
```bash
# 检查 CPU 特性
adb shell cat /proc/cpuinfo | grep -i pan

# 检查内核配置
adb shell zcat /proc/config.gz | grep ARM64_PAN
# CONFIG_ARM64_PAN=y
```

**触发示例**：
```c
// 内核代码直接访问用户空间 - 会触发异常
void vulnerable_function(void __user *user_ptr) {
    // 错误方式：直接解引用用户指针
    int value = *(int *)user_ptr;  // PAN 异常！
    
    // 正确方式：使用安全函数
    int value;
    if (copy_from_user(&value, user_ptr, sizeof(value)))
        return -EFAULT;
}
```

### 2.2 PXN (Privileged Execute Never)

禁止内核执行用户空间代码，防止 ret2usr 攻击。

**历史攻击 (PXN 之前)**：
```c
// ret2usr 攻击：将内核控制流重定向到用户空间代码
void __attribute__((section(".text"))) shellcode() {
    commit_creds(prepare_kernel_cred(0));
}

// 内核漏洞利用时跳转到用户空间
// 现代设备：PXN 触发异常
```

### 2.3 PAC (Pointer Authentication Codes)

ARMv8.3 引入，为指针添加加密签名，防止指针篡改。

**工作原理**：
```
64-bit 指针布局 (PAC 启用):
┌─────────────────────────────────────────────────────────┐
│ PAC (高位)  │        有效虚拟地址 (48-52 bits)           │
│  (12-16 bits) │                                          │
└─────────────────────────────────────────────────────────┘

签名: PAC = QARMA(Key, Pointer, Context)
验证: if QARMA(Key, Pointer, Context) != StoredPAC → 异常
```

**检查方法**：
```bash
# 检查 CPU 特性
adb shell cat /proc/cpuinfo | grep -i paca

# 检查内核配置
adb shell zcat /proc/config.gz | grep PAUTH
# CONFIG_ARM64_PTR_AUTH=y
# CONFIG_ARM64_PTR_AUTH_KERNEL=y
```

**内核中的 PAC 使用**：
```c
// 返回地址保护
paciasp    // 函数入口：签名 LR
autiasp    // 函数返回：验证 LR

// 数据指针保护 (可选)
pacda x0, x1   // 签名数据指针
autda x0, x1   // 验证数据指针
```

**Bypass 研究方向**：
1. **Key 泄露**：通过侧信道或内存读取获得 PAC 密钥
2. **PAC Oracle**：找到能验证任意 PAC 的接口
3. **未保护路径**：厂商驱动可能未使用 PAC
4. **签名伪造**：收集大量有效 PAC 尝试碰撞

### 2.4 MTE (Memory Tagging Extension)

ARMv8.5 引入，为每 16 字节内存分配 4-bit 标签，检测内存安全违规。

**工作原理**：
```
内存布局:
┌──────────────────┬──────────────────┬──────────────────┐
│  16 bytes (Tag=5) │  16 bytes (Tag=9) │  16 bytes (Tag=2) │
└──────────────────┴──────────────────┴──────────────────┘

指针布局:
┌──────────┬─────────────────────────────────────────────┐
│ Tag (4bit) │              地址 (60 bits)                  │
└──────────┴─────────────────────────────────────────────┘

访问时：if 指针Tag != 内存Tag → 异常 (SIGSEGV/同步异常)
```

**模式**：
```bash
# 检查 MTE 配置
adb shell cat /proc/cpuinfo | grep -i mte

# 进程 MTE 模式
# - SYNC: 同步检查，精确定位，性能开销大
# - ASYNC: 异步检查，延迟报告，性能开销小  
# - ASYMM: 读同步/写异步，平衡模式
```

**检测能力**：
```c
// Use-After-Free 检测
char *ptr = kmalloc(64, GFP_KERNEL);  // Tag = 5
kfree(ptr);  // 内存重分配时 Tag 变为 9
ptr[0] = 'A';  // 指针 Tag=5 != 内存 Tag=9 → 检测到！

// 堆溢出检测
char *buf = kmalloc(32, GFP_KERNEL);  // Tag = 3
buf[32] = 'X';  // 越界访问不同 Tag 的内存 → 检测到！
```

**Bypass 技术 (2024-2025)**：

| 技术 | 原理 | 代表性研究 |
|------|------|------------|
| DSP/协处理器攻击 | 通过 Pixel GXP 等协处理器绕过 MTE 保护 | HITCON 2025, CODEBLUE 2025 |
| 逻辑漏洞 | 利用不涉及内存破坏的逻辑错误 | 各种条件竞争 CVE |
| Tag 碰撞 | 4-bit 只有 16 种可能，1/16 概率猜中 | 理论攻击 |
| 未启用 MTE 的路径 | 某些内存区域/模块可能未启用 MTE | 驱动审计 |

**实际 Bypass 案例 - DSP 攻击链**：
```
1. 发现 Pixel GXP (DSP) 通信接口漏洞
2. 获得 DSP 代码执行能力
3. DSP 可直接访问物理内存，不受 MTE 保护
4. 通过 DSP 修改内核内存，绕过所有缓解
```

## 3. 缓解组合与分层防护

### 3.1 攻击链视角

```
典型内核提权攻击链：

[漏洞触发] → [信息泄露] → [内存破坏] → [控制流劫持] → [提权]
     ↓            ↓            ↓             ↓           ↓
   seccomp      KASLR         MTE          CFI/PAC      SELinux
   沙箱          阻止         检测          阻止        限制
```

### 3.2 设备缓解状态检查脚本

```bash
#!/bin/bash
# mitigation_check.sh - 检查 Android 设备缓解状态

echo "=== CPU 特性 ==="
adb shell cat /proc/cpuinfo | grep -E "Features|model name" | head -2

echo -e "\n=== 内核版本 ==="
adb shell uname -a

echo -e "\n=== 内核配置 (需要 root) ==="
adb shell "su -c 'zcat /proc/config.gz'" 2>/dev/null | grep -E \
    "RANDOMIZE_BASE|CFI_CLANG|SHADOW_CALL|ARM64_PAN|ARM64_MTE|PTR_AUTH" || \
    echo "无法访问 /proc/config.gz (需要 root)"

echo -e "\n=== SELinux 状态 ==="
adb shell getenforce

echo -e "\n=== seccomp 状态 ==="
adb shell cat /proc/self/status | grep Seccomp

echo -e "\n=== ASLR 状态 ==="
adb shell cat /proc/sys/kernel/randomize_va_space
# 2 = 完全随机化
```

### 3.3 各厂商缓解差异

| 厂商 | 特有缓解 | 备注 |
|------|----------|------|
| Google Pixel | MTE (Pixel 8+), hypervisor 隔离 | 最激进的缓解部署 |
| Samsung | KNOX, RKP (Real-time Kernel Protection), DEFEX | 自研防护层 |
| Qualcomm | QHEE (Qualcomm Hypervisor), QTEE | 芯片级安全 |
| MediaTek | MTK TEE, 自定义 hypervisor | 部分设备缓解较弱 |

## 4. 实战：绕过缓解的研究方法

### 4.1 研究流程

```
1. 确定目标设备缓解状态
   ↓
2. 寻找信息泄露原语 (绕过 KASLR)
   ↓
3. 寻找内存读写原语 (规避 MTE 或处理 Tag)
   ↓
4. 构造提权原语
   - 数据流攻击 (绕过 CFI)
   - 修改 cred 结构
   - 修改 SELinux 上下文
   ↓
5. 稳定化利用
```

### 4.2 常用原语类型

**信息泄露原语**：
```c
// 利用未初始化内存泄露内核指针
struct leak_struct {
    void *kernel_ptr;  // 未清零，包含残留指针
    char data[64];
};

// 利用 /proc 或 /sys 接口泄露
// 某些接口可能打印内核地址
```

**任意读写原语**：
```c
// 常见的 UAF → 任意读写转换
// 1. 触发 UAF，释放目标对象
// 2. 用可控内容重新占用 (堆喷射)
// 3. 通过悬空指针读写伪造对象

// 提权 payload
void escalate_privileges(void *arb_write) {
    struct cred *cred = current_cred();
    // 修改 cred->uid/gid/cap_* 为 root
    arb_write(cred + offsetof(struct cred, uid), 0);
    arb_write(cred + offsetof(struct cred, euid), 0);
    // ...
}
```

### 4.3 CVE-2025-38352 (Chronomaly) 利用分析

这是 2025 年公开的一个典型内核提权漏洞：

```c
// 漏洞：POSIX CPU 定时器竞争条件
// 位置：kernel/time/posix-cpu-timers.c

// 竞争窗口
Thread A: 进程退出，变成僵尸进程
Thread B: handle_posix_cpu_timers() 访问已释放的 task_struct

// 利用策略 (不依赖 KASLR bypass)
1. 创建大量线程扩大竞争窗口
2. 触发 UAF，task_struct 被释放
3. 堆喷射占用释放的内存
4. 通过定时器回调执行提权代码
```

## 5. 参考资源

### 官方文档
- [Android Kernel Security](https://source.android.com/docs/security/overview/kernel-security)
- [Android Security Features](https://source.android.com/docs/security/features)
- [ARM MTE Documentation](https://developer.arm.com/documentation/102433/latest/)
- [ARM PAC Documentation](https://developer.arm.com/documentation/102433/latest/)

### 研究资源
- [Project Zero: Defeating KASLR by Doing Nothing](https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html)
- [GitHub Blog: Android Kernel Mitigations Obstacle Race](https://github.blog/security/vulnerability-research/the-android-kernel-mitigations-obstacle-race/)
- [HITCON 2025: Cracking Pixel 8 MTE via DSP](https://hitcon.org/2025/slides/)
- [Chronomaly Exploit PoC](https://github.com/farazsth98/chronomaly)
- [Android Kernel CVE PoCs Collection](https://github.com/ScottyBauer/Android_Kernel_CVE_POCs)
