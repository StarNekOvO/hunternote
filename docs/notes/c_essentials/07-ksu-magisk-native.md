# 07 - KernelSU/Magisk Native

Android Root 工具的 C/内核层实现分析。

---

## 概念速览

**为什么要学这个？**
- 理解 Android Root 机制
- 内核级别安全研究基础
- 逆向分析的知识需求

**主流 Root 工具对比：**

| 工具 | 实现方式 | 检测难度 |
|------|----------|----------|
| Magisk | 修改 boot.img | 中等 |
| KernelSU | 内核模块 | 较高 |
| su 二进制 | setuid | 低（已过时）|

---

## 核心概念

### Root 的本质

**什么是 Root？**
```
普通 App: UID >= 10000
系统服务: UID 1000 (system)
Root:     UID 0
```

**获取 Root 需要什么？**
1. 在内核权限下运行代码
2. 修改进程的 credentials
3. 绑定 su 服务供应用调用

### credential 结构

```c
// include/linux/cred.h
struct cred {
    atomic_t usage;
    uid_t uid;          // 实际用户 ID
    uid_t euid;         // 有效用户 ID
    uid_t suid;         // 保存的用户 ID
    gid_t gid;
    gid_t egid;
    gid_t sgid;
    // ... 
    struct user_struct *user;
    struct group_info *group_info;
    struct key *session_keyring;
    // ...
};
```

**如何提权？**

```c
// 简化版：内核中提权
struct cred *new_cred = prepare_creds();
new_cred->uid = GLOBAL_ROOT_UID;
new_cred->gid = GLOBAL_ROOT_GID;
new_cred->euid = GLOBAL_ROOT_UID;
new_cred->egid = GLOBAL_ROOT_GID;
// ...
commit_creds(new_cred);
// 进程现在是 root！
```

---

## KernelSU 实现

### 架构概览

```
┌─────────────────────────────────────┐
│           用户空间 App              │
│      (请求 root 权限)               │
├─────────────────────────────────────┤
│           KernelSU Manager          │ ← 管理界面
├─────────────────────────────────────┤
│        KernelSU Kernel Module       │ ← 内核模块
│   ┌─────────────────────────────┐   │
│   │ syscall hook (prctl)        │   │
│   │ credential modification     │   │
│   │ SELinux bypass              │   │
│   └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

### 系统调用 Hook

KernelSU 通过 hook `prctl` 系统调用实现通信：

```c
// 简化版原理
static int ksu_handle_prctl(int option, unsigned long arg2,
                            unsigned long arg3, unsigned long arg4,
                            unsigned long arg5)
{
    // 特殊的 magic 值判断
    if (option == KSU_MAGIC) {
        switch (arg2) {
        case CMD_GET_VERSION:
            return KSU_VERSION;
            
        case CMD_BECOME_ROOT:
            if (is_allowed(current)) {
                // 提权
                grant_root();
                return 0;
            }
            return -EPERM;
            
        case CMD_CHECK_ALLOWED:
            return is_allowed_uid(arg3) ? 1 : 0;
        }
    }
    
    // 调用原始 prctl
    return original_prctl(option, arg2, arg3, arg4, arg5);
}
```

### 权限修改

```c
static void grant_root(void)
{
    struct cred *new_cred;
    
    // 准备新凭证
    new_cred = prepare_creds();
    if (!new_cred)
        return;
    
    // 设置 UID/GID 为 root
    new_cred->uid = GLOBAL_ROOT_UID;
    new_cred->gid = GLOBAL_ROOT_GID;
    new_cred->euid = GLOBAL_ROOT_UID;
    new_cred->egid = GLOBAL_ROOT_GID;
    new_cred->suid = GLOBAL_ROOT_UID;
    new_cred->sgid = GLOBAL_ROOT_GID;
    new_cred->fsuid = GLOBAL_ROOT_UID;
    new_cred->fsgid = GLOBAL_ROOT_GID;
    
    // 设置所有 capabilities
    new_cred->cap_effective = CAP_FULL_SET;
    new_cred->cap_permitted = CAP_FULL_SET;
    new_cred->cap_inheritable = CAP_FULL_SET;
    new_cred->cap_bset = CAP_FULL_SET;
    
    // 应用新凭证
    commit_creds(new_cred);
}
```

### SELinux 绕过

Android 的 SELinux 会阻止未授权操作：

```c
// 简化版 SELinux 相关处理
static void setup_selinux_context(void)
{
    // 方法1: 修改进程的 SELinux 上下文
    // 方法2: 临时禁用 SELinux 检查
    // 方法3: 添加允许规则
    
    // KernelSU 使用动态策略注入
}
```

---

## Magisk 实现

### 架构概览

```
┌─────────────────────────────────────┐
│           Magisk Manager            │ ← 用户界面 (Java/Kotlin)
├─────────────────────────────────────┤
│            magiskd                  │ ← 守护进程 (Rust)
├─────────────────────────────────────┤
│          magiskinit                 │ ← 启动注入 (Rust + C)
├─────────────────────────────────────┤
│           boot.img                  │ ← 修改的 ramdisk
└─────────────────────────────────────┘
```

### magiskinit (C 部分)

启动时最先运行，负责初始化：

```c
// 简化版 magiskinit 逻辑
int main(int argc, char **argv) {
    // 1. 检测启动模式
    if (is_recovery_mode()) {
        exec_recovery_init();
        return 0;
    }
    
    // 2. 挂载必要的文件系统
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    
    // 3. 加载 sepolicy 并注入规则
    load_sepolicy();
    patch_sepolicy();
    
    // 4. 启动真正的 init
    exec_init();
    
    return 0;
}
```

### MagiskHide (已废弃的例子)

检测隐藏原理：

```c
// 隐藏技术：unmount 敏感路径
static void hide_from_app(pid_t pid) {
    char path[256];
    
    // 进入目标进程的 namespace
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    int fd = open(path, O_RDONLY);
    setns(fd, CLONE_NEWNS);
    close(fd);
    
    // 解除 Magisk 相关挂载
    umount2("/sbin", MNT_DETACH);
    umount2("/system/bin/su", MNT_DETACH);
    // ...
}
```

> [!NOTE]
> MagiskHide 已被 Zygisk DenyList 取代。

---

## 实战场景

### Lab 1: 检测 KernelSU

```c
#include <stdio.h>
#include <sys/prctl.h>

#define KERNEL_SU_OPTION 0xDEADBEEF

int main(void) {
    int result = prctl(KERNEL_SU_OPTION, 0, 0, 0, 0);
    
    if (result > 0) {
        printf("KernelSU detected, version: %d\n", result);
    } else {
        printf("KernelSU not detected\n");
    }
    
    return 0;
}
```

### Lab 2: 理解 capabilities

```c
#include <stdio.h>
#include <sys/capability.h>

int main(void) {
    cap_t caps = cap_get_proc();
    
    printf("Current capabilities:\n");
    printf("%s\n", cap_to_text(caps, NULL));
    
    cap_free(caps);
    return 0;
}
```

```bash
# 普通用户
./caps
# =

# root
sudo ./caps
# = cap_chown,cap_dac_override,...+ep
```

### Lab 3: 模块系统

```c
// Magisk 模块的 post-fs-data.sh 执行原理
static void run_modules(void) {
    DIR *dir = opendir("/data/adb/modules");
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            char script[256];
            snprintf(script, sizeof(script),
                     "/data/adb/modules/%s/post-fs-data.sh",
                     entry->d_name);
            
            if (access(script, X_OK) == 0) {
                // 执行模块脚本
                system(script);
            }
        }
    }
    closedir(dir);
}
```

---

## Root 检测与绕过

### 常见检测方法

```c
// 1. 检查 su 二进制
if (access("/system/bin/su", F_OK) == 0)
    return ROOTED;

// 2. 检查包名
// Magisk Manager, KernelSU Manager 等

// 3. 检查挂载点
FILE *f = fopen("/proc/mounts", "r");
// 搜索可疑挂载

// 4. 检查属性
char value[PROP_VALUE_MAX];
__system_property_get("ro.debuggable", value);

// 5. 检查 Zygote 环境
// 检测注入
```

### 安全研究角度

```c
// 研究 Root 绕过时的安全考量：
// 1. 理解检测点
// 2. 分析执行流程
// 3. 不用于恶意目的
```

---

## 常见陷阱

### ❌ 陷阱 1: 内核版本兼容

```c
// 错误：硬编码偏移
cred->uid = *(kuid_t *)((char *)cred + 0x04);

// 正确：使用内核定义
cred->uid = GLOBAL_ROOT_UID;
```

### ❌ 陷阱 2: 竞态条件

```c
// 检查和使用之间的 TOCTOU
if (is_allowed(current)) {
    // 此时进程可能已改变
    grant_root();
}
```

### ❌ 陷阱 3: SELinux 恢复

修改 SELinux 后需要正确恢复：

```c
// 否则可能导致系统功能异常
```

### ❌ 陷阱 4: 日志泄露

```c
// 不要在生产环境记录敏感信息
pr_info("Granting root to pid %d\n", task_pid_nr(current));
```

---

## 深入阅读

**推荐资源：**
- [KernelSU 源码](https://github.com/tiann/KernelSU)
- [Magisk 源码](https://github.com/topjohnwu/Magisk)

**Android 安全相关：**
- [SELinux for Android](/notes/android/05-kernel/01-selinux)
- [内核安全](/notes/android/05-kernel/)

---

## 系列总结

C Essentials 完成！你现在应该能够：

- ✅ 理解 C 语言核心概念
- ✅ 理解内存布局和漏洞类型
- ✅ 阅读和编写内核模块
- ✅ 理解 Android 驱动和 Root 工具

---

## 下一步

继续学习：
- [Java Essentials](../java_essentials/) - Framework 开发
- [Rust Essentials](../rust_essentials/) - 内存安全编程
- [Android Security Notes](../android/) - 深入安全研究
