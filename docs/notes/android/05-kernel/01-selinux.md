# 5x01 - SELinux on Android

SELinux (Security-Enhanced Linux) 是 Android 强制访问控制 (MAC) 的核心。

SELinux 的目标不是"阻止一切 bug"，而是把 bug 的影响范围收窄：即使某个进程出现漏洞，进程也只能在其 domain 授权的范围内访问资源。

## 1. 运行模式
- **Permissive**: 仅记录违规行为，不拦截（通常用于开发调试）。
- **Enforcing**: 强制拦截违规行为（生产环境默认）。

研究时经常需要明确系统处于哪种模式，因为 permissive 环境下的行为与生产环境可能完全不同。

## 2. 核心概念
- **Domain (域)**: 进程的安全上下文（如 `u:r:untrusted_app:s0`）。
- **Type (类型)**: 资源的安全上下文（如 `u:object_r:app_data_file:s0`）。
- **Policy (策略)**: 定义了哪个 Domain 可以对哪个 Type 执行什么操作。

补充几个在 Android 上很常见的概念：

- **attribute**：一组 type/domain 的集合，用于批量授权
- **file context**：路径到 type 的映射（文件/目录最终是什么标签）
- **transition**：进程执行某个入口后 domain 切换（例如某服务从 init 启动后进入特定域）

## 3. SELinux 策略文件结构

Android SELinux 策略由多个文件组成，理解其结构是分析和绕过的基础。

### 3.1 策略文件位置

**AOSP 源码中的策略目录**：
```
system/sepolicy/
├── public/          # 公开 API，可被 vendor 引用
├── private/         # 系统私有策略
├── vendor/          # vendor 可定制部分
├── prebuilts/       # 预编译策略
└── Android.bp       # 构建配置
```

**设备上的策略文件**：
```
/sys/fs/selinux/policy           # 当前加载的二进制策略
/sepolicy                        # boot image 中的策略（旧版本）
/vendor/etc/selinux/             # vendor 策略
/system/etc/selinux/             # system 策略
/odm/etc/selinux/                # ODM 策略
```

### 3.2 关键策略文件类型

| 文件类型 | 扩展名 | 用途 |
|---------|--------|------|
| Type Enforcement | `.te` | 定义 domain/type 及 allow 规则 |
| File Contexts | `file_contexts` | 路径到 type 的映射 |
| Property Contexts | `property_contexts` | 系统属性到 type 的映射 |
| Service Contexts | `service_contexts` | Binder 服务到 type 的映射 |
| Seapp Contexts | `seapp_contexts` | 应用进程 domain 分配规则 |

### 3.3 策略规则语法

**allow 规则**：
```
allow source_domain target_type:target_class permissions;

# 示例：允许 untrusted_app 读取 app_data_file 类型的文件
allow untrusted_app app_data_file:file { read open getattr };
```

**type_transition 规则**：
```
type_transition source_domain target_type:class new_type;

# 示例：init 执行 /system/bin/app_process 后切换到 zygote domain
type_transition init zygote_exec:process zygote;
```

**neverallow 规则**：
```
neverallow source_domain target_type:class permissions;

# 示例：禁止 untrusted_app 访问 kernel 文件
neverallow untrusted_app kernel:file *;
```

### 3.4 从设备提取策略

```bash
# 提取二进制策略
adb pull /sys/fs/selinux/policy sepolicy.bin

# 提取 file_contexts
adb pull /system/etc/selinux/plat_file_contexts
adb pull /vendor/etc/selinux/vendor_file_contexts

# 提取 property_contexts
adb pull /system/etc/selinux/plat_property_contexts
```

## 4. 策略审计工具

分析 SELinux 策略需要专用工具，以下是常用的审计工具。

### 4.1 sesearch

`sesearch` 用于搜索策略中的规则。

```bash
# 安装（Ubuntu/Debian）
sudo apt install setools

# 搜索所有允许 untrusted_app 的规则
sesearch -A -s untrusted_app sepolicy.bin

# 搜索特定权限
sesearch -A -s untrusted_app -t app_data_file -c file sepolicy.bin

# 搜索 type_transition 规则
sesearch -T -s init sepolicy.bin

# 搜索 neverallow 规则
sesearch --neverallow sepolicy.bin
```

**输出示例**：
```
allow untrusted_app app_data_file:file { append create getattr ioctl ... };
allow untrusted_app app_data_file:dir { add_name create getattr ... };
```

### 4.2 seinfo

`seinfo` 用于查看策略的元信息。

```bash
# 查看所有 type
seinfo -t sepolicy.bin

# 查看所有 attribute
seinfo -a sepolicy.bin

# 查看特定 type 的 attribute
seinfo -t untrusted_app -x sepolicy.bin

# 查看所有 class
seinfo -c sepolicy.bin

# 统计信息
seinfo sepolicy.bin
```

**输出示例**：
```
Types: 1247    Attributes: 89
Classes: 83    Permissions: 267
Booleans: 0    Sensitivities: 1
Categories: 1024
```

### 4.3 audit2allow

`audit2allow` 从 AVC denial 日志生成 allow 规则。

```bash
# 从 dmesg 生成规则
adb shell dmesg | audit2allow -p sepolicy.bin

# 从 logcat 生成规则
adb logcat -d | grep 'avc: denied' | audit2allow -p sepolicy.bin

# 输出可直接使用的 .te 文件
adb shell dmesg | audit2allow -p sepolicy.bin -o fix.te

# 生成 reference policy 模块
adb shell dmesg | audit2allow -p sepolicy.bin -R
```

**注意**：`audit2allow` 生成的规则可能过于宽松，应人工审核后再使用。

### 4.4 其他实用工具

**sepolicy-analyze (AOSP)**：
```bash
# 检查 neverallow 违规
sepolicy-analyze sepolicy.bin neverallow -n neverallow_rules

# 查找可达路径
sepolicy-analyze sepolicy.bin permissive

# 查找 attribute 成员
sepolicy-analyze sepolicy.bin attribute domain
```

**apol (SETools GUI)**：
```bash
# 图形化策略分析
apol sepolicy.bin
```

## 5. 安全审计

- **Neverallow**: 策略中绝对禁止出现的规则，用于防止策略过于宽松。
- **MLS/MCS**: 通过安全级别/类别（Android 常见的是 MCS categories）来做额外隔离；具体落地依设备与厂商策略而定。

## 6. AVC Denial 排查方法

最常见的现场问题是遇到 `avc: denied`。

### 6.1 收集信息

- `adb logcat | grep -i 'avc: denied'`
- 若存在内核侧日志：`adb shell dmesg | grep -i avc`

典型日志会包含：

- `scontext`（来源 domain）
- `tcontext`（目标 type）
- `tclass`（对象类别：file/dir/socket/process 等）
- `perm`（尝试的操作：read/write/execute/connectto 等）

### 6.2 判断性质

- 若是系统组件正常功能被拦截：说明策略缺规则或上下文打标错误
- 若是低权限进程试图访问高敏感资源：可能是攻击尝试或漏洞链路

### 6.3 常见根因

- 文件/目录标签不对（file_contexts 配置或打包问题）
- 服务进程 domain 不对（init 启动配置或 transition 不生效）
- 访问路径不对（实际访问了不同的文件/设备节点）

## 7. SELinux Bypass 技术

### 7.1 策略漏洞利用

**过于宽松的 allow 规则**：

vendor 定制策略经常出现过于宽松的规则：

```
# 危险：允许 shell 访问所有 vendor 文件
allow shell vendor_file:file *;

# 危险：允许 app 访问设备节点
allow untrusted_app device:chr_file { read write };
```

**审计方法**：
```bash
# 查找 wildcard 权限
sesearch -A sepolicy.bin | grep '\*'

# 查找敏感 type 的访问者
sesearch -A -t kernel_data_file sepolicy.bin
sesearch -A -t proc_kmsg sepolicy.bin
```

**attribute 滥用**：

当一个 domain 被加入过于宽泛的 attribute 时，会继承大量权限：

```bash
# 查看 domain 所属的 attribute
seinfo -t vendor_init -x sepolicy.bin

# 查看 attribute 拥有的权限
sesearch -A -s coredomain sepolicy.bin | wc -l
```

### 7.2 内核模块注入绕过

SELinux 策略在内核空间执行，如果攻击者能加载内核模块，可以直接绕过 SELinux。

**攻击原理**：
1. 利用内核漏洞获取内核代码执行能力
2. 修改 `selinux_enforcing` 变量（设为 0）
3. 或 hook `avc_has_perm` 函数使其永远返回成功
4. 或直接修改进程的 security credentials

**内核符号定位**：
```c
// selinux_enforcing 控制 enforcing/permissive 模式
// 位置：security/selinux/selinuxfs.c
extern int selinux_enforcing;

// avc_has_perm 是权限检查的核心函数
// 位置：security/selinux/avc.c
int avc_has_perm(struct selinux_state *state,
                 u32 ssid, u32 tsid,
                 u16 tclass, u32 requested,
                 struct common_audit_data *auditdata);
```

**防御检测**：
```bash
# 检查 enforcing 状态是否被篡改
adb shell cat /sys/fs/selinux/enforce

# 检查内核完整性（如果有 dm-verity）
adb shell getprop ro.boot.verifiedbootstate
```

### 7.3 逻辑错误利用

SELinux 策略逻辑错误可能导致意外的权限泄露。

**常见逻辑错误类型**：

1. **type_transition 链断裂**：进程未能切换到预期的受限 domain
2. **条件规则误用**：booleans 配置错误导致规则生效/失效异常
3. **domain 继承问题**：fork 后子进程继承了不应有的权限
4. **MCS 分类错误**：不同安全级别的进程能相互访问

**检测方法**：
```bash
# 查找可能的 transition 问题
sesearch -T sepolicy.bin | grep -v 'type_transition'

# 检查 permissive domain（不应存在于生产环境）
seinfo -t sepolicy.bin | xargs -I {} sesearch -A -s {} -p permissive sepolicy.bin
```

## 8. CVE-2025-0078 分析

CVE-2025-0078 是一个 SELinux 策略评估中的逻辑错误漏洞，影响 Android 内核的权限检查流程。

### 8.1 漏洞背景

该漏洞存在于 SELinux 的 sidtab（Security ID Table）处理逻辑中。当系统在特定条件下进行 SID 查找时，可能返回错误的安全上下文，导致权限检查被绕过。

### 8.2 技术细节

**漏洞位置**：`security/selinux/ss/sidtab.c`

**问题代码逻辑**：
```c
// 简化的漏洞逻辑示意
static int sidtab_context_to_sid(struct sidtab *s,
                                  struct context *context,
                                  u32 *sid)
{
    // 在并发场景下，hash 查找可能返回错误的 entry
    // 导致 context 与实际 sid 不匹配
    entry = sidtab_search_context(s, context);
    if (entry) {
        *sid = entry->sid;  // 可能返回错误的 sid
        return 0;
    }
    // ...
}
```

**触发条件**：
1. 系统处于高并发状态（多个进程同时进行权限检查）
2. sidtab 正在进行 rehash 或扩容操作
3. 新的安全上下文正在被添加到表中

### 8.3 利用方式

攻击者可以通过以下步骤利用该漏洞：

1. **构造竞争条件**：创建大量进程触发 sidtab 操作
2. **时序窗口捕获**：在 sidtab 更新的瞬间发起权限请求
3. **权限提升**：利用返回的错误 SID 获得意外权限

**PoC 概念**：
```c
// 伪代码：触发竞争条件
void trigger_race() {
    // 1. 创建多个线程执行不同安全上下文的操作
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, context_switch_worker, NULL);
    }
    
    // 2. 在主线程尝试访问受限资源
    // 如果时序正确，可能获得错误的（更高权限的）SID
    while (!success) {
        attempt_privileged_operation();
    }
}
```

### 8.4 影响范围

- **受影响版本**：特定版本的 Android 内核（需查看具体 patch）
- **影响程度**：本地提权（Local Privilege Escalation）
- **CVSS 评分**：High

### 8.5 修复方案

Google 的修复引入了更严格的锁机制和一致性检查：

```c
// 修复后的逻辑
static int sidtab_context_to_sid(struct sidtab *s,
                                  struct context *context,
                                  u32 *sid)
{
    unsigned long flags;
    
    // 添加自旋锁保护
    spin_lock_irqsave(&s->lock, flags);
    
    entry = sidtab_search_context(s, context);
    if (entry) {
        // 增加一致性校验
        if (context_cmp(&entry->context, context) == 0) {
            *sid = entry->sid;
            spin_unlock_irqrestore(&s->lock, flags);
            return 0;
        }
    }
    
    spin_unlock_irqrestore(&s->lock, flags);
    // ...
}
```

**检查设备是否已修复**：
```bash
# 查看安全补丁级别
adb shell getprop ro.build.version.security_patch

# 应为 2025-XX-XX 或更新
```

## 9. Android Rooting 框架的 SELinux 绕过

现代 Android root 工具需要处理 SELinux，以下是常见框架的绕过策略。

### 9.1 Magisk 的 SELinux 处理

Magisk 采用"最小修改"策略，不完全禁用 SELinux：

**核心机制**：
1. **MagiskSU**：运行在独立的 `u:r:magisk:s0` domain
2. **策略注入**：动态 patch 策略添加必要规则
3. **Zygisk**：hook zygote 但保持原有安全上下文

**策略 patch 示例**：
```
# Magisk 注入的规则
allow magisk * * *;  # magisk domain 拥有完整权限
allow su * * *;      # su 进程权限
type_transition zygote magisk_file:process magisk;
```

**检测 Magisk 策略修改**：
```bash
# 对比原始策略和当前策略
sesearch -A -s magisk sepolicy.bin  # 如果有输出说明被修改
seinfo -t magisk sepolicy.bin       # 检查是否存在 magisk type
```

### 9.2 KernelSU 的 SELinux 处理

KernelSU 在内核层面实现，对 SELinux 的处理更底层：

**核心机制**：
1. **内核 hook**：直接 hook `avc_has_perm` 检查
2. **条件绕过**：仅对授权进程绕过 SELinux 检查
3. **最小化修改**：不修改策略文件本身

**内核实现概念**：
```c
// KernelSU hook 逻辑（简化）
int ksu_avc_has_perm_hook(u32 ssid, u32 tsid, u16 tclass, 
                          u32 requested, struct common_audit_data *ad)
{
    // 检查是否是授权的 root 进程
    if (ksu_is_allow_su()) {
        return 0;  // 直接允许
    }
    // 否则调用原始函数
    return original_avc_has_perm(ssid, tsid, tclass, requested, ad);
}
```

### 9.3 APatch 的方案

APatch 结合了 Magisk 和 KernelSU 的特点：

1. **内核 patch**：修改内核获取 root 权限
2. **策略修改**：运行时注入 SELinux 规则
3. **模块系统**：支持 Magisk 模块

### 9.4 检测 Root 框架的 SELinux 修改

```bash
# 检查异常 domain
seinfo -t sepolicy.bin | grep -E 'magisk|su|ksu'

# 检查过于宽松的规则
sesearch -A sepolicy.bin | grep 'allow.*\* \*'

# 检查 permissive domain
sesearch -A --permissive sepolicy.bin

# 内核完整性检查
adb shell cat /proc/version
adb shell cat /proc/kallsyms | grep -E 'ksu|magisk'
```

## 10. 实际利用案例

### 10.1 案例：Vendor 策略过于宽松

**场景**：某设备的 vendor 策略允许 `system_app` 访问所有 `vendor_data_file`

**发现过程**：
```bash
sesearch -A -s system_app -t vendor_data_file sepolicy.bin
# 输出：allow system_app vendor_data_file:file *;
```

**利用**：
1. 找到以 `system_app` 权限运行的应用（如预装应用）
2. 利用该应用的漏洞（如 intent 注入）
3. 读取 vendor 目录下的敏感数据（如密钥、配置）

### 10.2 案例：Type Transition 缺失

**场景**：自定义服务未正确配置 domain transition，以 init domain 运行

**发现过程**：
```bash
# 检查服务进程的 domain
adb shell ps -AZ | grep vendor_service
# 输出：u:r:init:s0  ... vendor_service  # 应该是专用 domain

# 检查是否缺少 transition 规则
sesearch -T -s init -t vendor_service_exec sepolicy.bin
# 无输出，说明缺少 transition
```

**利用**：
1. 服务以 init domain 运行，拥有大量权限
2. 找到服务中的漏洞（如命令注入、路径遍历）
3. 利用 init 的权限访问敏感资源

### 10.3 案例：MCS 隔离失效

**场景**：不同用户的应用能访问彼此的数据

**发现过程**：
```bash
# 检查不同用户应用的安全上下文
adb shell ps -AZ | grep u0_a100
# u:r:untrusted_app:s0:c100,c256,c512 ...

adb shell ps -AZ | grep u10_a100  
# u:r:untrusted_app:s0:c100,c256,c512 ... # 应该有不同的 category
```

**利用**：
1. 多用户场景下，不同用户的应用共享相同的 MCS category
2. 应用可以跨用户访问数据

## 11. 审计 checklist

1. 关键守护进程是否运行在预期 domain
2. 高风险资源（设备节点、socket、属性）是否存在异常可达路径
3. vendor 定制策略是否扩大了 privileged domain 的权限
4. neverallow 是否被绕过（构建期检测与实际镜像一致性）
5. 是否存在 permissive domain
6. 敏感 type 的访问者列表是否合理
7. type_transition 链是否完整
8. MCS category 分配是否正确

## 12. 常用命令（设备侧）

- 查看进程上下文：`adb shell ps -AZ | head`（工具可用性依赖环境）
- 查看文件上下文：`adb shell ls -lZ <path>`
- 查看当前 enforcing：`adb shell getenforce`

## 参考（AOSP）
- https://source.android.com/docs/security/features/selinux — Android SELinux 总览：模式、域、策略与与沙盒/版本演进的关系。
- https://source.android.com/docs/security/app-sandbox — 应用沙盒的内核级隔离基础与 SELinux/seccomp 等纵深防御要点。
- https://selinuxproject.org/page/Main_Page — SELinux 项目官方文档
- https://github.com/SELinuxProject/setools — SETools 策略分析工具
- https://github.com/topjohnwu/Magisk — Magisk 源码
- https://github.com/tiann/KernelSU — KernelSU 源码
