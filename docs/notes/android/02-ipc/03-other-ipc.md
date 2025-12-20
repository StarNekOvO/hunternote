# 2x03 - 其他 IPC 机制

虽然 Binder 占据了 Android IPC 的 90%，但在底层和特定场景下，其他 Linux 传统的 IPC 机制依然活跃。

这类 IPC 的共同特点是：

- 语义更“原始”（更像 Linux 通用机制）
- 安全属性依赖**文件权限/进程凭据/SELinux 策略**
- 容易出现“配置错误”型问题（权限过宽、路径可控、缺少鉴权）

## 1. Unix Domain Sockets (UDS)

UDS 常用于 Native 守护进程（Daemons）之间的通信，例如 `adbd`、`installd`、`vold`、`netd`。

### 1.1 安全机制

**文件权限控制**：
```bash
# Socket 文件示例
srw-rw---- 1 system system u:object_r:installd_socket:s0 /dev/socket/installd
```

- 所有者：system
- 权限：660 (只有 system 用户和组可以读写)
- SELinux 标签：`installd_socket`

**凭据获取**（`SO_PEERCRED`）：
```c
// Server 侧验证客户端身份
struct ucred cred;
socklen_t len = sizeof(cred);
getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);

if (cred.uid != AID_SYSTEM) {
    // 拒绝连接
    return -EPERM;
}
```

### 1.2 常见漏洞模式

**1. Socket 权限过宽**

```bash
# 危险配置（installd.rc）
service installd /system/bin/installd
    socket installd stream 666 system system
    # 666 = 任何进程都能连接！
```

**攻击**：任意应用可以连接到 installd，发送安装/卸载命令。

**2. 未校验调用方身份**

```c
// 危险代码：不检查 SO_PEERCRED
void handle_client(int fd) {
    char cmd[256];
    read(fd, cmd, sizeof(cmd));
    
    if (strcmp(cmd, "install") == 0) {
        do_install();  // 无权限检查！
    }
}
```

**3. Socket 路径劫持**

```c
// 危险：在可写目录创建 socket
unlink("/data/local/tmp/mysocket");
int fd = socket(AF_UNIX, SOCK_STREAM, 0);
bind(fd, "/data/local/tmp/mysocket", ...);
```

攻击者可以抢先创建符号链接：
```bash
ln -s /data/system/users/0/settings_system.xml /data/local/tmp/mysocket
```

服务启动时会覆盖 `settings_system.xml`！

**4. 协议注入/命令注入**

```c
// 危险：直接拼接命令
void handle_request(const char* filename) {
    char cmd[1024];
    sprintf(cmd, "chown system:system %s", filename);  // 注入点！
    system(cmd);
}
```

攻击者传入 `"; rm -rf /data"`，执行任意命令。

### 1.3 真实案例：CVE-2019-2043 (installd Socket 漏洞)

**漏洞原理**：

installd 守护进程在处理 `dexopt` 命令时，未正确校验路径参数。

```c
// 简化的漏洞代码
int do_dexopt(const char* apk_path, const char* dex_path) {
    // 危险：未规范化路径
    int fd = open(dex_path, O_WRONLY | O_CREAT);
    // 写入优化后的 dex 文件
}
```

**攻击流程**：
1. 恶意应用连接到 `/dev/socket/installd`（通过系统 API 间接调用）
2. 发送 `dexopt` 命令，传入 `dex_path = "../../data/system/users/0/settings_system.xml"`
3. installd 以 root 权限创建/覆盖任意文件
4. 提权成功

**修复**：
- 添加路径规范化（`realpath()`）
- 限制允许的目录白名单
- 增强 SELinux 策略（限制 installd 可写路径）

### 1.4 审计方法

**枚举系统中的 UDS**：
```bash
# 列出所有 Unix Domain Sockets
adb shell ss -xlp

# 输出示例：
# u_str LISTEN 0 10 /dev/socket/installd 12345 * 0 users:(("installd",pid=123,fd=5))

# 查看权限与 SELinux 标签
adb shell ls -lZ /dev/socket/

# 输出：
# srw-rw---- 1 root system u:object_r:installd_socket:s0 installd
# srwxrwxrwx 1 root root u:object_r:adbd_socket:s0 adbd  # 危险！
```

**测试连接**：
```python
import socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect("/dev/socket/installd")
    print("[+] 连接成功！")
    sock.send(b"test command\n")
except PermissionError:
    print("[-] 权限被拒绝（正常）")
except ConnectionRefusedError:
    print("[-] 连接被拒绝")
```

## 2. 共享内存 (Shared Memory)

Android 引入了 `ashmem` (Anonymous Shared Memory)，后来逐渐转向 Linux 主线的 `memfd`。

### 2.1 基本使用

**创建共享内存**：
```c
// ashmem (Android 特有)
int fd = ashmem_create_region("my_region", size);
void* addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

// 通过 Binder 传递 FD 给其他进程
Parcel data;
data.writeDupFileDescriptor(fd);
```

**接收方映射**：
```c
int received_fd = data.readFileDescriptor();
void* addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, received_fd, 0);
// 现在两个进程共享同一块物理内存
```

### 2.2 安全风险详解

**1. TOCTOU (Time-of-Check to Time-of-Use)**

```c
// Server 进程
struct Message {
    uint32_t type;
    uint32_t length;
    char data[1024];
};

void handle_message(Message* msg) {
    if (msg->length > 1024) {  // 检查
        return;  // 拒绝
    }
    
    // 危险时间窗口：Client 可以在此期间修改 msg->length
    
    memcpy(localBuffer, msg->data, msg->length);  // 使用：越界！
}
```

**攻击演示**：
```c
// Client 进程（恶意）
Message* msg = (Message*)shared_mem;
msg->type = 1;
msg->length = 100;  // 先传入合法值

// 发送请求
sendRequest(fd);

// 竞态：快速修改 length
msg->length = 2000;  // 在 Server 检查后、拷贝前修改
```

**防御**：
- 先将关键字段拷贝到本地变量：`uint32_t len = msg->length;`
- 或者使用原子操作/内存屏障
- 最佳实践：**共享内存只存放数据，控制字段通过 IPC 传递**

**2. 结构体解释不一致**

```c
// Framework 定义
struct VideoFrame {
    uint32_t width;
    uint32_t height;
    uint32_t format;  // RGB/YUV
    uint8_t data[];
};

// HAL 定义（不同！）
struct VideoFrame {
    uint16_t width;   // 不同类型！
    uint16_t height;
    uint32_t format;
    uint32_t stride;  // 多了字段
    uint8_t data[];
};
```

偏移量不匹配导致读取错误数据，可能触发越界或类型混淆。

**3. 权限不当（可写 mmap）**

```c
// 发送方以只读意图创建共享内存
int fd = ashmem_create_region("data", size);
ashmem_set_prot_region(fd, PROT_READ);  // 设置保护

// 但接收方可以以可写方式映射（如果没有在发送前 pin）
void* addr = mmap(NULL, size, PROT_WRITE, MAP_SHARED, received_fd, 0);
// 接收方可以修改数据！
```

**防御**：发送方在传递 FD 前调用 `ashmem_pin_region()`。

### 2.3 真实案例：CVE-2020-0286 (Bluetooth Stack)

**漏洞原理**：

Bluetooth 协议栈在处理音频数据时，使用共享内存在不同进程间传递音频缓冲区。

```c
// 简化的漏洞代码
struct AudioBuffer {
    uint32_t size;
    uint8_t data[];
};

void processAudio(AudioBuffer* buf) {
    if (buf->size > MAX_SIZE) return;
    
    // TOCTOU 窗口
    for (int i = 0; i < buf->size; i++) {  // buf->size 可能被修改
        processRawbyte(buf->data[i]);      // 越界访问
    }
}
```

**攻击**：
1. 恶意应用建立蓝牙音频连接
2. 创建共享内存，设置 `size = 1000`（合法）
3. 系统开始处理音频
4. 在循环执行期间，应用修改 `size = 100000`
5. 触发堆溢出 -> 代码执行

**修复**：
```c
void processAudio(AudioBuffer* buf) {
    uint32_t size = buf->size;  // 先拷贝到本地
    if (size > MAX_SIZE) return;
    
    for (int i = 0; i < size; i++) {  // 使用本地副本
        processByte(buf->data[i]);
    }
}
```

### 2.4 审计方法

**查看进程的内存映射**：
```bash
adb shell cat /proc/<pid>/maps | grep ashmem

# 输出示例：
# 7f1234000-7f1235000 rw-s 00000000 00:04 12345 /dev/ashmem/my_region (deleted)
```

**Frida 监控共享内存创建**：
```javascript
// Hook ashmem_create_region
Interceptor.attach(Module.findExportByName("libc.so", "ashmem_create_region"), {
    onEnter: function(args) {
        var name = Memory.readCString(args[0]);
        var size = args[1].toInt32();
        console.log("[+] ashmem_create_region: " + name + ", size=" + size);
    },
    onLeave: function(retval) {
        console.log("    fd=" + retval.toInt32());
    }
});
```

## 3. Pipes & FIFO

主要用于简单的单向数据流传递。

常见风险更多来自“谁能写/谁能读”：

- FIFO 路径在可写目录下可能被替换
- 服务端把 pipe 当成可信输入导致命令/协议注入

## 4. System Properties（属性服务，常被忽略）

Android 的属性系统也是一种"跨进程状态传递"机制，基于共享内存实现。

### 4.1 工作原理

```bash
# 设置属性
setprop debug.test.value 123

# 读取属性
getprop debug.test.value

# 监听属性变化
watchprops
```

**底层实现**：
- 所有属性存储在 `/dev/__properties__`（共享内存）
- `init` 进程管理写入权限
- SELinux 策略控制谁可以读/写特定属性

### 4.2 安全风险

**1. 属性注入触发敏感行为**

```bash
# 某些系统服务监听属性变化
# 如果属性可被普通应用修改，可能触发意外行为

# 危险示例（假设）
setprop persist.sys.usb.config adb,mass_storage
# 如果此属性可被修改，可能开启 ADB 或暴露存储
```

**2. 调试开关暴露**

厂商定制系统中常见：
```bash
# 某些设备的隐藏调试开关
setprop persist.vendor.debug.enable 1
setprop persist.sys.log.verbose 1
```

如果这些属性未受保护，可能泄露敏感日志或开启后门功能。

**3. Bootloader 解锁状态**

```bash
# OEM 解锁状态（影响安全启动）
getprop ro.boot.flash.locked
getprop ro.oem_unlock_supported
```

攻击者可能通过篡改这些属性（需要 root 或 bootloader 漏洞）绕过启动验证。

### 4.3 真实案例：厂商调试属性滥用

**场景**：某品牌设备在 `system.prop` 中包含：

```ini
# /system/build.prop
persist.vendor.debug.logcat=1
persist.vendor.debug.adb_root=0
```

**漏洞**：
1. `persist.vendor.debug.adb_root` 属性未受 SELinux 保护
2. 应用可以通过反射调用 `SystemProperties.set()` 修改
3. 设置为 `1` 后，`adbd` 重启并自动启用 root 权限

**影响**：任意应用可提权到 root。

**修复**：
- 添加 SELinux 策略：`neverallow { domain -init } vendor_debug_prop:property_service set;`
- 移除生产版本中的调试属性

### 4.4 审计方法

**枚举所有属性**：
```bash
adb shell getprop | grep -E "(debug|test|vendor\.debug|persist\.sys)"
```

**检查属性权限**：
```bash
# 查看 SELinux 属性上下文
adb shell ls -lZ /dev/__properties__

# 查看属性服务策略
adb shell cat /sepolicy | grep property_contexts
```

**测试修改权限**：
```bash
# 尝试修改系统属性
adb shell setprop debug.test.myvalue 123

# 如果成功，说明该属性未受保护
adb shell getprop debug.test.myvalue
```

**Frida 监控属性访问**：
```javascript
// Hook SystemProperties.set()
Java.perform(function() {
    var SystemProperties = Java.use("android.os.SystemProperties");
    
    SystemProperties.set.overload('java.lang.String', 'java.lang.String').implementation = function(key, val) {
        console.log("[Property] set: " + key + " = " + val);
        
        // 检查是否是敏感属性
        if (key.indexOf("debug") !== -1 || key.indexOf("persist") !== -1) {
            console.log("[!] 敏感属性被修改！");
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            ));
        }
        
        return this.set(key, val);
    };
});
```

## 5. 综合案例：多 IPC 机制的组合攻击

真实攻击往往结合多种 IPC 机制：

### 案例：CVE-2021-0642 (Media 提权链)

**攻击链**：

1. **Binder 入口**：应用调用 `MediaPlayer.setDataSource()`
2. **FD 传递**：通过 Binder 传递 media 文件的 FD 到 `mediaserver`
3. **共享内存**：`mediaserver` 使用 ashmem 与 codec HAL 共享解码缓冲区
4. **UDS 通信**：Codec HAL 通过 Unix Socket 与内核驱动通信
5. **漏洞触发**：在共享内存的 TOCTOU 窗口，应用修改缓冲区大小字段
6. **内核提权**：Codec HAL 触发内核驱动的堆溢出

**关键点**：
- 每个 IPC 边界都有潜在的输入验证问题
- 攻击者通过组合多个"小问题"构造完整利用链

## 6. IPC 安全审计通用 Checklist

无论使用哪种 IPC 机制，都应检查以下安全要点：

### 6.1 身份与权限验证

| 检查项 | Binder | UDS | 共享内存 | Properties |
|--------|--------|-----|----------|-----------|
| **调用方身份** | `getCallingUid()` | `SO_PEERCRED` | 通过 Binder 传递时检查 | init 强制 |
| **权限检查** | `checkPermission()` | 手动校验 UID/GID | N/A | SELinux 策略 |
| **SELinux MAC** | `binder_call` 规则 | `connectto` 规则 | `fd use` 规则 | `property_set` 规则 |

### 6.2 输入验证

```c
// 通用输入验证模板
bool validate_input(const Input* input) {
    // 1. 空指针检查
    if (input == NULL) return false;
    
    // 2. 长度/大小边界
    if (input->size > MAX_SIZE || input->size == 0) return false;
    
    // 3. 数值范围
    if (input->offset < 0 || input->offset >= input->size) return false;
    
    // 4. 整数溢出检查
    if (input->count > SIZE_MAX / sizeof(Element)) return false;
    
    // 5. 字符串终止符
    if (input->name[NAME_LEN - 1] != '\0') return false;
    
    // 6. 路径规范化
    char realpath_buf[PATH_MAX];
    if (realpath(input->path, realpath_buf) == NULL) return false;
    
    // 7. 白名单检查
    if (!is_in_whitelist(realpath_buf)) return false;
    
    return true;
}
```

### 6.3 资源限制（防 DoS）

```c
// 限制并发连接数
#define MAX_CLIENTS 100
static atomic_int active_clients = 0;

void handle_new_client(int fd) {
    if (atomic_fetch_add(&active_clients, 1) >= MAX_CLIENTS) {
        close(fd);
        atomic_fetch_sub(&active_clients, 1);
        return;
    }
    
    // 处理客户端请求
    // ...
    
    atomic_fetch_sub(&active_clients, 1);
}
```

```c
// 限制消息大小
#define MAX_MESSAGE_SIZE (1024 * 1024)  // 1MB

ssize_t read_message(int fd, char* buf) {
    uint32_t size;
    if (read(fd, &size, sizeof(size)) != sizeof(size)) {
        return -1;
    }
    
    if (size > MAX_MESSAGE_SIZE) {
        return -1;  // 拒绝过大的消息
    }
    
    return read(fd, buf, size);
}
```

### 6.4 并发安全

```c
// 共享状态的保护
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static bool is_initialized = false;

void sensitive_operation() {
    pthread_mutex_lock(&state_lock);
    
    if (!is_initialized) {
        pthread_mutex_unlock(&state_lock);
        return;
    }
    
    // 执行敏感操作
    // ...
    
    pthread_mutex_unlock(&state_lock);
}
```

### 6.5 安全的 IPC 模式

**模式 1：最小权限原则**
```c
// 每个操作单独检查权限，而不是"一次登录，永久信任"
void do_operation(int operation_type, uid_t caller_uid) {
    switch (operation_type) {
        case OP_READ:
            if (!check_read_permission(caller_uid)) return;
            break;
        case OP_WRITE:
            if (!check_write_permission(caller_uid)) return;
            break;
    }
    // 执行操作
}
```

**模式 2：Token 而非布尔状态**
```c
// 不安全：布尔标志容易被竞态绕过
bool is_authenticated = false;

void authenticate(const char* password) {
    if (check_password(password)) {
        is_authenticated = true;
    }
}

void sensitive_op() {
    if (is_authenticated) {  // 竞态窗口
        // ...
    }
}

// 安全：使用唯一 token
typedef struct {
    uint64_t token;
    time_t expires;
    uid_t uid;
} AuthToken;

AuthToken* authenticate(const char* password, uid_t uid) {
    if (!check_password(password)) return NULL;
    
    AuthToken* token = malloc(sizeof(AuthToken));
    token->token = generate_random_token();
    token->expires = time(NULL) + 3600;
    token->uid = uid;
    
    store_token(token);
    return token;
}

bool sensitive_op(uint64_t token, uid_t caller_uid) {
    AuthToken* stored = lookup_token(token);
    if (!stored || stored->uid != caller_uid) return false;
    if (stored->expires < time(NULL)) return false;
    
    // 执行操作
    return true;
}
```

**模式 3：Defense in Depth**
```c
// 多层防护：SELinux + 权限 + UID + 业务逻辑
bool is_operation_allowed(int operation, uid_t caller_uid) {
    // 第 1 层：SELinux 已经在内核检查过（隐式）
    
    // 第 2 层：Android 权限检查
    if (!check_android_permission(caller_uid, "CAMERA")) {
        return false;
    }
    
    // 第 3 层：UID 白名单
    if (!is_in_allowed_uid_list(caller_uid)) {
        return false;
    }
    
    // 第 4 层：业务逻辑约束（如频率限制）
    if (!check_rate_limit(caller_uid, operation)) {
        return false;
    }
    
    return true;
}
```

## 7. 总结

Android IPC 的多样性既是灵活性的体现，也是攻击面的来源。在审计时：

1. **Binder** 是主要攻击面，关注混淆代理和反序列化
2. **UDS** 关注权限配置和协议注入
3. **共享内存** 警惕 TOCTOU 和结构不一致
4. **Properties** 检查调试开关和敏感配置

**核心原则**：
- 永远不要信任跨进程边界的输入
- 在每个 IPC 边界都要重新验证身份和权限
- 使用纵深防御：SELinux + DAC + 应用层鉴权

## 参考（AOSP）

- **SELinux 策略**：https://source.android.com/docs/security/features/selinux
- **架构概览**：https://source.android.com/docs/core/architecture
- **AIDL 概览**：https://source.android.com/docs/core/architecture/aidl
- **应用沙盒**：https://source.android.com/docs/security/app-sandbox
