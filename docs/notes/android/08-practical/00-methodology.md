# 8x00 - Vulnerability Research Methodology

安全研究不是碰运气，而是一套系统的方法论。

本章目标是把 Android 研究工作拆成可重复执行的流程：从选目标、定位入口、拿到可观测证据，到完成定级与修复验证。

## 1. 攻击面分析 (Attack Surface Mapping)

### 1.1 攻击面分类

| 层级 | 攻击面 | 典型入口 | 权限要求 |
|------|--------|----------|----------|
| 应用层 | Intent/ContentProvider | 导出组件、DeepLink | 无 |
| Framework | Binder 接口 | system_server 服务 | 无/普通权限 |
| Native | Socket/文件 | 守护进程、HAL | 无/ADB |
| 内核 | syscall/ioctl | 驱动设备节点 | 无/root |
| 硬件 | 无线协议 | WiFi/BT/NFC/Baseband | 物理接近 |

### 1.2 攻击面枚举脚本

**枚举导出组件**：
```bash
#!/bin/bash
# enum_exported.sh - 枚举目标应用的导出组件

PACKAGE=$1

echo "=== 导出 Activities ==="
adb shell pm query-activities --exported -a android.intent.action.VIEW 2>/dev/null | grep $PACKAGE

echo -e "\n=== 导出 Services ==="
adb shell dumpsys package $PACKAGE | grep -A 50 "Service Resolver Table" | head -60

echo -e "\n=== 导出 Receivers ==="
adb shell dumpsys package $PACKAGE | grep -A 50 "Receiver Resolver Table" | head -60

echo -e "\n=== 导出 Providers ==="
adb shell dumpsys package $PACKAGE | grep -A 20 "ContentProvider Coverage" | head -30

echo -e "\n=== DeepLinks ==="
adb shell dumpsys package $PACKAGE | grep -E "Schemes:|Hosts:|Paths:"
```

**枚举系统服务 Binder 接口**：
```bash
#!/bin/bash
# enum_services.sh - 枚举系统服务

echo "=== 所有系统服务 ==="
adb shell service list

echo -e "\n=== 高价值服务详情 ==="
for svc in activity package window input_method; do
    echo "--- $svc ---"
    adb shell dumpsys $svc | head -50
done

echo -e "\n=== Native 服务 ==="
adb shell ls -la /dev/binder /dev/hwbinder /dev/vndbinder 2>/dev/null
```

**枚举设备节点**：
```bash
#!/bin/bash
# enum_devices.sh - 枚举可能有漏洞的设备节点

echo "=== 可读写设备节点 ==="
adb shell "find /dev -type c 2>/dev/null | while read d; do
    if [ -r \"\$d\" ] || [ -w \"\$d\" ]; then
        ls -la \"\$d\"
    fi
done"

echo -e "\n=== /dev 下非 root 可访问 ==="
adb shell ls -la /dev/ | grep -v "root.*root"

echo -e "\n=== 厂商特有设备 ==="
adb shell ls -la /dev/*gpu* /dev/*ion* /dev/*mali* /dev/*kgsl* 2>/dev/null
```

### 1.3 Frida 攻击面枚举

```javascript
// enum_attack_surface.js - Frida 脚本枚举攻击面

Java.perform(function() {
    console.log("[*] Enumerating attack surface...\n");
    
    // 1. 枚举所有加载的类
    console.log("=== Loaded Classes (sample) ===");
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("ContentProvider") || 
                className.includes("BroadcastReceiver")) {
                console.log("  " + className);
            }
        },
        onComplete: function() {}
    });
    
    // 2. Hook Intent 接收
    console.log("\n=== Hooking Intent receivers ===");
    var Activity = Java.use("android.app.Activity");
    Activity.onNewIntent.implementation = function(intent) {
        console.log("[Intent] " + intent.toString());
        console.log("  Action: " + intent.getAction());
        console.log("  Data: " + intent.getDataString());
        console.log("  Extras: " + intent.getExtras());
        return this.onNewIntent(intent);
    };
    
    // 3. Hook ContentProvider query
    var ContentProvider = Java.use("android.content.ContentProvider");
    ContentProvider.query.overload(
        'android.net.Uri', '[Ljava.lang.String;', 
        'android.os.Bundle', 'android.os.CancellationSignal'
    ).implementation = function(uri, proj, queryArgs, cancel) {
        console.log("[ContentProvider.query] " + uri.toString());
        return this.query(uri, proj, queryArgs, cancel);
    };
    
    // 4. Hook Binder transactions
    console.log("\n=== Hooking Binder transactions ===");
    var Binder = Java.use("android.os.Binder");
    Binder.execTransact.implementation = function(code, data, reply, flags) {
        console.log("[Binder] code=" + code + " flags=" + flags);
        return this.execTransact(code, data, reply, flags);
    };
});
```

## 2. 漏洞挖掘手段

### 2.1 静态分析

**AOSP 源码搜索**：
```bash
# 搜索危险函数调用
grep -rn "strcpy\|sprintf\|gets\|system(" frameworks/base/

# 搜索权限检查
grep -rn "checkCallingPermission\|enforceCallingPermission" frameworks/

# 搜索 Parcel 反序列化
grep -rn "readParcelable\|readSerializable" frameworks/
```

**jadx 反编译分析**：
```bash
# 反编译 APK
jadx -d output/ target.apk

# 搜索敏感模式
grep -rn "Runtime.exec\|ProcessBuilder" output/
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE" output/
grep -rn "addJavascriptInterface" output/
```

### 2.2 模糊测试

**libFuzzer Harness 模板**：
```cpp
// fuzz_parser.cpp - 通用解析器 fuzzer 模板
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// 包含目标库头文件
// #include "target_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 大小检查
    if (size < 4 || size > 1024 * 1024) {
        return 0;
    }
    
    // 调用目标解析函数
    // parse_data(data, size);
    
    return 0;
}

// 编译命令
// clang++ -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
//   fuzz_parser.cpp target_lib.a -o fuzz_parser
```

**AFL++ Android Fuzzing**：
```bash
# 1. 编译 AFL++ for Android
export ANDROID_NDK=/path/to/ndk
cd AFLplusplus
make clean
CC=aarch64-linux-android30-clang make

# 2. 编译目标 (插桩)
afl-clang-fast -o target target.c

# 3. 运行 fuzzer
afl-fuzz -i corpus/ -o findings/ -- ./target @@
```

**Syzkaller 内核 Fuzzing**：
```bash
# syz-manager 配置示例
{
    "target": "linux/arm64",
    "http": "0.0.0.0:56741",
    "workdir": "/syzkaller/workdir",
    "kernel_obj": "/android/out/target/product/generic_arm64/obj/KERNEL_OBJ",
    "image": "/android/out/target/product/generic_arm64/system.img",
    "sshkey": "/root/.ssh/id_rsa",
    "syzkaller": "/syzkaller",
    "procs": 8,
    "type": "adb",
    "vm": {
        "devices": ["/dev/kvm"],
        "count": 4
    }
}
```

### 2.3 动态分析 Frida 脚本

**Hook 危险函数**：
```javascript
// hook_dangerous.js - Hook 常见危险函数

// 1. Hook Runtime.exec
Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        console.log("[!] Runtime.exec: " + cmd.join(" "));
        console.log("    Stack: " + Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
        return this.exec(cmd);
    };
});

// 2. Hook 文件操作
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = args[0].readCString();
        this.flags = args[1].toInt32();
    },
    onLeave: function(ret) {
        if (this.path && this.path.includes("/data/")) {
            console.log("[open] " + this.path + " flags=" + this.flags + " fd=" + ret);
        }
    }
});

// 3. Hook memcpy 检测大拷贝
Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function(args) {
        var size = args[2].toInt32();
        if (size > 0x10000) {
            console.log("[!] Large memcpy: " + size + " bytes");
            console.log("    " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n    "));
        }
    }
});

// 4. Hook Parcel 反序列化
Java.perform(function() {
    var Parcel = Java.use("android.os.Parcel");
    Parcel.readParcelable.overload("java.lang.ClassLoader").implementation = function(cl) {
        var result = this.readParcelable(cl);
        if (result != null) {
            console.log("[Parcel] readParcelable: " + result.getClass().getName());
        }
        return result;
    };
});
```

**监控 Binder 调用**：
```javascript
// hook_binder.js - 监控 Binder IPC

Java.perform(function() {
    // Hook BinderProxy.transact
    var BinderProxy = Java.use("android.os.BinderProxy");
    BinderProxy.transact.implementation = function(code, data, reply, flags) {
        var iface = this.getInterfaceDescriptor();
        console.log("[Binder] " + iface + " code=" + code);
        
        // 打印 Parcel 数据 (前 64 字节)
        var dataBytes = data.marshall();
        if (dataBytes.length > 0) {
            var hex = "";
            for (var i = 0; i < Math.min(64, dataBytes.length); i++) {
                hex += ("0" + (dataBytes[i] & 0xff).toString(16)).slice(-2) + " ";
            }
            console.log("    Data: " + hex);
        }
        
        return this.transact(code, data, reply, flags);
    };
});
```

## 3. 研究流水线

### 3.1 完整流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 1: 目标选择                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 1. 确定研究目标 (组件/功能/版本)                             ││
│  │ 2. 收集相关信息 (源码/文档/历史CVE)                          ││
│  │ 3. 评估攻击面优先级                                          ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    Phase 2: 环境准备                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 1. 搭建测试环境 (真机/模拟器)                                ││
│  │ 2. 配置调试工具 (Frida/LLDB/logcat)                         ││
│  │ 3. 建立基线日志                                              ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    Phase 3: 漏洞挖掘                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 1. 代码审计 (静态分析)                                       ││
│  │ 2. 动态测试 (手工/Fuzzing)                                   ││
│  │ 3. 记录可疑行为                                              ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    Phase 4: 漏洞确认                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 1. 稳定复现                                                  ││
│  │ 2. 根因分析                                                  ││
│  │ 3. 影响评估                                                  ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    Phase 5: 报告提交                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 1. 编写报告                                                  ││
│  │ 2. 准备 PoC                                                  ││
│  │ 3. 提交并跟进                                                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 目标选择优先级

| 优先级 | 特征 | 示例 |
|--------|------|------|
| P0 (最高) | 无需权限 + 远程可达 + 高权限进程 | Baseband RCE, WiFi 驱动漏洞 |
| P1 | 无需权限 + 本地可达 + 高权限进程 | system_server 漏洞, 内核驱动 |
| P2 | 需普通权限 + 高权限进程 | 特权服务接口漏洞 |
| P3 | 需普通权限 + 普通进程 | 应用组件漏洞 |

### 3.3 可观测性建立

```bash
#!/bin/bash
# setup_observability.sh - 建立可观测性

# 1. 启动 logcat 持续记录
adb logcat -v time > logcat_$(date +%Y%m%d_%H%M%S).log &
LOGCAT_PID=$!

# 2. 监控崩溃
adb shell "while true; do
    inotifywait -e create /data/tombstones/ 2>/dev/null
    ls -la /data/tombstones/ | tail -1
done" &

# 3. 监控 ANR
adb shell "while true; do
    inotifywait -e create /data/anr/ 2>/dev/null
    ls -la /data/anr/ | tail -1
done" &

# 4. 监控 kernel log
adb shell dmesg -w > dmesg_$(date +%Y%m%d_%H%M%S).log &

echo "Observability setup complete. PIDs: logcat=$LOGCAT_PID"
echo "Press Ctrl+C to stop all monitors"
wait
```

## 4. 漏洞定级评估

### 4.1 评估模板

```markdown
## 漏洞定级评估

### 基本信息
- 漏洞类型: [RCE/LPE/信息泄露/DoS]
- 受影响组件: 
- 受影响版本: 

### 触发条件
- [ ] 需要用户交互
- [ ] 需要本地代码执行
- [ ] 需要特定权限: 
- [ ] 需要物理接触
- [ ] 需要 ADB/USB 调试

### 影响评估
- 权限提升: [无 → App / App → System / System → Root]
- 数据影响: [读取/修改/删除]
- 可用性影响: [临时DoS/永久DoS/无]

### 缓解机制
- [ ] SELinux 是否限制: 
- [ ] seccomp 是否限制: 
- [ ] 进程隔离是否有效: 
- [ ] ASLR/CFI/MTE 是否影响利用: 

### 最终定级
- CVSS 评分: 
- 严重程度: [Critical/High/Moderate/Low]
- 建议修复优先级: 
```

### 4.2 CVSS 快速计算

| 因素 | Critical | High | Medium | Low |
|------|----------|------|--------|-----|
| 攻击向量 | 网络 | 本地 | 物理 | - |
| 权限要求 | 无 | 低 | 高 | - |
| 用户交互 | 无 | 需要 | - | - |
| 影响范围 | 变更 | 不变 | - | - |
| 机密性 | 高 | 低 | 无 | - |
| 完整性 | 高 | 低 | 无 | - |
| 可用性 | 高 | 低 | 无 | - |

## 5. 工具清单

### 5.1 按层分类

| 层级 | 工具 | 用途 |
|------|------|------|
| App | jadx, apktool, dex2jar | 反编译、解包 |
| App | Frida, Objection | 动态 Hook |
| Framework | adb dumpsys, service call | 服务交互 |
| Native | IDA Pro, Ghidra | 逆向分析 |
| Native | GDB, LLDB | 调试 |
| Kernel | ftrace, perf | 追踪分析 |
| Kernel | Syzkaller | Fuzzing |
| 通用 | Burp Suite | 网络抓包 |

### 5.2 必备命令

```bash
# 应用分析
adb shell pm list packages -f          # 列出所有包
adb shell dumpsys package <pkg>        # 包详情
adb shell am start -n <component>      # 启动组件

# 系统服务
adb shell service list                 # 服务列表
adb shell dumpsys <service>            # 服务状态

# 调试
adb logcat -s TAG:V                    # 过滤日志
adb shell cat /data/tombstones/*       # 查看崩溃

# 内核
adb shell cat /proc/version            # 内核版本
adb shell dmesg                        # 内核日志
adb shell cat /proc/kallsyms           # 内核符号 (需root)
```

## 6. 案例：Binder 接口漏洞研究

### 6.1 研究流程示例

```
目标: 研究 ClipboardService 的安全性

1. 信息收集
   - 阅读 AOSP 源码: frameworks/base/services/core/java/.../ClipboardService.java
   - 查看历史 CVE: CVE-2021-0340 等
   - 理解接口: setPrimaryClip, getPrimaryClip

2. 攻击面分析
   - 接口权限检查
   - 跨用户访问控制
   - 数据序列化/反序列化

3. 测试用例
   - 跨用户读取剪贴板
   - 大数据量 DoS
   - 恶意 ClipData 反序列化

4. Frida 脚本
   [见上文 hook 脚本]

5. 发现 & 确认
   - 记录异常行为
   - 稳定复现
   - 根因定位

6. 报告编写
   [见 bug-bounty 章节]
```

## 7. 参考资源

### 官方资源
- [AOSP 源码](https://cs.android.com/)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [报告 Bug 指南](https://source.android.com/docs/setup/contribute/report-bugs)

### 工具资源
- [Frida](https://frida.re/)
- [Objection](https://github.com/sensepost/objection)
- [jadx](https://github.com/skylot/jadx)
- [Syzkaller](https://github.com/google/syzkaller)

### 学习资源
- [Android Security Internals](https://nostarch.com/androidsecurity)
- [Maddie Stone's Android Exploitation](https://github.com/maddiestone/AndroidAppRE)
