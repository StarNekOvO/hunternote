# 06 - AOSP 实战

Android Framework 核心组件分析。


## 概念速览

**为什么学 AOSP Java？**
- Android 安全研究的核心
- 系统服务漏洞分析
- 权限绕过理解

**关键组件：**

```
┌─────────────────────────────────────────┐
│              Applications                │
├─────────────────────────────────────────┤
│           Framework (Java)               │
│  ┌─────────────────────────────────────┐ │
│  │ system_server                       │ │
│  │ ├── AMS (Activity Manager)          │ │
│  │ ├── PMS (Package Manager)           │ │
│  │ ├── WMS (Window Manager)            │ │
│  │ └── ...                             │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│              Binder IPC                  │
├─────────────────────────────────────────┤
│              Native/Kernel               │
└─────────────────────────────────────────┘
```


## system_server

### 启动流程

```
Zygote
   ↓ fork
system_server (PID 很小，通常是几百)
   ↓
SystemServer.main()
   ↓
startBootstrapServices()  ← AMS, PMS
   ↓
startCoreServices()       ← BatteryService
   ↓
startOtherServices()      ← WMS, 其他
```

### 源码位置

```
frameworks/base/services/java/com/android/server/SystemServer.java
frameworks/base/services/core/java/com/android/server/am/  ← AMS
frameworks/base/services/core/java/com/android/server/pm/  ← PMS
frameworks/base/services/core/java/com/android/server/wm/  ← WMS
```


## Binder Java 层

### AIDL 生成代码

```java
// IActivityManager.aidl
interface IActivityManager {
    int startActivity(in Intent intent, ...);
    ComponentName startService(in Intent intent, ...);
}
```

**生成的代码结构：**
```
IActivityManager
├── Stub (服务端)
│   └── onTransact() - 处理请求
└── Stub.Proxy (客户端)
    └── startActivity() - 发送请求
```

### 获取系统服务

```java
// 应用层
ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);

// 底层实现
IBinder binder = ServiceManager.getService("activity");
IActivityManager am = IActivityManager.Stub.asInterface(binder);
```

### ServiceManager

```java
// frameworks/base/core/java/android/os/ServiceManager.java
public static IBinder getService(String name) {
    IBinder service = sCache.get(name);
    if (service != null) {
        return service;
    }
    return Binder.allowBlocking(rawGetService(name));
}

// 注册服务 (system_server 做的)
public static void addService(String name, IBinder service) {
    getIServiceManager().addService(name, service, false, ...);
}
```


## AMS (ActivityManagerService)

### 核心功能

- 管理 Activity 生命周期
- 进程管理
- 任务栈管理
- 广播分发

### startActivity 流程

```
App: startActivity()
  ↓
Instrumentation.execStartActivity()
  ↓
ActivityTaskManager.getService().startActivity()
  ↓ Binder
ActivityTaskManagerService.startActivity()
  ↓
ActivityStarter.execute()
  ↓
创建 ActivityRecord，加入任务栈
  ↓
通知目标 App 启动 Activity
```

### CVE-2024-0025 分析

**后台启动绕过漏洞：**

```java
// 简化的漏洞模式
// 正常检查
if (!canStartActivityForResult()) {
    throw new SecurityException("Not allowed to start activity");
}

// 漏洞：某些路径绕过了检查
if (specialCondition) {
    // 直接启动，未经检查
    startActivityInner(...);
}
```

> [!CAUTION]
> 这类漏洞允许后台 App 在前台显示界面，可用于钓鱼攻击。


## PMS (PackageManagerService)

### 核心功能

- 应用安装/卸载
- 权限管理
- 包信息查询
- 签名验证

### 安装流程

```
APK 文件
  ↓
PackageInstallerSession.commit()
  ↓
PackageManagerService.installPackagesLI()
  ↓
解析 AndroidManifest.xml
  ↓
验证签名
  ↓
分配 UID
  ↓
创建数据目录
  ↓
DEX 优化 (dex2oat)
  ↓
更新 packages.xml
```

### CVE-2024-0044 分析

**run-as 任意应用身份漏洞：**

```java
// run-as 命令用于调试
// 正常：只能 run-as 可调试应用

// 漏洞：PMS 返回错误的包信息
// 攻击者可以安装一个伪造的包
// 使得 run-as 认为目标应用可调试
```

**影响：**
- 读取任意应用私有数据
- 执行任意应用上下文代码


## 权限系统

### 权限检查流程

```java
// 应用请求权限
checkSelfPermission(Manifest.permission.READ_CONTACTS)

// 底层实现
PermissionManagerService.checkPermission(...)
  ↓
AppOpsService.checkOperation(...)  // 运行时权限
  ↓
PackageManagerService.checkUidPermission(...)  // 声明权限
```

### 权限级别

| 级别 | 说明 | 授权方式 |
|------|------|----------|
| normal | 低风险 | 自动授予 |
| dangerous | 隐私相关 | 用户授权 |
| signature | 系统签名 | 签名一致 |
| privileged | 系统特权 | 预装+白名单 |

### 权限绕过模式

```java
// 1. 调用链检查不完整
// 深层调用没有检查调用者权限

// 2. Intent 重定向
// 利用系统组件作为代理

// 3. 条件竞争
// 权限检查和操作之间的 TOCTOU
```


## 实战场景

### Lab 1: 获取系统服务

```java
// 反射获取隐藏服务
Class<?> smClass = Class.forName("android.os.ServiceManager");
Method getService = smClass.getMethod("getService", String.class);

IBinder binder = (IBinder) getService.invoke(null, "activity");
System.out.println("AMS binder: " + binder);
```

### Lab 2: Binder 调用追踪

```java
// 使用 Frida 追踪 Binder 调用
Java.perform(function() {
    var Binder = Java.use("android.os.Binder");
    
    Binder.execTransact.implementation = function(code, data, reply, flags) {
        console.log("Binder transaction: code=" + code);
        return this.execTransact(code, data, reply, flags);
    };
});
```

### Lab 3: 分析权限检查

```java
// 追踪权限检查调用
Java.perform(function() {
    var ContextImpl = Java.use("android.app.ContextImpl");
    
    ContextImpl.checkPermission.overload(
        'java.lang.String', 'int', 'int'
    ).implementation = function(perm, pid, uid) {
        var result = this.checkPermission(perm, pid, uid);
        console.log("checkPermission: " + perm + " = " + result);
        return result;
    };
});
```


## CVE 研究方法

### 分析步骤

1. **阅读公告** - 获取影响范围和大致原因
2. **定位补丁** - 在 AOSP 找到修复 commit
3. **对比代码** - diff 分析修改内容
4. **理解漏洞** - 推断原始漏洞原理
5. **构造 PoC** - 尝试复现

### 常用资源

```
# Android 安全公告
https://source.android.com/security/bulletin

# AOSP 代码搜索
https://cs.android.com/

# Git 提交历史
https://android.googlesource.com/
```


## 常见陷阱

### ❌ 陷阱 1: 反射隐藏 API 限制

Android 9+ 限制反射访问隐藏 API：

```java
// 可能抛出异常或返回空
Method method = clazz.getDeclaredMethod("hiddenMethod");
```

### ❌ 陷阱 2: Binder 调用权限

```java
// 清除调用者身份（危险）
long token = Binder.clearCallingIdentity();
try {
    // 使用系统权限执行
} finally {
    Binder.restoreCallingIdentity(token);
}
```

### ❌ 陷阱 3: 多用户环境

```java
// 需要考虑多用户
int userId = UserHandle.getUserId(callingUid);
// 0 = 主用户, 10+ = 工作配置文件/访客
```


## 深入阅读

**推荐资源：**
- [Android Internals](http://newandroidbook.com/)
- [Exploring Android Internals](https://source.android.com/docs)

**相关章节：**
- [Binder 深度解析](/notes/android/02-ipc/00-binder-deep-dive)
- [AMS 深度解析](/notes/android/03-services/01-ams)
- [PMS 深度解析](/notes/android/03-services/02-pms)


## 下一步

[07 - Xposed/LSPosed](./07-xposed-lsposed.md) - Hook 开发
