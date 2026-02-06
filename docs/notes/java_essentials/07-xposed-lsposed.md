# 07 - Xposed/LSPosed

Android Java 层 Hook 框架。


## 概念速览

**什么是 Xposed？**
在不修改 APK 的情况下修改应用和系统行为。

**为什么使用它？**
- 安全研究和漏洞分析
- 绕过应用限制
- 系统定制
- 逆向工程辅助

**框架演进：**

| 框架 | Android 版本 | 状态 |
|------|-------------|------|
| Xposed | 4.4 - 8.1 | 停止维护 |
| EdXposed | 8.0 - 10 | 停止维护 |
| LSPosed | 8.1+ | 活跃 |
| LSPatch | 无 Root | 活跃 |


## 工作原理

### Xposed 原理

```
Zygote
   ↓ 注入
Xposed Framework
   ↓ Hook
app_process (所有应用进程)
   ↓
方法调用被拦截
   ↓
执行 Hook 回调
```

### LSPosed 原理

```
Magisk + Zygisk
   ↓
注入 Zygote
   ↓
加载 LSPosed 核心
   ↓
通过 ART Hook 拦截方法
```

**相比 Xposed：**
- 使用 ART hook 而非 Dalvik
- 模块隔离，更稳定
- 只 Hook 选定的应用


## LSPosed 开发

### 项目结构

```
my-xposed-module/
├── app/
│   ├── src/main/
│   │   ├── java/
│   │   │   └── com/example/module/
│   │   │       ├── MainHook.java      ← Hook 入口
│   │   │       └── Utils.java
│   │   ├── assets/
│   │   │   └── xposed_init          ← 入口类声明
│   │   └── AndroidManifest.xml
│   └── build.gradle
└── settings.gradle
```

### AndroidManifest.xml

```xml
<manifest>
    <application>
        <!-- 标记为 Xposed 模块 -->
        <meta-data
            android:name="xposedmodule"
            android:value="true" />
        <meta-data
            android:name="xposeddescription"
            android:value="My Xposed Module" />
        <meta-data
            android:name="xposedminversion"
            android:value="93" />
        <meta-data
            android:name="xposedscope"
            android:resource="@array/xposed_scope" />
    </application>
</manifest>
```

### xposed_init

```
com.example.module.MainHook
```

### build.gradle

```groovy
dependencies {
    compileOnly 'de.robv.android.xposed:api:82'
    // 或 LSPosed API
    compileOnly 'io.github.libxposed:api:100'
}
```


## Hook API

### 基本 Hook

```java
public class MainHook implements IXposedHookLoadPackage {
    
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("com.target.app")) {
            return;
        }
        
        XposedBridge.log("Hooking: " + lpparam.packageName);
        
        // Hook 方法
        XposedHelpers.findAndHookMethod(
            "com.target.app.MainActivity",  // 类名
            lpparam.classLoader,
            "checkLicense",                  // 方法名
            String.class,                    // 参数类型
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    XposedBridge.log("checkLicense called with: " + param.args[0]);
                }
                
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    // 修改返回值
                    param.setResult(true);
                }
            }
        );
    }
}
```

### 替换方法

```java
XposedHelpers.findAndHookMethod(
    "com.target.app.Security",
    lpparam.classLoader,
    "isRooted",
    new XC_MethodReplacement() {
        @Override
        protected Object replaceHookedMethod(MethodHookParam param) {
            // 完全替换原方法
            return false;
        }
    }
);
```

### Hook 构造器

```java
XposedHelpers.findAndHookConstructor(
    "com.target.app.User",
    lpparam.classLoader,
    String.class,  // name
    int.class,     // age
    new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            XposedBridge.log("User created: " + param.args[0]);
        }
    }
);
```

### 获取/设置字段

```java
// 实例字段
Object obj = param.thisObject;
String name = (String) XposedHelpers.getObjectField(obj, "name");
XposedHelpers.setObjectField(obj, "name", "modified");

// 静态字段
int value = XposedHelpers.getStaticIntField(clazz, "staticField");
XposedHelpers.setStaticIntField(clazz, "staticField", 42);
```

### Hook 所有方法

```java
Class<?> clazz = XposedHelpers.findClass("com.target.app.Target", lpparam.classLoader);

for (Method method : clazz.getDeclaredMethods()) {
    XposedBridge.hookMethod(method, new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            XposedBridge.log("Called: " + param.method.getName());
        }
    });
}
```


## 实战场景

### Lab 1: 绕过 Root 检测

```java
// Hook 常见检测方法
String[] rootCheckClasses = {
    "com.scottyab.rootbeer.RootBeer",
    "com.example.RootChecker"
};

for (String className : rootCheckClasses) {
    try {
        XposedHelpers.findAndHookMethod(
            className,
            lpparam.classLoader,
            "isRooted",
            new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return false;
                }
            }
        );
    } catch (Throwable t) {
        // 类不存在，跳过
    }
}

// Hook Runtime.exec 检测
XposedHelpers.findAndHookMethod(
    Runtime.class,
    "exec",
    String.class,
    new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            String cmd = (String) param.args[0];
            if (cmd.contains("su") || cmd.contains("which")) {
                param.setThrowable(new IOException("Command not found"));
            }
        }
    }
);
```

### Lab 2: SSL Pinning 绕过

```java
// Hook OkHttp CertificatePinner
try {
    XposedHelpers.findAndHookMethod(
        "okhttp3.CertificatePinner",
        lpparam.classLoader,
        "check",
        String.class, List.class,
        new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) {
                return null;  // 跳过检查
            }
        }
    );
} catch (Throwable t) {}

// Hook TrustManager
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String auth) {}
        public void checkServerTrusted(X509Certificate[] chain, String auth) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};

// Hook SSLContext.init
XposedHelpers.findAndHookMethod(
    "javax.net.ssl.SSLContext",
    lpparam.classLoader,
    "init",
    KeyManager[].class, TrustManager[].class, SecureRandom.class,
    new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            param.args[1] = trustAllCerts;
        }
    }
);
```

### Lab 3: CVE 复现辅助

```java
// 示例：分析 AMS 调用
XposedHelpers.findAndHookMethod(
    "com.android.server.am.ActivityManagerService",
    lpparam.classLoader,
    "startActivity",
    IApplicationThread.class, String.class, Intent.class,
    // ... 更多参数
    new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            Intent intent = (Intent) param.args[2];
            int callingUid = Binder.getCallingUid();
            XposedBridge.log(String.format(
                "startActivity: uid=%d, intent=%s",
                callingUid, intent
            ));
        }
    }
);
```


## LSPosed 特有功能

### 模块作用域

```xml
<!-- res/values/arrays.xml -->
<resources>
    <string-array name="xposed_scope">
        <item>com.target.app</item>
        <item>system</item>
    </string-array>
</resources>
```

### 资源 Hook

```java
public class MainHook implements IXposedHookInitPackageResources {
    
    @Override
    public void handleInitPackageResources(InitPackageResourcesParam resparam) {
        if (!resparam.packageName.equals("com.target.app")) {
            return;
        }
        
        // 替换字符串资源
        resparam.res.setReplacement(
            "com.target.app",
            "string",
            "app_name",
            "Modified Name"
        );
        
        // 替换布局
        resparam.res.hookLayout(
            "com.target.app",
            "layout",
            "activity_main",
            new XC_LayoutInflated() {
                @Override
                public void handleLayoutInflated(LayoutInflatedParam liparam) {
                    View view = liparam.view.findViewById(
                        liparam.res.getIdentifier("button", "id", "com.target.app")
                    );
                    // 修改 view
                }
            }
        );
    }
}
```


## 调试技巧

### 日志

```java
// Xposed 日志
XposedBridge.log("Message");

// 带 tag
XposedBridge.log("[MyModule] " + message);

// 查看日志
adb logcat -s LSPosed Xposed
```

### 错误处理

```java
try {
    // Hook 代码
} catch (NoSuchMethodError e) {
    XposedBridge.log("Method not found: " + e.getMessage());
} catch (ClassNotFoundException e) {
    XposedBridge.log("Class not found: " + e.getMessage());
} catch (Throwable t) {
    XposedBridge.log(t);
}
```


## 常见陷阱

### ❌ 陷阱 1: ClassLoader 问题

```java
// 错误：使用系统 ClassLoader
Class.forName("com.target.app.MyClass");

// 正确：使用应用的 ClassLoader
XposedHelpers.findClass("com.target.app.MyClass", lpparam.classLoader);
```

### ❌ 陷阱 2: 混淆后的类名

```java
// 混淆后类名变化，需要分析 mapping.txt
// 或使用其他特征定位
```

### ❌ 陷阱 3: 线程安全

```java
// Hook 回调可能在不同线程执行
// 注意同步问题
```


## 深入阅读

**推荐资源：**
- [LSPosed](https://github.com/LSPosed/LSPosed)
- [Xposed API](https://api.xposed.info/)

**相关章节：**
- [05 - Smali 与逆向](./05-smali.md) - 静态分析配合
- [04 - JVM 与 ART](./04-jvm-art.md) - 运行时原理


## 系列总结

Java Essentials 完成！你现在应该能够：

- ✅ 掌握 Java 核心语法和 OOP
- ✅ 理解 JVM/ART 运行时
- ✅ 阅读和修改 Smali 代码
- ✅ 分析 AOSP Framework
- ✅ 开发 Xposed/LSPosed 模块


## 下一步

继续学习：
- [Rust Essentials](../rust_essentials/) - 内存安全编程
- [C Essentials](../c_essentials/) - 内核/驱动开发
- [Android Security Notes](../android/) - 深入安全研究
