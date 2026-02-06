# 05 - Smali 与逆向

DEX 字节码、Smali 语法、逆向工具。


## 概念速览

**什么是 Smali？**
DEX 字节码的人类可读形式，类似汇编。

**为什么要学 Smali？**
- APK 逆向分析基础
- 理解木马/恶意软件行为
- 修改和重打包 APK
- 漏洞 PoC 开发

**工作流程：**
```
APK → 解包 → classes.dex → baksmali → .smali 文件
                                ↓ 分析/修改
                             smali → classes.dex → 重打包 → 签名
```


## Smali 语法

### 文件结构

```smali
.class public Lcom/example/MyClass;
.super Ljava/lang/Object;
.source "MyClass.java"

# 接口
.implements Landroid/view/View$OnClickListener;

# 字段
.field private name:Ljava/lang/String;
.field public static final TAG:Ljava/lang/String; = "MyClass"

# 方法
.method public constructor <init>()V
    .registers 1
    
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
```

### 类型描述符

| Java 类型 | Smali 描述符 |
|-----------|-------------|
| void | V |
| boolean | Z |
| byte | B |
| char | C |
| short | S |
| int | I |
| long | J |
| float | F |
| double | D |
| Object | Ljava/lang/Object; |
| int[] | [I |
| Object[][] | [[Ljava/lang/Object; |

### 寄存器

```smali
# p 寄存器: 参数 (p0 是 this)
# v 寄存器: 局部变量

.method public add(II)I
    .registers 4    # 总共 4 个寄存器
    
    # p0 = this
    # p1 = 参数 a
    # p2 = 参数 b
    # v0 = 局部变量
    
    add-int v0, p1, p2
    return v0
.end method
```

### 常用指令

```smali
# 常量
const/4 v0, 0x0        # 4 位常量 (0)
const/16 v0, 0x100     # 16 位常量
const-string v0, "hello"

# 移动
move v0, v1            # 寄存器移动
move-result v0         # 获取返回值
move-exception v0      # 获取异常

# 返回
return-void
return v0
return-object v0

# 条件跳转
if-eq v0, v1, :label   # v0 == v1
if-ne v0, v1, :label   # v0 != v1
if-lt v0, v1, :label   # v0 < v1
if-ge v0, v1, :label   # v0 >= v1
if-eqz v0, :label      # v0 == 0
if-nez v0, :label      # v0 != 0

# 跳转
goto :label

# 方法调用
invoke-virtual {v0, v1}, Lcom/example/Class;->method(I)V
invoke-direct {p0}, Ljava/lang/Object;-><init>()V
invoke-static {v0}, Ljava/lang/Math;->abs(I)I
invoke-interface {v0}, Ljava/lang/Runnable;->run()V

# 字段访问
iget v0, p0, Lcom/example/Class;->field:I
iput v1, p0, Lcom/example/Class;->field:I
sget v0, Lcom/example/Class;->staticField:I
sput v1, Lcom/example/Class;->staticField:I

# 对象操作
new-instance v0, Lcom/example/Class;
check-cast v0, Ljava/lang/String;
instance-of v0, v1, Ljava/lang/String;

# 数组
new-array v0, v1, [I
array-length v0, v1
aget v0, v1, v2
aput v0, v1, v2
```


## 逆向工具

### apktool

```bash
# 安装
brew install apktool

# 反编译
apktool d app.apk -o app_out

# 重打包
apktool b app_out -o app_modified.apk

# 签名
jarsigner -keystore my.keystore app_modified.apk alias_name
# 或
apksigner sign --ks my.keystore app_modified.apk
```

### jadx

```bash
# 安装
brew install jadx

# GUI
jadx-gui app.apk

# 命令行
jadx app.apk -d output_dir
```

**jadx 输出：**
- 反编译的 Java 代码
- 资源文件
- AndroidManifest.xml

### dex2jar & jd-gui

```bash
# dex 转 jar
d2j-dex2jar classes.dex

# 用 jd-gui 查看
jd-gui classes-dex2jar.jar
```

### Frida

```bash
# 安装
pip install frida-tools

# 列出进程
frida-ps -U

# Hook
frida -U -f com.example.app -l hook.js
```

```javascript
// hook.js
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    
    MainActivity.onClick.implementation = function(view) {
        console.log("onClick called!");
        this.onClick(view);
    };
});
```


## 实战场景

### Lab 1: 分析简单方法

**Java 源码：**
```java
public int add(int a, int b) {
    return a + b;
}
```

**Smali：**
```smali
.method public add(II)I
    .registers 4
    
    .param p1, "a"
    .param p2, "b"
    
    add-int v0, p1, p2
    return v0
.end method
```

### Lab 2: 修改返回值

**目标：** 让 `isValid()` 总是返回 `true`

**原始：**
```smali
.method public isValid()Z
    .registers 2
    
    # 一些验证逻辑...
    sget-boolean v0, Lcom/example/App;->validated:Z
    return v0
.end method
```

**修改后：**
```smali
.method public isValid()Z
    .registers 2
    
    const/4 v0, 0x1    # 直接返回 true
    return v0
.end method
```

### Lab 3: 添加日志

**添加位置：方法开头**

```smali
.method public secretMethod()V
    .registers 3
    
    # 添加日志
    const-string v0, "TAG"
    const-string v1, "secretMethod called"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    
    # 原始代码...
    return-void
.end method
```

### Lab 4: 绕过签名验证

**常见模式：**
```smali
.method private checkSignature()Z
    .registers 3
    
    # 获取签名
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    
    # ... 验证逻辑
    
    # 直接返回 true 绕过
    const/4 v0, 0x1
    return v0
.end method
```


## 常见混淆手段

### ProGuard 混淆

```smali
# 混淆前
Lcom/example/UserManager;->validateUser(Ljava/lang/String;)Z

# 混淆后
La/b/c;->a(Ljava/lang/String;)Z
```

**应对：**
- 根据字符串定位
- 分析调用关系
- 动态调试

### 字符串加密

```java
// 原始
String key = "secret_key";

// 加密后
String key = decrypt("base64_encoded_string");
```

**应对：**
- Hook `decrypt` 方法
- 分析加密算法
- 动态获取解密结果

### 控制流混淆

```smali
# 插入不透明谓词
if-nez v0, :real_code
goto :fake_code

:real_code
# 真实代码

:fake_code
# 永远不执行的代码
```


## 常见陷阱

### ❌ 陷阱 1: 寄存器数量不足

```smali
# 错误：使用超出范围的寄存器
.method public test()V
    .registers 2
    
    const/4 v3, 0x0   # 寄存器 v3 不存在！
.end method
```

### ❌ 陷阱 2: 忘记修改 `.registers`

添加代码后需要增加寄存器数量。

### ❌ 陷阱 3: 对齐签名

修改后需要重新签名，否则无法安装。

```bash
# 对齐
zipalign -v 4 app_modified.apk app_aligned.apk

# 签名
apksigner sign --ks my.keystore app_aligned.apk
```


## 深入阅读

**推荐资源：**
- [Smali/Baksmali](https://github.com/JesusFreke/smali)
- [Android Reverse Engineering](https://maddiestone.github.io/AndroidAppRE/)

**相关章节：**
- [04 - JVM 与 ART](./04-jvm-art.md) - DEX 格式
- [07 - Xposed/LSPosed](./07-xposed-lsposed.md) - Hook 开发


## 下一步

[06 - AOSP 实战](./06-android-java.md) - Framework 分析
