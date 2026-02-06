# 04 - JVM 与 ART

Java 虚拟机基础和 Android 运行时。

---

## 概念速览

**为什么要学 JVM/ART？**
- 理解内存布局和 GC
- 性能优化基础
- Xposed Hook 的前提
- 漏洞分析需要

**JVM vs Android 运行时：**

| 特性 | JVM | Dalvik | ART |
|------|-----|--------|-----|
| 字节码 | .class | .dex | .dex |
| 执行 | 解释+JIT | 解释+JIT | AOT+JIT |
| Android 版本 | - | 4.4 以前 | 5.0+ |
| 性能 | 中等 | 较慢 | 快 |

---

## JVM 基础

### 类加载

```
加载 → 验证 → 准备 → 解析 → 初始化 → 使用 → 卸载
```

**类加载器层次：**
```
Bootstrap ClassLoader  ← rt.jar (核心类)
       ↓
Extension ClassLoader  ← ext/*.jar
       ↓
Application ClassLoader ← classpath
       ↓
Custom ClassLoader
```

**双亲委派模型：**

```java
protected Class<?> loadClass(String name) {
    // 1. 检查是否已加载
    Class<?> c = findLoadedClass(name);
    
    if (c == null) {
        // 2. 委托父加载器
        if (parent != null) {
            c = parent.loadClass(name);
        } else {
            c = findBootstrapClassOrNull(name);
        }
        
        // 3. 父加载器找不到，自己加载
        if (c == null) {
            c = findClass(name);
        }
    }
    return c;
}
```

**为什么这样设计？**
- 安全：防止核心类被替换
- 避免重复加载
- 保证类的唯一性

### 内存区域

```
┌─────────────────────────────────────────────┐
│            Method Area (方法区)              │
│  - 类信息、常量池、静态变量                    │
├─────────────────────────────────────────────┤
│                 Heap (堆)                    │
│              对象实例、数组                    │
│  ┌─────────────┬──────────────────────────┐ │
│  │ Young Gen   │      Old Generation      │ │
│  │ Eden│S0│S1  │                          │ │
│  └─────────────┴──────────────────────────┘ │
├─────────────────────────────────────────────┤
│  Stack │ Stack │ Stack │     ...  (每线程)   │
│  局部变量、操作数栈、栈帧                      │
├─────────────────────────────────────────────┤
│            Native Method Stack               │
├─────────────────────────────────────────────┤
│            PC Register (程序计数器)           │
└─────────────────────────────────────────────┘
```

### 垃圾回收

**GC 算法：**

| 算法 | 特点 | 适用场景 |
|------|------|----------|
| 标记-清除 | 产生碎片 | 老年代 |
| 标记-整理 | 无碎片，慢 | 老年代 |
| 复制 | 快，浪费空间 | 新生代 |
| 分代 | 综合以上 | 通用 |

**对象分配流程：**

```
新对象 → Eden
         ↓ Eden 满
      Minor GC
         ↓ 存活
    Survivor (S0/S1)
         ↓ 年龄够大
    Old Generation
         ↓ Old 满
      Major GC / Full GC
```

---

## Android ART

### Dalvik vs ART

```
Dalvik (Android 4.4 以前):
  安装快 → 运行时 JIT 编译 → 启动慢

ART (Android 5.0+):
  安装时 AOT 编译 → 运行时直接执行 + JIT → 启动快
```

### DEX 文件格式

```
┌─────────────────────┐
│     DEX Header      │ ← 文件校验、版本
├─────────────────────┤
│     String IDs      │ ← 字符串表
├─────────────────────┤
│      Type IDs       │ ← 类型表
├─────────────────────┤
│     Proto IDs       │ ← 方法原型
├─────────────────────┤
│     Field IDs       │ ← 字段引用
├─────────────────────┤
│    Method IDs       │ ← 方法引用
├─────────────────────┤
│    Class Defs       │ ← 类定义
├─────────────────────┤
│       Data          │ ← 实际代码和数据
└─────────────────────┘
```

### ART 编译流程

```
.java
   ↓ javac
.class
   ↓ d8/r8
.dex
   ↓ 安装时 dex2oat (AOT)
.oat / .vdex / .art
   ↓ 运行时
Native Code + 热点 JIT
```

### Android GC

```
ART GC 类型:
├── Concurrent Mark Sweep (CMS)
├── Concurrent Copying
└── Generational GC (Android 10+)
```

**特点：**
- 背景 GC，减少暂停
- 分代策略
- 压缩减少碎片

---

## 反射

### 基本用法

```java
// 获取 Class
Class<?> clazz = Class.forName("com.example.Person");
Class<?> clazz2 = Person.class;
Class<?> clazz3 = person.getClass();

// 创建实例
Object obj = clazz.getDeclaredConstructor().newInstance();

// 构造器
Constructor<?> ctor = clazz.getConstructor(String.class, int.class);
Object person = ctor.newInstance("Alice", 25);

// 方法
Method method = clazz.getMethod("setName", String.class);
method.invoke(person, "Bob");

// 私有方法
Method privateMethod = clazz.getDeclaredMethod("privateMethod");
privateMethod.setAccessible(true);  // 突破访问限制
privateMethod.invoke(person);

// 字段
Field field = clazz.getDeclaredField("name");
field.setAccessible(true);
String name = (String) field.get(person);
field.set(person, "Charlie");
```

> [!WARNING]
> 反射可绕过访问控制，是安全研究和 Hook 的基础。

### 反射在 Android 中的应用

```java
// 调用隐藏 API (Android 9 开始受限)
Class<?> activityThread = Class.forName("android.app.ActivityThread");
Method currentActivityThread = activityThread.getMethod("currentActivityThread");
Object thread = currentActivityThread.invoke(null);

// 获取 Context
Method getApplication = activityThread.getMethod("getApplication");
Application app = (Application) getApplication.invoke(thread);
```

---

## JNI

### Java 端

```java
public class NativeLib {
    static {
        System.loadLibrary("native-lib");
    }
    
    // native 方法声明
    public native String stringFromJNI();
    public native int add(int a, int b);
    public native void processArray(int[] arr);
}
```

### C/C++ 端

```c
#include <jni.h>

JNIEXPORT jstring JNICALL
Java_com_example_NativeLib_stringFromJNI(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, "Hello from C");
}

JNIEXPORT jint JNICALL
Java_com_example_NativeLib_add(JNIEnv *env, jobject thiz, jint a, jint b) {
    return a + b;
}

JNIEXPORT void JNICALL
Java_com_example_NativeLib_processArray(JNIEnv *env, jobject thiz, jintArray arr) {
    jsize len = (*env)->GetArrayLength(env, arr);
    jint *elements = (*env)->GetIntArrayElements(env, arr, NULL);
    
    for (int i = 0; i < len; i++) {
        elements[i] *= 2;
    }
    
    (*env)->ReleaseIntArrayElements(env, arr, elements, 0);
}
```

### JNI 类型映射

| Java | JNI | C |
|------|-----|---|
| boolean | jboolean | unsigned char |
| byte | jbyte | signed char |
| int | jint | int |
| long | jlong | long long |
| Object | jobject | - |
| String | jstring | - |
| int[] | jintArray | - |

---

## 实战场景

### Lab 1: 自定义 ClassLoader

```java
public class MyClassLoader extends ClassLoader {
    private String classPath;
    
    public MyClassLoader(String classPath) {
        this.classPath = classPath;
    }
    
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] data = loadClassData(name);
        return defineClass(name, data, 0, data.length);
    }
    
    private byte[] loadClassData(String name) {
        String path = classPath + "/" + name.replace('.', '/') + ".class";
        try (InputStream is = new FileInputStream(path)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```

### Lab 2: 动态代理

```java
public interface Service {
    void doSomething();
}

Service proxy = (Service) Proxy.newProxyInstance(
    Service.class.getClassLoader(),
    new Class<?>[] { Service.class },
    (proxyObj, method, args) -> {
        System.out.println("Before: " + method.getName());
        Object result = method.invoke(realService, args);
        System.out.println("After: " + method.getName());
        return result;
    }
);
```

### Lab 3: 内存分析

```java
// 获取运行时信息
Runtime runtime = Runtime.getRuntime();
long maxMemory = runtime.maxMemory();
long totalMemory = runtime.totalMemory();
long freeMemory = runtime.freeMemory();
long usedMemory = totalMemory - freeMemory;

System.out.printf("Max: %dMB, Used: %dMB\n",
    maxMemory / 1024 / 1024,
    usedMemory / 1024 / 1024);

// 手动触发 GC (仅建议，不保证执行)
System.gc();
```

---

## 常见陷阱

### ❌ 陷阱 1: 反射性能

```java
// 反射比直接调用慢很多
// 热点代码避免使用反射

// 缓存 Method 对象可以缓解
private static final Method cachedMethod;
static {
    cachedMethod = MyClass.class.getMethod("myMethod");
}
```

### ❌ 陷阱 2: JNI 内存泄漏

```java
// 本地引用需要手动释放
JNIEXPORT void JNICALL method(JNIEnv *env, ...) {
    jstring str = (*env)->NewStringUTF(env, "...");
    // ... 使用 str
    (*env)->DeleteLocalRef(env, str);  // 释放
}
```

### ❌ 陷阱 3: 类加载器泄漏

```java
// 自定义 ClassLoader 加载的类如果持有静态引用
// 会导致 ClassLoader 和所有加载的类无法回收
```

---

## 深入阅读

**推荐资源：**
- [深入理解 Java 虚拟机](https://book.douban.com/subject/34907497/)
- [ART and Dalvik](https://source.android.com/devices/tech/dalvik)

**相关章节：**
- [05 - Smali 与逆向](./05-smali.md) - DEX 字节码
- [07 - Xposed/LSPosed](./07-xposed-lsposed.md) - Hook 技术

---

## 下一步

[05 - Smali 与逆向](./05-smali.md) - DEX 字节码分析
