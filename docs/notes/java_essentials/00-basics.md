# 00 - 基础语法

Java 核心语法快速回顾，为 Android Framework 开发打基础。

---

## 概念速览

**Java 是什么？**
1995 年诞生的面向对象语言，"Write Once, Run Anywhere"。

**为什么 Android 选择 Java？**
- 当时最流行的应用开发语言
- 大量开发者基础
- 虚拟机提供安全隔离

**与 C 的关键区别：**

| 特性 | C | Java |
|------|---|------|
| 内存管理 | 手动 | GC 自动回收 |
| 指针 | 有 | 无（只有引用）|
| 类型系统 | 弱类型 | 强类型 |
| 面向对象 | 无 | 完整支持 |
| 编译目标 | 机器码 | 字节码 |

---

## 核心概念

### JVM vs ART

```
传统 Java:      .java → javac → .class → JVM 解释/JIT
Android (旧):   .java → javac → .class → dx → .dex → Dalvik
Android (新):   .java → javac → .class → d8 → .dex → ART (AOT+JIT)
```

**为什么 Android 不直接用 JVM？**
1. Oracle 许可证问题
2. 移动设备资源限制
3. DEX 格式更紧凑

### 程序入口

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, Android!");
    }
}
```

**编译运行：**
```bash
javac HelloWorld.java
java HelloWorld
```

---

## 基础用法

### 数据类型

```java
// 基本类型 (primitive)
byte    b = 127;          // 1 byte, -128 ~ 127
short   s = 32767;        // 2 bytes
int     i = 42;           // 4 bytes
long    l = 100000L;      // 8 bytes
float   f = 3.14f;        // 4 bytes
double  d = 3.14159;      // 8 bytes
char    c = 'A';          // 2 bytes (Unicode)
boolean flag = true;      // 1 bit (逻辑上)

// 引用类型
String str = "Hello";
int[] arr = {1, 2, 3};
Object obj = new Object();
```

**与 C 的区别：**
- Java 的 `char` 是 2 字节（Unicode）
- 没有无符号类型（但可以用位运算模拟）
- `boolean` 是独立类型，不是数字

### 包装类

```java
// 基本类型的对象包装
Integer i = Integer.valueOf(42);     // 装箱
int n = i.intValue();                // 拆箱

// 自动装箱/拆箱 (Java 5+)
Integer x = 42;    // 自动装箱
int y = x;         // 自动拆箱

// 字符串转换
int parsed = Integer.parseInt("123");
String str = String.valueOf(456);
```

### 变量与常量

```java
// 变量
int count = 0;
count = 10;

// 常量 (final)
final int MAX_SIZE = 100;
// MAX_SIZE = 200;  // 编译错误！

// 静态常量
public static final int BUFFER_SIZE = 1024;
```

### 控制流

```java
// if-else
if (x > 0) {
    System.out.println("positive");
} else if (x < 0) {
    System.out.println("negative");
} else {
    System.out.println("zero");
}

// switch (支持 String，Java 7+)
switch (day) {
    case "Monday":
        System.out.println("Start of week");
        break;
    case "Friday":
        System.out.println("End of week");
        break;
    default:
        System.out.println("Middle");
}

// switch 表达式 (Java 14+)
String result = switch (day) {
    case "Monday" -> "Start";
    case "Friday" -> "End";
    default -> "Middle";
};
```

### 循环

```java
// for 循环
for (int i = 0; i < 10; i++) {
    System.out.println(i);
}

// 增强 for (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println(num);
}

// while
int i = 0;
while (i < 10) {
    System.out.println(i++);
}

// do-while
do {
    System.out.println("至少执行一次");
} while (false);
```

### 数组

```java
// 声明和初始化
int[] arr1 = new int[5];           // 默认值为 0
int[] arr2 = {1, 2, 3, 4, 5};      // 直接初始化
int[] arr3 = new int[]{1, 2, 3};   // 匿名初始化

// 多维数组
int[][] matrix = new int[3][4];
int[][] jagged = {{1, 2}, {3, 4, 5}};  // 锯齿数组

// 数组长度
System.out.println(arr2.length);  // 5

// 遍历
for (int i = 0; i < arr2.length; i++) {
    System.out.println(arr2[i]);
}

// 工具方法
Arrays.sort(arr2);                    // 排序
Arrays.fill(arr1, 0);                 // 填充
int[] copy = Arrays.copyOf(arr2, 10); // 复制
```

---

## 进阶用法

### 方法

```java
public class Calculator {
    // 实例方法
    public int add(int a, int b) {
        return a + b;
    }
    
    // 静态方法
    public static int multiply(int a, int b) {
        return a * b;
    }
    
    // 可变参数
    public int sum(int... numbers) {
        int total = 0;
        for (int n : numbers) {
            total += n;
        }
        return total;
    }
}

// 使用
Calculator calc = new Calculator();
calc.add(1, 2);           // 实例方法需要对象
Calculator.multiply(3, 4); // 静态方法直接调用
calc.sum(1, 2, 3, 4, 5);  // 可变参数
```

### 字符串

```java
// String 是不可变的
String s1 = "Hello";
String s2 = "Hello";
System.out.println(s1 == s2);      // true (字符串池)
System.out.println(s1.equals(s2)); // true

String s3 = new String("Hello");
System.out.println(s1 == s3);      // false (不同对象)
System.out.println(s1.equals(s3)); // true

// 常用方法
s1.length();                 // 5
s1.charAt(0);                // 'H'
s1.substring(1, 3);          // "el"
s1.indexOf("l");             // 2
s1.replace("l", "L");        // "HeLLo"
s1.split(",");               // 分割
s1.toUpperCase();            // "HELLO"
s1.trim();                   // 去除首尾空白

// StringBuilder (可变，线程不安全)
StringBuilder sb = new StringBuilder();
sb.append("Hello").append(" ").append("World");
String result = sb.toString();

// StringBuffer (可变，线程安全)
StringBuffer sbf = new StringBuffer();
```

> [!TIP]
> 循环拼接字符串时使用 `StringBuilder`，避免创建大量临时对象。

### 异常处理

```java
try {
    int result = 10 / 0;
} catch (ArithmeticException e) {
    System.out.println("除零错误: " + e.getMessage());
} catch (Exception e) {
    System.out.println("其他错误: " + e.getMessage());
} finally {
    System.out.println("总是执行");
}

// try-with-resources (Java 7+)
try (FileInputStream fis = new FileInputStream("file.txt")) {
    // 自动关闭
} catch (IOException e) {
    e.printStackTrace();
}

// 抛出异常
public void readFile(String path) throws IOException {
    if (path == null) {
        throw new IllegalArgumentException("Path cannot be null");
    }
    // ...
}
```

**异常层次：**
```
Throwable
├── Error           ← 不应捕获
│   ├── OutOfMemoryError
│   └── StackOverflowError
└── Exception
    ├── RuntimeException   ← 非检查异常
    │   ├── NullPointerException
    │   └── IndexOutOfBoundsException
    └── IOException        ← 检查异常
```

---

## 实战场景

### Lab 1: 命令行参数解析

```java
public class Args {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Args <name> <count>");
            return;
        }
        
        String name = args[0];
        int count = Integer.parseInt(args[1]);
        
        for (int i = 0; i < count; i++) {
            System.out.printf("Hello, %s! (%d)\n", name, i + 1);
        }
    }
}
```

### Lab 2: 简单计算器

```java
import java.util.Scanner;

public class Calculator {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("输入表达式 (如 3 + 4): ");
        double a = scanner.nextDouble();
        String op = scanner.next();
        double b = scanner.nextDouble();
        
        double result = switch (op) {
            case "+" -> a + b;
            case "-" -> a - b;
            case "*" -> a * b;
            case "/" -> b != 0 ? a / b : Double.NaN;
            default -> {
                System.out.println("未知运算符");
                yield Double.NaN;
            }
        };
        
        System.out.printf("%.2f %s %.2f = %.2f\n", a, op, b, result);
        scanner.close();
    }
}
```

### Lab 3: 文件读写

```java
import java.io.*;
import java.nio.file.*;

public class FileDemo {
    public static void main(String[] args) throws IOException {
        // 传统方式
        try (BufferedReader reader = new BufferedReader(
                new FileReader("input.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
        
        // NIO 方式 (简洁)
        String content = Files.readString(Path.of("input.txt"));
        Files.writeString(Path.of("output.txt"), content);
        
        // 读取所有行
        List<String> lines = Files.readAllLines(Path.of("input.txt"));
    }
}
```

---

## 常见陷阱

### ❌ 陷阱 1: == vs equals

```java
String s1 = "hello";
String s2 = new String("hello");

// 错误
if (s1 == s2) { ... }  // false！比较引用

// 正确
if (s1.equals(s2)) { ... }  // true，比较内容

// 更安全（避免 NullPointerException）
if ("hello".equals(s2)) { ... }
```

### ❌ 陷阱 2: Integer 缓存

```java
Integer a = 127;
Integer b = 127;
System.out.println(a == b);  // true (缓存 -128~127)

Integer c = 128;
Integer d = 128;
System.out.println(c == d);  // false!
System.out.println(c.equals(d));  // true
```

### ❌ 陷阱 3: 空指针

```java
String s = null;
// s.length();  // NullPointerException

// 防御
if (s != null && s.length() > 0) { ... }

// 或使用 Optional (Java 8+)
Optional.ofNullable(s).ifPresent(str -> System.out.println(str.length()));
```

### ❌ 陷阱 4: 浮点比较

```java
double a = 0.1 + 0.2;
double b = 0.3;

// 错误
if (a == b) { ... }  // 可能是 false!

// 正确
if (Math.abs(a - b) < 1e-10) { ... }

// 或使用 BigDecimal
BigDecimal x = new BigDecimal("0.1");
BigDecimal y = new BigDecimal("0.2");
BigDecimal z = x.add(y);  // 精确
```

---

## 深入阅读

**推荐资源：**
- [Oracle Java Tutorials](https://docs.oracle.com/javase/tutorial/)
- [Effective Java (书籍)](https://www.oreilly.com/library/view/effective-java-3rd/9780134686097/)

**相关章节：**
- [01 - 面向对象](./01-oop.md) - 类、继承、接口
- [04 - JVM 与 ART](./04-jvm-art.md) - 深入运行时

---

## 下一步

[01 - 面向对象](./01-oop.md) - Java 的核心范式
