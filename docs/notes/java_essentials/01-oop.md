# 01 - 面向对象

Java 的核心范式：类、继承、接口、多态。


## 概念速览

**OOP 四大特性：**
- **封装** - 隐藏实现细节
- **继承** - 代码复用
- **多态** - 统一接口，不同实现
- **抽象** - 定义规范，隐藏细节

**为什么 Android Framework 重度使用 OOP？**
- 代码复用和模块化
- 解耦和可测试性
- 适合大型团队协作


## 核心概念

### 类与对象

```java
// 类定义
public class Person {
    // 字段 (属性)
    private String name;
    private int age;
    
    // 构造器
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    // 方法
    public void introduce() {
        System.out.printf("I'm %s, %d years old\n", name, age);
    }
    
    // Getter/Setter
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

// 创建对象
Person person = new Person("Alice", 25);
person.introduce();
```

### 访问控制

| 修饰符 | 本类 | 同包 | 子类 | 其他包 |
|--------|------|------|------|--------|
| `private` | ✓ | ✗ | ✗ | ✗ |
| (默认) | ✓ | ✓ | ✗ | ✗ |
| `protected` | ✓ | ✓ | ✓ | ✗ |
| `public` | ✓ | ✓ | ✓ | ✓ |

**最佳实践：**
- 字段通常 `private`
- 方法按需开放
- 构造器通常 `public`

### 静态成员

```java
public class Counter {
    private static int count = 0;  // 类变量
    private int id;                // 实例变量
    
    public Counter() {
        this.id = ++count;
    }
    
    public static int getCount() {  // 类方法
        return count;
    }
    
    public int getId() {
        return id;
    }
}

Counter c1 = new Counter();
Counter c2 = new Counter();
System.out.println(Counter.getCount());  // 2
```


## 继承

### 基本继承

```java
// 父类
public class Animal {
    protected String name;
    
    public Animal(String name) {
        this.name = name;
    }
    
    public void speak() {
        System.out.println("Some sound");
    }
}

// 子类
public class Dog extends Animal {
    public Dog(String name) {
        super(name);  // 调用父类构造器
    }
    
    @Override
    public void speak() {
        System.out.println(name + " says: Woof!");
    }
    
    public void fetch() {
        System.out.println(name + " fetches the ball");
    }
}

Dog dog = new Dog("Buddy");
dog.speak();  // Buddy says: Woof!
dog.fetch();  // Buddy fetches the ball
```

### 方法重写规则

```java
public class Parent {
    public void method() { }
    protected void protectedMethod() { }
    final void finalMethod() { }  // 不能重写
}

public class Child extends Parent {
    @Override
    public void method() { }  // OK
    
    @Override
    public void protectedMethod() { }  // OK, 可以放大访问权限
    
    // @Override void finalMethod() { }  // 编译错误！
}
```

**重写规则：**
- 方法签名相同
- 返回类型相同或协变
- 访问权限不能缩小
- 不能抛出更多检查异常

### Object 类

所有类的根类：

```java
public class Object {
    public String toString() { ... }
    public boolean equals(Object obj) { ... }
    public int hashCode() { ... }
    public final Class<?> getClass() { ... }
    protected Object clone() { ... }
    protected void finalize() { ... }  // 已废弃
    // ...
}
```

**重写 equals 和 hashCode：**

```java
public class Person {
    private String name;
    private int age;
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Person person = (Person) o;
        return age == person.age && Objects.equals(name, person.name);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name, age);
    }
}
```

> [!CAUTION]
> 重写 `equals` 必须同时重写 `hashCode`，否则 HashMap 等会出问题。


## 接口

### 接口定义

```java
public interface Drawable {
    void draw();  // 抽象方法 (隐式 public abstract)
    
    default void clear() {  // 默认方法 (Java 8+)
        System.out.println("Clearing...");
    }
    
    static void helper() {  // 静态方法
        System.out.println("Helper");
    }
}

public class Circle implements Drawable {
    @Override
    public void draw() {
        System.out.println("Drawing circle");
    }
}
```

### 多接口实现

```java
public interface Runnable {
    void run();
}

public interface Comparable<T> {
    int compareTo(T o);
}

public class Task implements Runnable, Comparable<Task> {
    private int priority;
    
    @Override
    public void run() {
        System.out.println("Running task");
    }
    
    @Override
    public int compareTo(Task other) {
        return Integer.compare(this.priority, other.priority);
    }
}
```

### 函数式接口 (Java 8+)

```java
@FunctionalInterface
public interface Calculator {
    int calculate(int a, int b);
}

// Lambda 表达式
Calculator add = (a, b) -> a + b;
Calculator sub = (a, b) -> a - b;

System.out.println(add.calculate(3, 2));  // 5
System.out.println(sub.calculate(3, 2));  // 1
```


## 抽象类

### 抽象类 vs 接口

```java
public abstract class Shape {
    protected String color;
    
    public Shape(String color) {
        this.color = color;
    }
    
    // 抽象方法
    public abstract double area();
    
    // 具体方法
    public void setColor(String color) {
        this.color = color;
    }
}

public class Rectangle extends Shape {
    private double width, height;
    
    public Rectangle(String color, double width, double height) {
        super(color);
        this.width = width;
        this.height = height;
    }
    
    @Override
    public double area() {
        return width * height;
    }
}
```

| 特性 | 抽象类 | 接口 |
|------|--------|------|
| 构造器 | 有 | 无 |
| 成员变量 | 任意 | 只能 static final |
| 方法实现 | 可以有 | 只能 default/static |
| 继承 | 单继承 | 多实现 |
| 使用场景 | is-a 关系 | can-do 能力 |


## 多态

### 运行时多态

```java
Animal[] animals = {
    new Dog("Buddy"),
    new Cat("Whiskers"),
    new Bird("Tweety")
};

for (Animal animal : animals) {
    animal.speak();  // 根据实际类型调用
}
// Buddy says: Woof!
// Whiskers says: Meow!
// Tweety says: Tweet!
```

### 向上转型与向下转型

```java
// 向上转型 (自动)
Animal animal = new Dog("Buddy");
animal.speak();  // OK
// animal.fetch();  // 编译错误！Animal 没有 fetch

// 向下转型 (需要强制)
if (animal instanceof Dog) {
    Dog dog = (Dog) animal;
    dog.fetch();  // OK
}

// 模式匹配 (Java 16+)
if (animal instanceof Dog dog) {
    dog.fetch();  // 直接使用
}
```


## 内部类

### 成员内部类

```java
public class Outer {
    private int x = 10;
    
    public class Inner {
        public void access() {
            System.out.println("x = " + x);  // 可以访问外部类私有成员
        }
    }
}

Outer outer = new Outer();
Outer.Inner inner = outer.new Inner();
inner.access();
```

### 静态内部类

```java
public class Outer {
    private static int staticX = 10;
    
    public static class StaticInner {
        public void access() {
            System.out.println("staticX = " + staticX);
            // System.out.println("x = " + x);  // 不能访问非静态成员
        }
    }
}

Outer.StaticInner inner = new Outer.StaticInner();
```

### 匿名内部类

```java
// 传统方式
Runnable task = new Runnable() {
    @Override
    public void run() {
        System.out.println("Running");
    }
};

// Lambda (函数式接口)
Runnable lambdaTask = () -> System.out.println("Running");
```


## 实战场景

### Lab 1: Android Service 模式

```java
// Android 系统服务的典型模式
public interface IActivityManager {
    void startActivity(Intent intent);
    void bindService(Intent intent, ServiceConnection conn);
}

public class ActivityManagerService implements IActivityManager {
    @Override
    public void startActivity(Intent intent) {
        // 实现...
    }
    
    @Override
    public void bindService(Intent intent, ServiceConnection conn) {
        // 实现...
    }
}
```

### Lab 2: Builder 模式

```java
public class AlertDialog {
    private String title;
    private String message;
    private String positiveButton;
    
    private AlertDialog(Builder builder) {
        this.title = builder.title;
        this.message = builder.message;
        this.positiveButton = builder.positiveButton;
    }
    
    public static class Builder {
        private String title;
        private String message;
        private String positiveButton;
        
        public Builder setTitle(String title) {
            this.title = title;
            return this;
        }
        
        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }
        
        public Builder setPositiveButton(String text) {
            this.positiveButton = text;
            return this;
        }
        
        public AlertDialog build() {
            return new AlertDialog(this);
        }
    }
}

// 使用
AlertDialog dialog = new AlertDialog.Builder()
    .setTitle("确认")
    .setMessage("是否删除?")
    .setPositiveButton("删除")
    .build();
```

### Lab 3: 观察者模式

```java
// Android 中大量使用
public interface Observer {
    void onUpdate(String data);
}

public class Subject {
    private List<Observer> observers = new ArrayList<>();
    
    public void addObserver(Observer o) {
        observers.add(o);
    }
    
    public void notifyAll(String data) {
        for (Observer o : observers) {
            o.onUpdate(data);
        }
    }
}
```


## 常见陷阱

### ❌ 陷阱 1: equals 与 == 混淆

```java
String s1 = new String("hello");
String s2 = new String("hello");

// 错误
if (s1 == s2) { ... }  // false

// 正确
if (s1.equals(s2)) { ... }  // true
```

### ❌ 陷阱 2: 构造器调用虚方法

```java
public class Parent {
    public Parent() {
        init();  // 危险！
    }
    
    protected void init() { }
}

public class Child extends Parent {
    private String name;
    
    public Child() {
        name = "child";
    }
    
    @Override
    protected void init() {
        System.out.println(name.length());  // NullPointerException!
    }
}
```

### ❌ 陷阱 3: 过度继承

```java
// 不好：继承只是为了复用代码
public class Stack extends ArrayList { ... }

// 好：组合优于继承
public class Stack {
    private List<Object> list = new ArrayList<>();
    // ...
}
```


## 深入阅读

**推荐资源：**
- [Effective Java - Item 18: Favor composition over inheritance](https://www.oreilly.com/library/view/effective-java-3rd/9780134686097/)
- [Design Patterns](https://refactoring.guru/design-patterns)

**相关章节：**
- [02 - 集合框架](./02-collections.md) - List, Map, Set
- [06 - AOSP 实战](./06-android-java.md) - Framework 中的 OOP


## 下一步

[02 - 集合框架](./02-collections.md) - Java 数据结构
