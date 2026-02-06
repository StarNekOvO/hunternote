# 02 - 类型系统

Rust 的枚举、Option、Result、泛型、Trait。

---

## 概念速览

**Rust 类型系统的特点：**
- 编译时类型检查，无运行时开销
- 强大的枚举（代数数据类型）
- 无空指针：Option 替代 null
- 强制错误处理：Result

**与其他语言对比：**

| 特性 | C | Java | Rust |
|------|---|------|------|
| 空值 | NULL | null | Option |
| 错误处理 | 返回码 | 异常 | Result |
| 泛型 | 无（宏） | 类型擦除 | 单态化 |

---

## 枚举

### 基本枚举

```rust
enum Direction {
    Up,
    Down,
    Left,
    Right,
}

fn main() {
    let dir = Direction::Up;
    
    match dir {
        Direction::Up => println!("Going up!"),
        Direction::Down => println!("Going down!"),
        Direction::Left => println!("Going left!"),
        Direction::Right => println!("Going right!"),
    }
}
```

### 带数据的枚举

```rust
enum Message {
    Quit,                       // 无数据
    Move { x: i32, y: i32 },    // 匿名结构体
    Write(String),              // 单个值
    ChangeColor(u8, u8, u8),    // 元组
}

fn process(msg: Message) {
    match msg {
        Message::Quit => println!("Quit"),
        Message::Move { x, y } => println!("Move to ({}, {})", x, y),
        Message::Write(s) => println!("Write: {}", s),
        Message::ChangeColor(r, g, b) => println!("Color: {}/{}/{}", r, g, b),
    }
}
```

### 枚举方法

```rust
impl Message {
    fn call(&self) {
        match self {
            Message::Write(s) => println!("{}", s),
            _ => println!("Other message"),
        }
    }
}

fn main() {
    let msg = Message::Write(String::from("Hello"));
    msg.call();
}
```

---

## Option

### 无空指针

```rust
// 标准库定义
enum Option<T> {
    Some(T),
    None,
}

fn main() {
    let some_number: Option<i32> = Some(5);
    let no_number: Option<i32> = None;
    
    // 必须处理 None 情况
    match some_number {
        Some(n) => println!("Got number: {}", n),
        None => println!("No number"),
    }
}
```

### 常用方法

```rust
let x: Option<i32> = Some(5);

// unwrap (危险：None 时 panic)
let n = x.unwrap();

// expect (带自定义消息的 unwrap)
let n = x.expect("Expected a number");

// unwrap_or (提供默认值)
let n = x.unwrap_or(0);

// unwrap_or_else (延迟计算默认值)
let n = x.unwrap_or_else(|| compute_default());

// map (转换内部值)
let doubled: Option<i32> = x.map(|n| n * 2);  // Some(10)

// and_then (链式调用)
let result = x.and_then(|n| Some(n + 1));

// is_some / is_none
if x.is_some() { ... }

// if let (简化匹配)
if let Some(n) = x {
    println!("Got: {}", n);
}
```

---

## Result

### 错误处理

```rust
// 标准库定义
enum Result<T, E> {
    Ok(T),
    Err(E),
}

fn divide(a: f64, b: f64) -> Result<f64, String> {
    if b == 0.0 {
        Err(String::from("Division by zero"))
    } else {
        Ok(a / b)
    }
}

fn main() {
    match divide(10.0, 2.0) {
        Ok(result) => println!("Result: {}", result),
        Err(e) => println!("Error: {}", e),
    }
}
```

### ? 操作符

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_file(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;  // 错误时提前返回
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// 等同于
fn read_file_verbose(path: &str) -> Result<String, io::Error> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    // ...
}
```

### 常用方法

```rust
let result: Result<i32, String> = Ok(5);

// unwrap 系列 (同 Option)
let n = result.unwrap();
let n = result.expect("Failed");
let n = result.unwrap_or(0);

// map / map_err
let doubled = result.map(|n| n * 2);
let mapped_err = result.map_err(|e| format!("Error: {}", e));

// ok() / err() 转换为 Option
let opt: Option<i32> = result.ok();

// and_then 链式
let chained = result.and_then(|n| Ok(n + 1));
```

---

## 泛型

### 函数泛型

```rust
fn largest<T: PartialOrd>(list: &[T]) -> &T {
    let mut largest = &list[0];
    for item in list {
        if item > largest {
            largest = item;
        }
    }
    largest
}

fn main() {
    let numbers = vec![34, 50, 25, 100, 65];
    println!("Largest: {}", largest(&numbers));
    
    let chars = vec!['y', 'm', 'a', 'q'];
    println!("Largest: {}", largest(&chars));
}
```

### 结构体泛型

```rust
struct Point<T> {
    x: T,
    y: T,
}

impl<T> Point<T> {
    fn x(&self) -> &T {
        &self.x
    }
}

// 特定类型的实现
impl Point<f64> {
    fn distance_from_origin(&self) -> f64 {
        (self.x.powi(2) + self.y.powi(2)).sqrt()
    }
}

fn main() {
    let int_point = Point { x: 5, y: 10 };
    let float_point = Point { x: 1.0, y: 4.0 };
    
    println!("{}", float_point.distance_from_origin());
}
```

### 多个类型参数

```rust
struct Point<T, U> {
    x: T,
    y: U,
}

fn main() {
    let point = Point { x: 5, y: 4.0 };
}
```

---

## Trait

### 定义和实现

```rust
trait Summary {
    fn summarize(&self) -> String;
    
    // 默认实现
    fn summarize_author(&self) -> String {
        String::from("Unknown author")
    }
}

struct Article {
    title: String,
    author: String,
    content: String,
}

impl Summary for Article {
    fn summarize(&self) -> String {
        format!("{} by {}", self.title, self.author)
    }
    
    fn summarize_author(&self) -> String {
        self.author.clone()
    }
}

fn main() {
    let article = Article {
        title: String::from("Rust Ownership"),
        author: String::from("Alice"),
        content: String::from("..."),
    };
    println!("{}", article.summarize());
}
```

### Trait 作为参数

```rust
// 语法糖
fn notify(item: &impl Summary) {
    println!("Breaking news! {}", item.summarize());
}

// Trait bound 语法
fn notify<T: Summary>(item: &T) {
    println!("Breaking news! {}", item.summarize());
}

// 多个 trait
fn process<T: Summary + Display>(item: &T) { ... }

// where 语法
fn process<T, U>(t: &T, u: &U) -> String
where
    T: Summary + Clone,
    U: Summary + Debug,
{
    // ...
}
```

### 返回 impl Trait

```rust
fn create_summarizable() -> impl Summary {
    Article {
        title: String::from("Hello"),
        author: String::from("World"),
        content: String::from("..."),
    }
}
```

### 常用 Trait

| Trait | 功能 |
|-------|------|
| `Clone` | 深拷贝 |
| `Copy` | 按位复制 |
| `Debug` | {:?} 格式化 |
| `Display` | {} 格式化 |
| `Default` | 默认值 |
| `PartialEq/Eq` | 相等比较 |
| `PartialOrd/Ord` | 大小比较 |
| `Hash` | 哈希计算 |
| `Drop` | 析构函数 |
| `Send/Sync` | 并发安全 |

### derive 宏

```rust
#[derive(Debug, Clone, PartialEq)]
struct Point {
    x: i32,
    y: i32,
}

fn main() {
    let p1 = Point { x: 1, y: 2 };
    let p2 = p1.clone();
    
    println!("{:?}", p1);           // Debug
    println!("{}", p1 == p2);       // PartialEq
}
```

---

## 实战场景

### Lab 1: 自定义错误类型

```rust
use std::fmt;

#[derive(Debug)]
enum AppError {
    NotFound(String),
    InvalidInput(String),
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppError::NotFound(s) => write!(f, "Not found: {}", s),
            AppError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
            AppError::Internal(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for AppError {}

fn find_user(id: u32) -> Result<String, AppError> {
    if id == 0 {
        Err(AppError::InvalidInput("ID cannot be 0".into()))
    } else if id > 100 {
        Err(AppError::NotFound(format!("User {} not found", id)))
    } else {
        Ok(format!("User {}", id))
    }
}
```

### Lab 2: 泛型数据结构

```rust
struct Stack<T> {
    items: Vec<T>,
}

impl<T> Stack<T> {
    fn new() -> Self {
        Stack { items: Vec::new() }
    }
    
    fn push(&mut self, item: T) {
        self.items.push(item);
    }
    
    fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }
    
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn main() {
    let mut stack: Stack<i32> = Stack::new();
    stack.push(1);
    stack.push(2);
    println!("{:?}", stack.pop());  // Some(2)
}
```

---

## 常见陷阱

### ❌ 陷阱 1: 过度使用 unwrap

```rust
// 危险
let x = some_option.unwrap();

// 安全
let x = some_option.unwrap_or_default();
// 或
if let Some(x) = some_option { ... }
```

### ❌ 陷阱 2: 忽略 Result

```rust
// 警告：未使用的 Result
let _ = File::create("file.txt");  // 显式忽略

// 更好
File::create("file.txt")?;
```

### ❌ 陷阱 3: Trait 对象大小

```rust
// 错误：Trait 对象大小未知
fn foo() -> dyn Summary { ... }

// 正确：使用 Box
fn foo() -> Box<dyn Summary> { ... }
```

---

## 深入阅读

**推荐资源：**
- [Rust Book - Enums](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [Rust Book - Traits](https://doc.rust-lang.org/book/ch10-02-traits.html)

**相关章节：**
- [03 - 错误处理](./03-error.md) - 深入 Result 模式
- [04 - 并发](./04-concurrency.md) - Send/Sync Trait

---

## 下一步

[03 - 错误处理](./03-error.md) - Rust 的错误处理最佳实践
