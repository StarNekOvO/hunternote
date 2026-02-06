# 00 - 基础语法

Rust 核心语法快速入门，强调所有权思想。


## 概念速览

**Rust 是什么？**
2010 年 Mozilla 发起，注重安全、并发、性能的系统编程语言。

**为什么学 Rust？**
- Android 逐步采用 Rust (Keystore2, Binder, Bluetooth)
- 无 GC 的内存安全
- 编译时防止大部分内存漏洞
- 现代化工具链

**与 C 的核心区别：**

| 特性 | C | Rust |
|------|---|------|
| 内存安全 | 手动，易出错 | 编译器保证 |
| 空指针 | 有 | 无（Option） |
| 数据竞争 | 可能 | 编译时防止 |
| 包管理 | 无内置 | Cargo |


## 核心概念

### 所有权 (Ownership)

**Rust 最核心的概念：**

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1;  // 所有权转移 (move)
    
    // println!("{}", s1);  // 编译错误！s1 已失效
    println!("{}", s2);  // OK
}
```

**三条规则：**
1. 每个值有一个所有者 (owner)
2. 同一时刻只有一个所有者
3. 所有者离开作用域，值被丢弃

### 借用 (Borrowing)

```rust
fn main() {
    let s = String::from("hello");
    
    let len = calculate_length(&s);  // 借用，不转移所有权
    
    println!("'{}' has length {}", s, len);  // s 仍有效
}

fn calculate_length(s: &String) -> usize {
    s.len()
}
```

**借用规则：**
- 任意数量的不可变借用 `&T`
- **或者**一个可变借用 `&mut T`
- 借用必须有效（生命周期）

```rust
let mut s = String::from("hello");

let r1 = &s;      // OK
let r2 = &s;      // OK
// let r3 = &mut s;  // 错误！已有不可变借用

let r4 = &mut s;  // OK，r1 和 r2 不再使用
r4.push_str(" world");
```

### 生命周期 (Lifetimes)

```rust
// 显式生命周期注解
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

fn main() {
    let s1 = String::from("long string");
    let result;
    {
        let s2 = String::from("short");
        result = longest(&s1, &s2);
        println!("{}", result);  // OK，s2 仍有效
    }
    // println!("{}", result);  // 错误！s2 已失效
}
```


## 基础用法

### 变量与可变性

```rust
// 默认不可变
let x = 5;
// x = 6;  // 编译错误！

// 可变变量
let mut y = 5;
y = 6;  // OK

// 常量
const MAX_POINTS: u32 = 100_000;

// 遮蔽 (shadowing)
let x = 5;
let x = x + 1;  // 新变量，不是修改
let x = "hello";  // 可以改变类型
```

### 数据类型

```rust
// 整数
let i: i32 = -42;     // 有符号 32 位
let u: u64 = 1000;    // 无符号 64 位
let byte: u8 = 0xff;

// 浮点
let f: f64 = 3.14;

// 布尔
let b: bool = true;

// 字符 (Unicode)
let c: char = '中';

// 元组
let tup: (i32, f64, char) = (500, 6.4, 'a');
let (x, y, z) = tup;  // 解构
let first = tup.0;    // 索引访问

// 数组 (固定长度)
let arr: [i32; 5] = [1, 2, 3, 4, 5];
let first = arr[0];
let same = [3; 5];  // [3, 3, 3, 3, 3]
```

### 函数

```rust
fn main() {
    let result = add(5, 3);
    println!("Result: {}", result);
}

fn add(a: i32, b: i32) -> i32 {
    a + b  // 表达式，无分号 = 返回值
}

// 无返回值
fn print_hello() {
    println!("Hello");
}

// 显式返回
fn early_return(x: i32) -> i32 {
    if x < 0 {
        return 0;
    }
    x * 2
}
```

### 控制流

```rust
// if 是表达式
let x = 5;
let result = if x > 0 { "positive" } else { "non-positive" };

// loop
let mut count = 0;
let result = loop {
    count += 1;
    if count == 10 {
        break count * 2;  // 返回值
    }
};

// while
while count > 0 {
    count -= 1;
}

// for (推荐)
for i in 0..5 {
    println!("{}", i);  // 0, 1, 2, 3, 4
}

for i in (0..5).rev() {
    println!("{}", i);  // 4, 3, 2, 1, 0
}

let arr = [10, 20, 30];
for element in arr.iter() {
    println!("{}", element);
}
```


## 进阶用法

### 模式匹配

```rust
let x = 5;

match x {
    1 => println!("one"),
    2 | 3 => println!("two or three"),
    4..=6 => println!("four to six"),
    _ => println!("other"),
}

// 解构
let point = (3, 5);
match point {
    (0, _) => println!("on y axis"),
    (_, 0) => println!("on x axis"),
    (x, y) => println!("at ({}, {})", x, y),
}

// if let (简化 match)
let some_value = Some(3);
if let Some(x) = some_value {
    println!("Got {}", x);
}
```

### 结构体

```rust
struct User {
    username: String,
    email: String,
    active: bool,
}

impl User {
    // 关联函数 (类似静态方法)
    fn new(username: String, email: String) -> User {
        User {
            username,
            email,
            active: true,
        }
    }
    
    // 方法
    fn is_active(&self) -> bool {
        self.active
    }
    
    fn deactivate(&mut self) {
        self.active = false;
    }
}

fn main() {
    let mut user = User::new(
        String::from("alice"),
        String::from("alice@example.com"),
    );
    
    println!("Active: {}", user.is_active());
    user.deactivate();
}
```

### 枚举

```rust
enum Message {
    Quit,
    Move { x: i32, y: i32 },
    Write(String),
    ChangeColor(u8, u8, u8),
}

impl Message {
    fn process(&self) {
        match self {
            Message::Quit => println!("Quit"),
            Message::Move { x, y } => println!("Move to ({}, {})", x, y),
            Message::Write(s) => println!("Write: {}", s),
            Message::ChangeColor(r, g, b) => println!("Color: {}, {}, {}", r, g, b),
        }
    }
}
```


## 实战场景

### Lab 1: Hello World

```rust
fn main() {
    println!("Hello, Rust!");
}
```

```bash
rustc hello.rs
./hello

# 或使用 Cargo
cargo new hello
cd hello
cargo run
```

### Lab 2: 命令行参数

```rust
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <name>", args[0]);
        return;
    }
    
    println!("Hello, {}!", args[1]);
}
```

### Lab 3: 文件读写

```rust
use std::fs;
use std::io::{self, Write};

fn main() -> io::Result<()> {
    // 读取
    let content = fs::read_to_string("input.txt")?;
    println!("{}", content);
    
    // 写入
    let mut file = fs::File::create("output.txt")?;
    file.write_all(b"Hello from Rust")?;
    
    Ok(())
}
```


## 常见陷阱

### ❌ 陷阱 1: 所有权转移

```rust
fn main() {
    let s = String::from("hello");
    takes_ownership(s);
    // println!("{}", s);  // 编译错误！
}

fn takes_ownership(s: String) {
    println!("{}", s);
}

// 解决：借用
fn main() {
    let s = String::from("hello");
    borrows(&s);
    println!("{}", s);  // OK
}

fn borrows(s: &String) {
    println!("{}", s);
}
```

### ❌ 陷阱 2: 悬垂引用

```rust
// 编译错误：返回悬垂引用
fn dangle() -> &String {
    let s = String::from("hello");
    &s  // s 离开作用域被丢弃，引用无效
}

// 正确：返回所有权
fn no_dangle() -> String {
    let s = String::from("hello");
    s
}
```

### ❌ 陷阱 3: 借用冲突

```rust
let mut v = vec![1, 2, 3];

// 错误
let first = &v[0];
v.push(4);  // 可变借用
println!("{}", first);  // 使用不可变借用

// 正确
v.push(4);
let first = &v[0];
println!("{}", first);
```


## 深入阅读

**推荐资源：**
- [The Rust Book](https://doc.rust-lang.org/book/) - 官方教程
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)

**相关章节：**
- [01 - 所有权深入](./01-ownership.md) - 详细理解所有权
- [02 - 类型系统](./02-types.md) - enum, Option, Result


## 下一步

[01 - 所有权深入](./01-ownership.md) - 深入理解 Rust 核心
