# 01 - 所有权深入

Rust 的核心创新：所有权系统详解。


## 概念速览

**为什么需要所有权？**
- 编译时内存安全，无运行时开销
- 无 GC，无手动 free
- 防止 UAF、Double-free、数据竞争

**对比其他语言：**

| 语言 | 内存管理 | 安全性 | 性能 |
|------|----------|--------|------|
| C | 手动 | 不安全 | 高 |
| Java | GC | 安全 | 中 |
| Rust | 所有权 | 安全 | 高 |


## 栈与堆

### 存储位置

```rust
fn main() {
    // 栈上：固定大小，编译时已知
    let x: i32 = 42;
    let arr: [i32; 3] = [1, 2, 3];
    
    // 堆上：动态大小
    let s = String::from("hello");  // 数据在堆上，指针在栈上
    let v = vec![1, 2, 3];
}
```

**String 内存布局：**

```
栈上                     堆上
┌─────────────┐         ┌───┬───┬───┬───┬───┐
│ ptr ────────│────────►│ h │ e │ l │ l │ o │
├─────────────┤         └───┴───┴───┴───┴───┘
│ len: 5      │
├─────────────┤
│ capacity: 5 │
└─────────────┘
```

### Copy vs Move

```rust
// Copy 类型：栈上数据，按位复制
let x = 5;
let y = x;
println!("{} {}", x, y);  // OK，都有效

// Move 类型：堆上数据，所有权转移
let s1 = String::from("hello");
let s2 = s1;
// println!("{}", s1);  // 错误！s1 已无效
println!("{}", s2);  // OK
```

**Copy trait 的类型：**
- 所有整数类型 (i32, u64, ...)
- 浮点类型 (f32, f64)
- 布尔类型 (bool)
- 字符类型 (char)
- 仅包含 Copy 类型的元组 ((i32, i32))


## 引用与借用

### 不可变借用

```rust
fn main() {
    let s = String::from("hello");
    
    // 可以有多个不可变借用
    let r1 = &s;
    let r2 = &s;
    
    println!("{} {}", r1, r2);  // OK
}

fn calculate_length(s: &String) -> usize {
    s.len()
    // 函数结束时，借用结束，不会丢弃数据
}
```

### 可变借用

```rust
fn main() {
    let mut s = String::from("hello");
    
    change(&mut s);
    println!("{}", s);  // "hello world"
}

fn change(s: &mut String) {
    s.push_str(" world");
}
```

### 借用规则

```rust
let mut s = String::from("hello");

// 规则 1: 多个不可变借用 OK
let r1 = &s;
let r2 = &s;
println!("{} {}", r1, r2);

// 规则 2: 不可变和可变借用不能共存
let r3 = &s;
// let r4 = &mut s;  // 错误！
// println!("{}", r3);

// 规则 3: 只能有一个可变借用
let r5 = &mut s;
// let r6 = &mut s;  // 错误！
r5.push_str("!");
```

### NLL (Non-Lexical Lifetimes)

```rust
fn main() {
    let mut s = String::from("hello");
    
    let r1 = &s;
    println!("{}", r1);  // r1 最后使用点
    
    // r1 已经不再使用，可以创建可变借用
    let r2 = &mut s;     // OK，因为 NLL
    r2.push_str(" world");
}
```


## 切片

### 字符串切片

```rust
let s = String::from("hello world");

let hello: &str = &s[0..5];   // "hello"
let world: &str = &s[6..11];  // "world"

// 简写
let hello = &s[..5];   // 从开头
let world = &s[6..];   // 到结尾
let whole = &s[..];    // 整个

// 字符串字面量就是切片
let s: &str = "hello";  // &str 类型
```

**切片内存布局：**

```
s (String)                hello (切片)
┌──────────┐              ┌──────────┐
│ ptr ─────│─────┐        │ ptr ─────│────┐
├──────────┤     │        ├──────────┤    │
│ len: 11  │     │        │ len: 5   │    │
├──────────┤     │        └──────────┘    │
│ cap: 11  │     ↓                        ↓
└──────────┘     ┌───┬───┬───┬───┬───┬───┬─────────┐
                 │ h │ e │ l │ l │ o │   │ w o r l d │
                 └───┴───┴───┴───┴───┴───┴─────────┘
                 ↑
```

### 数组切片

```rust
let a = [1, 2, 3, 4, 5];

let slice: &[i32] = &a[1..3];  // [2, 3]
println!("{:?}", slice);
```


## 生命周期

### 为什么需要生命周期？

```rust
// 编译器如何知道返回值的有效期？
fn longest(x: &str, y: &str) -> &str {
    if x.len() > y.len() { x } else { y }
}
// 编译错误！需要生命周期注解
```

### 生命周期注解

```rust
// 'a 是生命周期参数
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

fn main() {
    let s1 = String::from("long string");
    let result;
    {
        let s2 = String::from("short");
        result = longest(&s1, &s2);
        println!("{}", result);  // OK
    }
    // println!("{}", result);  // 错误！s2 已超出作用域
}
```

### 生命周期省略规则

编译器自动推断的情况：

```rust
// 规则 1: 每个引用参数获得独立的生命周期
fn foo(x: &str) -> &str { ... }
// 等同于
fn foo<'a>(x: &'a str) -> &'a str { ... }

// 规则 2: 只有一个输入生命周期，赋给所有输出
fn first_word(s: &str) -> &str { ... }
// 等同于
fn first_word<'a>(s: &'a str) -> &'a str { ... }

// 规则 3: 方法中有 &self，self 的生命周期赋给所有输出
impl<'a> MyStruct<'a> {
    fn method(&self, other: &str) -> &str { ... }
}
```

### 静态生命周期

```rust
// 'static: 整个程序运行期间有效
let s: &'static str = "I have a static lifetime";

// 字符串字面量都是 'static
// 编译到二进制文件中
```


## 实战场景

### Lab 1: 理解 Move 语义

```rust
fn main() {
    let data = vec![1, 2, 3];
    
    // 错误示范
    // let sum = sum_vec(data);
    // println!("{:?}", data);  // 编译错误
    
    // 正确 1: 借用
    let sum = sum_vec_borrow(&data);
    println!("Sum: {}, Data: {:?}", sum, data);
    
    // 正确 2: Clone
    let sum = sum_vec(data.clone());
    println!("Data: {:?}", data);
}

fn sum_vec(v: Vec<i32>) -> i32 {
    v.iter().sum()
}

fn sum_vec_borrow(v: &Vec<i32>) -> i32 {
    v.iter().sum()
}
```

### Lab 2: 结构体中的引用

```rust
// 结构体持有引用需要生命周期注解
struct Excerpt<'a> {
    part: &'a str,
}

fn main() {
    let novel = String::from("Call me Ishmael. Some years ago...");
    let first_sentence = novel.split('.').next().unwrap();
    
    let excerpt = Excerpt {
        part: first_sentence,
    };
    
    println!("Excerpt: {}", excerpt.part);
}
```

### Lab 3: 可变借用实践

```rust
fn main() {
    let mut numbers = vec![1, 2, 3, 4, 5];
    
    // 获取可变借用，修改元素
    double_all(&mut numbers);
    
    println!("{:?}", numbers);  // [2, 4, 6, 8, 10]
}

fn double_all(v: &mut Vec<i32>) {
    for n in v.iter_mut() {
        *n *= 2;
    }
}
```


## 常见陷阱

### ❌ 陷阱 1: 返回局部变量引用

```rust
// 错误
fn dangle() -> &String {
    let s = String::from("hello");
    &s  // s 被丢弃，引用无效
}

// 正确
fn no_dangle() -> String {
    String::from("hello")  // 返回所有权
}
```

### ❌ 陷阱 2: 迭代时修改

```rust
let mut v = vec![1, 2, 3];

// 错误
for i in &v {
    v.push(*i);  // 不可变借用和可变借用冲突
}

// 正确：先收集再添加
let additions: Vec<_> = v.iter().cloned().collect();
v.extend(additions);
```

### ❌ 陷阱 3: 生命周期不匹配

```rust
// 错误：返回可能失效的引用
fn pick<'a>(x: &'a str, y: &str) -> &'a str {
    if x.len() > 0 {
        x
    } else {
        y  // y 的生命周期可能短于 'a
    }
}

// 正确：两者都使用相同生命周期
fn pick<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > 0 { x } else { y }
}
```


## 深入阅读

**推荐资源：**
- [Rust Book - Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [Rustonomicon](https://doc.rust-lang.org/nomicon/) - unsafe Rust

**相关章节：**
- [02 - 类型系统](./02-types.md) - Option, Result
- [05 - Unsafe Rust](./05-unsafe.md) - 绕过所有权检查


## 下一步

[02 - 类型系统](./02-types.md) - Rust 强大的类型系统
