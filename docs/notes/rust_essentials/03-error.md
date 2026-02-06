# 03 - 错误处理

Rust 错误处理的最佳实践。

---

## 概念速览

**Rust 错误处理哲学：**
- 无异常，使用 Result 类型
- 可恢复错误：`Result<T, E>`
- 不可恢复错误：`panic!`

**与其他语言对比：**

| 语言 | 方式 | 特点 |
|------|------|------|
| C | 返回码 | 容易忽略 |
| Java | try/catch | 运行时开销 |
| Go | (value, error) | 冗长 |
| Rust | Result + ? | 编译时检查，简洁 |

---

## panic!

### 何时使用

```rust
fn main() {
    // 显式 panic
    panic!("Crash and burn!");
    
    // 数组越界
    let v = vec![1, 2, 3];
    v[99];  // panic: index out of bounds
    
    // unwrap 失败
    let x: Option<i32> = None;
    x.unwrap();  // panic: called `unwrap()` on a `None` value
}
```

### 适用场景

- 程序不可恢复的错误状态
- 测试中断言失败
- 快速原型（不想处理错误）

### 栈回溯

```bash
# 显示完整回溯
RUST_BACKTRACE=1 cargo run

# 完整回溯
RUST_BACKTRACE=full cargo run
```

---

## Result 深入

### 基本模式

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_file(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn main() {
    match read_file("hello.txt") {
        Ok(content) => println!("{}", content),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

### ? 操作符详解

```rust
// ? 做了什么？
fn read_file(path: &str) -> Result<String, io::Error> {
    let file = File::open(path)?;
    // 等同于
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(e.into()),  // 注意：自动转换
    };
    // ...
}
```

### 错误类型转换

```rust
use std::num::ParseIntError;

fn parse_and_double(s: &str) -> Result<i32, ParseIntError> {
    let n: i32 = s.parse()?;
    Ok(n * 2)
}

// 多种错误类型
fn complex_operation() -> Result<(), Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string("config.txt")?;
    let value: i32 = file_content.trim().parse()?;
    println!("Value: {}", value);
    Ok(())
}
```

---

## 自定义错误

### 定义错误类型

```rust
use std::fmt;
use std::error::Error;

#[derive(Debug)]
enum AppError {
    IoError(std::io::Error),
    ParseError(std::num::ParseIntError),
    Custom(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppError::IoError(e) => write!(f, "IO error: {}", e),
            AppError::ParseError(e) => write!(f, "Parse error: {}", e),
            AppError::Custom(s) => write!(f, "Error: {}", s),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AppError::IoError(e) => Some(e),
            AppError::ParseError(e) => Some(e),
            AppError::Custom(_) => None,
        }
    }
}

// From trait 实现自动转换
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::IoError(e)
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(e: std::num::ParseIntError) -> Self {
        AppError::ParseError(e)
    }
}
```

### 使用 thiserror crate

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),
    
    #[error("Custom error: {0}")]
    Custom(String),
}

fn process() -> Result<(), AppError> {
    let content = std::fs::read_to_string("file.txt")?;  // 自动转换
    let value: i32 = content.trim().parse()?;            // 自动转换
    Ok(())
}
```

### 使用 anyhow crate

```rust
use anyhow::{Result, Context, bail};

fn process(path: &str) -> Result<i32> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read {}", path))?;
    
    let value: i32 = content.trim().parse()
        .context("Failed to parse number")?;
    
    if value < 0 {
        bail!("Value cannot be negative");  // 快速返回错误
    }
    
    Ok(value)
}

fn main() {
    if let Err(e) = process("config.txt") {
        eprintln!("Error: {:?}", e);  // 显示完整错误链
    }
}
```

---

## 错误处理模式

### 忽略错误

```rust
// 显式忽略
let _ = do_something();

// 使用 ok() 转换为 Option
let result = do_something().ok();
```

### 传播错误

```rust
fn foo() -> Result<(), Error> {
    bar()?;  // 短路返回
    baz()?;
    Ok(())
}
```

### 处理多个 Result

```rust
fn process_all(items: Vec<&str>) -> Vec<Result<i32, ParseIntError>> {
    items.iter().map(|s| s.parse()).collect()
}

fn process_all_or_fail(items: Vec<&str>) -> Result<Vec<i32>, ParseIntError> {
    items.iter().map(|s| s.parse()).collect()  // collect 处理 Result
}
```

### 组合多个 Result

```rust
fn combined() -> Result<i32, Error> {
    let a = get_a()?;
    let b = get_b()?;
    let c = get_c()?;
    Ok(a + b + c)
}

// 并行处理（不短路）
use itertools::Itertools;

fn try_all() -> Vec<Result<i32, Error>> {
    vec![get_a(), get_b(), get_c()]
}
```

---

## 实战场景

### Lab 1: 配置文件解析

```rust
use serde::Deserialize;
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
enum ConfigError {
    #[error("Failed to read config: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
}

#[derive(Deserialize)]
struct Config {
    host: String,
    port: u16,
}

fn load_config(path: &str) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    
    if config.host.is_empty() {
        return Err(ConfigError::MissingField("host".to_string()));
    }
    
    Ok(config)
}
```

### Lab 2: 重试逻辑

```rust
use std::thread;
use std::time::Duration;

fn retry<T, E, F>(mut f: F, attempts: u32, delay: Duration) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    for i in 0..attempts {
        match f() {
            Ok(value) => return Ok(value),
            Err(e) if i == attempts - 1 => return Err(e),
            Err(_) => {
                thread::sleep(delay);
            }
        }
    }
    unreachable!()
}

fn main() {
    let result = retry(
        || network_request(),
        3,
        Duration::from_secs(1),
    );
}
```

### Lab 3: 错误链追踪

```rust
use anyhow::{Context, Result};

fn read_config() -> Result<Config> {
    let path = get_config_path()
        .context("Failed to get config path")?;
    
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    
    let config: Config = toml::from_str(&content)
        .context("Failed to parse config file")?;
    
    Ok(config)
}

fn main() {
    if let Err(e) = read_config() {
        // 打印完整错误链
        eprintln!("Error: {:#}", e);
        
        // 遍历错误链
        for (i, cause) in e.chain().enumerate() {
            eprintln!("  {}: {}", i, cause);
        }
    }
}
```

---

## 常见陷阱

### ❌ 陷阱 1: 过度使用 unwrap

```rust
// 不好
let file = File::open("file.txt").unwrap();

// 好：提供上下文
let file = File::open("file.txt").expect("Failed to open file.txt");

// 更好：传播错误
let file = File::open("file.txt")?;
```

### ❌ 陷阱 2: 忽略错误

```rust
// 危险
let _ = write_to_file(data);

// 至少记录日志
if let Err(e) = write_to_file(data) {
    eprintln!("Warning: failed to write: {}", e);
}
```

### ❌ 陷阱 3: 错误类型过于宽泛

```rust
// 不好：丢失具体错误信息
fn process() -> Result<(), Box<dyn Error>> { ... }

// 好：使用具体错误类型
fn process() -> Result<(), AppError> { ... }

// 或者使用 anyhow 保留上下文
fn process() -> anyhow::Result<()> { ... }
```

---

## 深入阅读

**推荐资源：**
- [Rust Book - Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- [anyhow crate](https://docs.rs/anyhow)
- [thiserror crate](https://docs.rs/thiserror)

**相关章节：**
- [02 - 类型系统](./02-types.md) - Result 和 Option
- [04 - 并发](./04-concurrency.md) - 并发中的错误处理

---

## 下一步

[04 - 并发](./04-concurrency.md) - Rust 的无畏并发
