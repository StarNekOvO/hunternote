# 05 - Unsafe Rust

突破安全边界：裸指针、FFI、内联汇编。


## 概念速览

**为什么需要 unsafe？**
- 与 C/C++ 代码互操作 (FFI)
- 实现底层抽象 (如标准库中的数据结构)
- 性能关键路径

**unsafe 能做什么？**
1. 解引用裸指针
2. 调用 unsafe 函数
3. 访问可变静态变量
4. 实现 unsafe trait
5. 访问 union 字段


## 裸指针

### 创建裸指针

```rust
fn main() {
    let x = 5;
    
    // 从引用创建（安全）
    let r1: *const i32 = &x;
    let r2: *mut i32 = &x as *const i32 as *mut i32;
    
    // 从任意地址创建（危险！）
    let address = 0x012345usize;
    let r3 = address as *const i32;
    
    // 解引用需要 unsafe
    unsafe {
        println!("r1 = {}", *r1);
    }
}
```

### 裸指针 vs 引用

| 特性 | 引用 | 裸指针 |
|------|------|--------|
| 生命周期 | 有 | 无 |
| 空值检查 | 编译器保证 | 无 |
| 悬垂检查 | 编译器保证 | 无 |
| 别名规则 | 强制 | 无 |
| 可以为空 | 否 | 是 |

### 常见操作

```rust
fn main() {
    let mut x = 10;
    let ptr: *mut i32 = &mut x;
    
    unsafe {
        // 读取
        let value = *ptr;
        
        // 写入
        *ptr = 20;
        
        // 偏移
        let ptr2 = ptr.offset(1);  // 危险！可能越界
        
        // 判空
        if !ptr.is_null() {
            println!("{}", *ptr);
        }
    }
}
```


## FFI (Foreign Function Interface)

### 调用 C 函数

```rust
use std::ffi::CString;
use std::os::raw::c_char;

// 声明外部函数
extern "C" {
    fn strlen(s: *const c_char) -> usize;
    fn printf(format: *const c_char, ...) -> i32;
}

fn main() {
    let s = CString::new("Hello, FFI!").unwrap();
    
    unsafe {
        let len = strlen(s.as_ptr());
        println!("Length: {}", len);
        
        printf(CString::new("Value: %d\n").unwrap().as_ptr(), 42);
    }
}
```

### 导出 Rust 函数给 C

```rust
// lib.rs
#[no_mangle]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
pub extern "C" fn rust_greet(name: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(name) };
    let name = c_str.to_str().unwrap_or("Unknown");
    println!("Hello, {}!", name);
}
```

```c
// main.c
extern int rust_add(int a, int b);
extern void rust_greet(const char *name);

int main() {
    printf("Result: %d\n", rust_add(3, 4));
    rust_greet("World");
    return 0;
}
```

### 类型映射

| C 类型 | Rust 类型 |
|--------|----------|
| `int` | `c_int` / `i32` |
| `char` | `c_char` / `i8` |
| `char *` | `*const c_char` |
| `void *` | `*mut c_void` |
| `size_t` | `usize` |
| `struct` | `#[repr(C)] struct` |

### #[repr(C)]

```rust
// 确保与 C 相同的内存布局
#[repr(C)]
struct Point {
    x: f64,
    y: f64,
}

// 对应 C 的:
// struct Point {
//     double x;
//     double y;
// };
```


## Unsafe Trait

### Send 和 Sync

```rust
// 标记 trait (无方法)
unsafe trait MySend {}
unsafe trait MySync {}

struct MyType {
    ptr: *mut i32,
}

// 手动声明线程安全
unsafe impl Send for MyType {}
unsafe impl Sync for MyType {}
```

### 为什么是 unsafe？

```rust
// 错误的声明可能导致数据竞争
struct NotSync {
    data: std::cell::Cell<i32>,
}

// 如果错误地实现 Sync，多线程可能同时修改 Cell
// unsafe impl Sync for NotSync {}  // 危险！
```


## 可变静态变量

```rust
static mut COUNTER: i32 = 0;

fn increment() {
    unsafe {
        COUNTER += 1;
    }
}

fn main() {
    increment();
    increment();
    unsafe {
        println!("COUNTER = {}", COUNTER);
    }
}
```

> [!WARNING]
> 可变静态变量存在数据竞争风险，优先使用 `Mutex<T>` 或原子类型。

```rust
use std::sync::atomic::{AtomicI32, Ordering};

static COUNTER: AtomicI32 = AtomicI32::new(0);

fn increment() {
    COUNTER.fetch_add(1, Ordering::SeqCst);
}
```


## 实战场景

### Lab 1: 实现简单的链表

```rust
type Link<T> = Option<Box<Node<T>>>;

struct Node<T> {
    data: T,
    next: Link<T>,
}

struct List<T> {
    head: Link<T>,
}

impl<T> List<T> {
    fn new() -> Self {
        List { head: None }
    }
    
    fn push(&mut self, data: T) {
        let new_node = Box::new(Node {
            data,
            next: self.head.take(),
        });
        self.head = Some(new_node);
    }
    
    fn pop(&mut self) -> Option<T> {
        self.head.take().map(|node| {
            self.head = node.next;
            node.data
        })
    }
}
```

### Lab 2: FFI 封装

```rust
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// 安全封装不安全的 C 函数
mod ffi {
    use super::*;
    
    extern "C" {
        fn getenv(name: *const c_char) -> *mut c_char;
    }
    
    pub fn get_env(name: &str) -> Option<String> {
        let c_name = CString::new(name).ok()?;
        
        unsafe {
            let result = getenv(c_name.as_ptr());
            if result.is_null() {
                None
            } else {
                Some(CStr::from_ptr(result).to_string_lossy().into_owned())
            }
        }
    }
}

fn main() {
    if let Some(path) = ffi::get_env("PATH") {
        println!("PATH = {}", path);
    }
}
```

### Lab 3: [CVE-2025-48530](../../cves/entries/CVE-2025-48530.md) 分析

**CrabbyAVIF 中的 unsafe 漏洞：**

```rust
// 简化的漏洞模式
unsafe fn decode_image(data: *const u8, len: usize) -> Image {
    // 未验证 len 的有效性
    let slice = std::slice::from_raw_parts(data, len);
    
    // 如果 len 超过实际分配，这里会读取越界数据
    process_pixels(slice)
}
```

> [!CAUTION]
> unsafe 代码中的边界检查省略是常见漏洞来源。


## Unsafe 最佳实践

### 最小化 unsafe 范围

```rust
// 不好
unsafe {
    let ptr = get_pointer();
    do_safe_stuff();
    *ptr = 42;
    do_more_safe_stuff();
}

// 好
let ptr = get_pointer();
do_safe_stuff();
unsafe { *ptr = 42; }
do_more_safe_stuff();
```

### 文档化安全条件

```rust
/// # Safety
///
/// - `ptr` must be valid and properly aligned
/// - `ptr` must point to initialized data
/// - No other references to the data may exist
unsafe fn dangerous_operation(ptr: *mut i32) {
    *ptr = 42;
}
```

### 安全封装

```rust
pub struct SafeWrapper {
    inner: *mut InternalData,
}

impl SafeWrapper {
    pub fn new() -> Self {
        Self {
            inner: unsafe { create_internal_data() },
        }
    }
    
    // 安全的公开接口
    pub fn do_something(&self) -> i32 {
        unsafe { operation(self.inner) }
    }
}

impl Drop for SafeWrapper {
    fn drop(&mut self) {
        unsafe { destroy_internal_data(self.inner) }
    }
}
```


## 常见陷阱

### ❌ 陷阱 1: 悬垂指针

```rust
fn dangling() -> *const i32 {
    let x = 42;
    &x as *const i32  // x 被丢弃，指针悬垂！
}
```

### ❌ 陷阱 2: 未对齐访问

```rust
#[repr(packed)]
struct Packed {
    a: u8,
    b: i32,  // 可能未对齐
}

let p = Packed { a: 1, b: 2 };
let ptr: *const i32 = &p.b;  // 未对齐指针
// unsafe { *ptr }  // 在某些架构上会崩溃
```

### ❌ 陷阱 3: 违反别名规则

```rust
fn bad_aliasing() {
    let mut x = 42;
    let r1 = &x as *const i32;
    let r2 = &mut x as *mut i32;
    
    unsafe {
        // 同时存在可变和不可变访问
        *r2 = 100;
        println!("{}", *r1);  // 未定义行为！
    }
}
```


## 深入阅读

**推荐资源：**
- [Rustonomicon](https://doc.rust-lang.org/nomicon/) - unsafe Rust 权威指南
- [Rust FFI Guide](https://michael-f-bryan.github.io/rust-ffi-guide/)

**相关章节：**
- [06 - AOSP Rust](./06-android-rust.md) - FFI 在 Android 中的应用
- [07 - Magisk Rust](./07-magisk-rust.md) - C++/Rust 互操作


## 下一步

[06 - AOSP Rust](./06-android-rust.md) - Android 中的 Rust
