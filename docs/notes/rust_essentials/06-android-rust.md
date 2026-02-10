# 06 - AOSP Rust

Android 系统中的 Rust：Keystore2、Binder、系统组件。


## 概念速览

**Android 为什么引入 Rust？**
- 70% 内存安全漏洞来自 C/C++
- Rust 提供编译时内存安全
- 渐进式迁移，与 C/C++ 互操作

**Rust 在 AOSP 中的位置：**

| 年份 | Android 版本 | Rust 支持 |
|------|-------------|----------|
| 2021 | Android 12 | 引入支持 |
| 2022 | Android 13 | Keystore2, UWB |
| 2023 | Android 14 | 更多组件 |
| 2024 | Android 15 | 持续扩展 |


## AOSP Rust 构建

### Android.bp 基础

```blueprint
rust_library {
    name: "libmy_library",
    crate_name: "my_library",
    srcs: ["src/lib.rs"],
    edition: "2021",
    
    // 依赖
    rustlibs: [
        "libbinder_rs",
        "liblog_rust",
    ],
    
    // 共享库依赖
    shared_libs: [
        "libc",
    ],
}

rust_binary {
    name: "my_binary",
    srcs: ["src/main.rs"],
    rustlibs: ["libmy_library"],
}
```

### 常用库

| 库名 | 功能 |
|------|------|
| `libbinder_rs` | Binder Rust 绑定 |
| `liblog_rust` | Android 日志 |
| `libnix` | Unix 系统调用 |
| `libserde` | 序列化 |
| `libtokio` | 异步运行时 |


## Keystore2

### 架构概览

```
App (Java)
    ↓ Binder
android.security.keystore2 (Rust service)
    ↓
Hardware Keymaster/KeyMint (HAL)
```

### 核心结构

```rust
// 简化的 Keystore2 架构
pub struct KeystoreService {
    db: Arc<Mutex<KeystoreDB>>,
    sec_level: SecurityLevel,
}

impl IKeystoreService for KeystoreService {
    fn createOperation(
        &self,
        key: &KeyDescriptor,
        params: &[KeyParameter],
    ) -> Result<CreateOperationResponse, Error> {
        // 验证权限
        self.check_permission()?;
        
        // 获取密钥
        let key_entry = self.db.lock().unwrap()
            .get_key_entry(key)?;
        
        // 创建操作
        self.create_operation_impl(key_entry, params)
    }
}
```

### 为什么用 Rust？

**Keystore 处理敏感数据：**
- 密钥材料
- 加密操作
- 权限检查

**Rust 保证：**
- 无缓冲区溢出
- 无 UAF
- 正确的并发处理


## Binder Rust

### 服务端实现

```rust
use binder::{Interface, Result, Strong};

// 定义接口
binder_interface! {
    IHelloWorld["android.example.IHelloWorld"] {
        fn sayHello(&self, name: &str) -> Result<String>;
        fn add(&self, a: i32, b: i32) -> Result<i32>;
    }
}

// 实现服务
struct HelloWorldService;

impl Interface for HelloWorldService {}

impl IHelloWorld for HelloWorldService {
    fn sayHello(&self, name: &str) -> Result<String> {
        Ok(format!("Hello, {}!", name))
    }
    
    fn add(&self, a: i32, b: i32) -> Result<i32> {
        Ok(a + b)
    }
}

// 注册服务
fn main() {
    let service = HelloWorldService;
    let binder = BnHelloWorld::new_binder(service);
    binder::add_service("hello", binder.as_binder())
        .expect("Failed to register service");
    binder::ProcessState::join_thread_pool();
}
```

### 客户端调用

```rust
fn main() {
    let service: Strong<dyn IHelloWorld> = 
        binder::get_interface("hello")
            .expect("Failed to get service");
    
    let greeting = service.sayHello("World").unwrap();
    println!("{}", greeting);
    
    let sum = service.add(3, 4).unwrap();
    println!("3 + 4 = {}", sum);
}
```


## 日志与调试

### Android 日志

```rust
use log::{info, warn, error, debug};

fn main() {
    // 初始化 Android 日志
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(log::Level::Debug)
            .with_tag("MyService"),
    );
    
    info!("Service started");
    debug!("Debug info: {:?}", some_data);
    warn!("Warning: {}", warning_message);
    error!("Error occurred: {}", error);
}
```

### 查看日志

```bash
adb logcat -s MyService
```


## 实战场景

### Lab 1: 简单系统服务

```rust
// 定义接口 (AIDL 转换后)
binder_interface! {
    ICounter["android.example.ICounter"] {
        fn get(&self) -> Result<i32>;
        fn increment(&self) -> Result<()>;
    }
}

// 实现
use std::sync::atomic::{AtomicI32, Ordering};

struct CounterService {
    count: AtomicI32,
}

impl ICounter for CounterService {
    fn get(&self) -> Result<i32> {
        Ok(self.count.load(Ordering::SeqCst))
    }
    
    fn increment(&self) -> Result<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
```

### Lab 2: 与 C++ 互操作

```rust
// Rust 侧
#[cxx::bridge(namespace = "android")]
mod ffi {
    extern "Rust" {
        fn rust_process(data: &[u8]) -> Vec<u8>;
    }
    
    unsafe extern "C++" {
        include!("legacy.h");
        fn cpp_legacy_function(data: *const u8, len: usize) -> bool;
    }
}

pub fn rust_process(data: &[u8]) -> Vec<u8> {
    // 安全处理
    data.iter().map(|b| b.wrapping_add(1)).collect()
}
```

### Lab 3: [CVE-2025-68260](../../cves/entries/CVE-2025-68260.md) 分析

**AOSP Rust 组件的漏洞模式：**

```rust
// 简化示例：不安全的边界检查
fn process_message(data: &[u8]) -> Result<Message, Error> {
    // 漏洞：未验证长度
    let len = data[0] as usize;
    
    // 如果 len > data.len()，切片会 panic
    // 但这不是内存安全问题
    let payload = &data[1..1+len];
    
    // 真正的问题可能在 unsafe 块中
    unsafe {
        process_unsafe(payload.as_ptr(), payload.len())
    }
}
```

> [!NOTE]
> Rust 的内存安全仍可能被 unsafe 代码绕过，或存在逻辑漏洞。


## 与 C/C++ 集成

### CXX 桥接

```rust
// build.rs
fn main() {
    cxx_build::bridge("src/ffi.rs")
        .file("src/legacy.cc")
        .compile("mylib");
}
```

```rust
// src/ffi.rs
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib/include/legacy.h");
        
        type LegacyObject;
        
        fn create_legacy_object() -> UniquePtr<LegacyObject>;
        fn legacy_process(obj: &LegacyObject, data: &[u8]) -> bool;
    }
    
    extern "Rust" {
        fn rust_callback(result: i32);
    }
}
```

### bindgen (C 头文件自动绑定)

```rust
// build.rs
fn main() {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate()
        .expect("Failed to generate bindings");
    
    bindings
        .write_to_file("src/bindings.rs")
        .expect("Failed to write bindings");
}
```


## 常见陷阱

### ❌ 陷阱 1: Binder 线程安全

```rust
// Binder 服务可能被多线程调用
// 状态必须线程安全

// 错误
struct Service {
    data: RefCell<Data>,  // RefCell 不是 Sync
}

// 正确
struct Service {
    data: Mutex<Data>,
}
```

### ❌ 陷阱 2: FFI 内存管理

```rust
// C++ 分配的内存，Rust 不能 drop
extern "C" {
    fn cpp_create() -> *mut Data;
    fn cpp_destroy(data: *mut Data);
}

// 使用智能指针封装
struct CppData(*mut Data);

impl Drop for CppData {
    fn drop(&mut self) {
        unsafe { cpp_destroy(self.0); }
    }
}
```

### ❌ 陷阱 3: AIDL 类型映射

```rust
// AIDL String 是可空的
// Rust 侧使用 Option<String>
fn process(input: Option<String>) -> Result<String> {
    let input = input.ok_or(Error::NullInput)?;
    Ok(input.to_uppercase())
}
```


## 深入阅读

**推荐资源：**
- [Android Rust Guide](https://source.android.com/docs/setup/build/rust/building-rust-modules/overview)
- [CXX Documentation](https://cxx.rs/)
- [Keystore2 Source](https://cs.android.com/android/platform/superproject/+/master:system/security/keystore2/)

**相关章节：**
- [05 - Unsafe Rust](./05-unsafe.md) - FFI 基础
- [07 - Magisk Rust](./07-magisk-rust.md) - 工具中的 Rust


## 下一步

[07 - Magisk Rust](./07-magisk-rust.md) - Root 工具的 Rust 组件
