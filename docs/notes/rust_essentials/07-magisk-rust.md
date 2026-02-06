# 07 - Magisk Rust

Magisk 的 Rust 组件分析：magiskpolicy、magiskboot。


## 概念速览

**Magisk 为什么迁移到 Rust？**
- 处理不可信输入（boot.img、sepolicy）
- 减少内存安全漏洞
- 现代化代码库

**Rust 组件概览：**

| 组件 | 功能 | 之前 |
|------|------|------|
| magiskboot | boot.img 解析/打包 | C++ |
| magiskpolicy | SEPolicy 处理 | C++ |
| busybox | 工具集 | C |
| magiskinit | 启动注入 | C/C++ |


## magiskboot

### 功能

- 解析各种 boot.img 格式
- 提取/替换 kernel、ramdisk
- 处理压缩和签名

### 架构分析

```rust
// 简化的 boot.img 解析
pub struct BootImage {
    pub header: BootHeader,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second: Option<Vec<u8>>,
    pub dtb: Option<Vec<u8>>,
}

impl BootImage {
    pub fn parse(data: &[u8]) -> Result<Self> {
        // 验证魔数
        let magic = &data[0..8];
        if magic != b"ANDROID!" {
            return Err(Error::InvalidMagic);
        }
        
        // 解析头部
        let header = BootHeader::parse(&data[0..1024])?;
        
        // 提取各段
        let kernel = extract_segment(data, header.kernel_offset, header.kernel_size)?;
        let ramdisk = extract_segment(data, header.ramdisk_offset, header.ramdisk_size)?;
        
        Ok(BootImage {
            header,
            kernel,
            ramdisk,
            second: None,
            dtb: None,
        })
    }
}
```

### 安全优势

```rust
// Rust 版本：边界自动检查
fn extract_segment(data: &[u8], offset: usize, size: usize) -> Result<Vec<u8>> {
    if offset + size > data.len() {
        return Err(Error::OutOfBounds);
    }
    Ok(data[offset..offset + size].to_vec())
}

// C++ 版本需要手动检查，容易遗漏
```


## magiskpolicy

### SELinux 策略操作

```rust
// 策略规则表示
pub enum PolicyStatement {
    Allow {
        source: String,
        target: String,
        class: String,
        permissions: Vec<String>,
    },
    TypeAttr {
        type_name: String,
        attribute: String,
    },
    // ... 更多规则类型
}

impl PolicyStatement {
    pub fn parse(line: &str) -> Result<Self> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        
        match tokens.first() {
            Some(&"allow") => parse_allow_rule(&tokens),
            Some(&"typeattribute") => parse_type_attr(&tokens),
            _ => Err(Error::UnknownStatement),
        }
    }
}
```

### 策略注入

```rust
pub struct PolicyPatcher {
    policy: SepolicyFile,
}

impl PolicyPatcher {
    pub fn add_rule(&mut self, stmt: PolicyStatement) -> Result<()> {
        match stmt {
            PolicyStatement::Allow { source, target, class, permissions } => {
                let source_type = self.policy.find_or_create_type(&source)?;
                let target_type = self.policy.find_or_create_type(&target)?;
                
                for perm in permissions {
                    self.policy.add_allow(source_type, target_type, &class, &perm)?;
                }
            }
            // ... 其他语句
        }
        Ok(())
    }
    
    pub fn apply_magisk_rules(&mut self) -> Result<()> {
        // Magisk 需要的权限
        let rules = vec![
            "allow magisk * * *",
            "allow su * * *",
            // ...
        ];
        
        for rule in rules {
            let stmt = PolicyStatement::parse(rule)?;
            self.add_rule(stmt)?;
        }
        
        Ok(())
    }
}
```


## C++/Rust 互操作

### CXX Bridge 实践

```rust
// src/ffi.rs
#[cxx::bridge(namespace = "magisk")]
mod ffi {
    // Rust 结构体暴露给 C++
    struct RustConfig {
        debug: bool,
        root_mount: String,
    }
    
    // Rust 函数暴露给 C++
    extern "Rust" {
        fn parse_boot_image(data: &[u8]) -> Result<BootParseResult>;
        fn patch_sepolicy(policy: &[u8], rules: &str) -> Result<Vec<u8>>;
    }
    
    // C++ 函数供 Rust 调用
    unsafe extern "C++" {
        include!("magisk_core.hpp");
        
        type MagiskCore;
        
        fn get_magisk_core() -> *mut MagiskCore;
        fn core_mount_sbin(core: *mut MagiskCore) -> bool;
    }
}
```

### 内存安全边界

```rust
// 从 C++ 接收的数据需要谨慎处理
pub fn process_cpp_buffer(ptr: *const u8, len: usize) -> Result<Vec<u8>> {
    if ptr.is_null() {
        return Err(Error::NullPointer);
    }
    
    // 创建安全的切片
    let slice = unsafe {
        // 这里假设 C++ 提供了有效的指针和长度
        // 这是一个信任边界
        std::slice::from_raw_parts(ptr, len)
    };
    
    // 后续操作是完全安全的
    let processed = slice.iter()
        .map(|b| b.wrapping_add(1))
        .collect();
    
    Ok(processed)
}
```


## 实战场景

### Lab 1: Boot Image 解析

```rust
use std::fs;

fn main() -> Result<()> {
    let data = fs::read("boot.img")?;
    
    let boot = BootImage::parse(&data)?;
    
    println!("Kernel size: {} bytes", boot.kernel.len());
    println!("Ramdisk size: {} bytes", boot.ramdisk.len());
    
    // 提取 ramdisk
    fs::write("ramdisk.cpio", &boot.ramdisk)?;
    
    Ok(())
}
```

### Lab 2: SEPolicy 规则处理

```rust
fn main() -> Result<()> {
    let policy_data = fs::read("sepolicy")?;
    let mut patcher = PolicyPatcher::new(&policy_data)?;
    
    // 添加自定义规则
    patcher.add_rule(PolicyStatement::Allow {
        source: "untrusted_app".to_string(),
        target: "my_file_type".to_string(),
        class: "file".to_string(),
        permissions: vec!["read".to_string(), "open".to_string()],
    })?;
    
    let patched = patcher.build()?;
    fs::write("sepolicy.patched", patched)?;
    
    Ok(())
}
```

### Lab 3: 模块配置解析

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct ModuleConfig {
    id: String,
    name: String,
    version: String,
    version_code: u32,
    author: String,
    description: String,
}

fn parse_module_prop(content: &str) -> Result<ModuleConfig> {
    let mut props = HashMap::new();
    
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            props.insert(key.trim(), value.trim());
        }
    }
    
    Ok(ModuleConfig {
        id: props.get("id").unwrap_or(&"").to_string(),
        name: props.get("name").unwrap_or(&"").to_string(),
        version: props.get("version").unwrap_or(&"").to_string(),
        version_code: props.get("versionCode")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        author: props.get("author").unwrap_or(&"").to_string(),
        description: props.get("description").unwrap_or(&"").to_string(),
    })
}
```


## 安全考量

### 处理不可信输入

```rust
// boot.img 来自用户，可能是恶意的
pub fn safe_parse(data: &[u8]) -> Result<BootImage> {
    // 1. 验证基本大小
    if data.len() < MIN_HEADER_SIZE {
        return Err(Error::TooSmall);
    }
    
    // 2. 验证魔数
    if &data[0..8] != b"ANDROID!" {
        return Err(Error::InvalidMagic);
    }
    
    // 3. 解析时检查所有偏移
    let header = parse_header_safely(data)?;
    
    // 4. 确保段不重叠
    validate_segments(&header)?;
    
    // 5. Rust 的切片自动边界检查
    let kernel = data.get(header.kernel_range())
        .ok_or(Error::InvalidOffset)?
        .to_vec();
    
    Ok(BootImage { header, kernel, /* ... */ })
}
```

### 与 C++ 混合时的注意事项

```rust
// C++ 分配的内存，Rust 不能 free
extern "C" {
    fn cpp_parse_image(data: *const u8, len: usize) -> *mut ImageData;
    fn cpp_free_image(image: *mut ImageData);
}

// RAII 封装
struct CppImage(*mut ImageData);

impl CppImage {
    fn from_raw(data: &[u8]) -> Option<Self> {
        let ptr = unsafe { cpp_parse_image(data.as_ptr(), data.len()) };
        if ptr.is_null() {
            None
        } else {
            Some(CppImage(ptr))
        }
    }
}

impl Drop for CppImage {
    fn drop(&mut self) {
        unsafe { cpp_free_image(self.0); }
    }
}
```


## 常见陷阱

### ❌ 陷阱 1: 版本兼容性

```rust
// Boot image 格式随 Android 版本变化
fn parse_header(data: &[u8]) -> Result<Header> {
    let version = u32::from_le_bytes(data[0..4].try_into()?);
    
    match version {
        0 | 1 | 2 => parse_v0_header(data),
        3 => parse_v3_header(data),
        4 => parse_v4_header(data),
        _ => Err(Error::UnsupportedVersion(version)),
    }
}
```

### ❌ 陷阱 2: 压缩格式检测

```rust
fn detect_compression(data: &[u8]) -> Compression {
    match &data[0..2] {
        [0x1f, 0x8b] => Compression::Gzip,
        [0x5d, 0x00] => Compression::Lzma,
        [0x28, 0xb5] => Compression::Zstd,
        [0x04, 0x22] => Compression::Lz4Legacy,
        _ => Compression::None,
    }
}
```

### ❌ 陷阱 3: SEPolicy 二进制格式

```rust
// sepolicy 是二进制格式，需要正确解析
// 不同 Android 版本格式可能不同
fn parse_policy_version(data: &[u8]) -> Result<u32> {
    // 魔数位置和格式需要精确
    if data.len() < 8 {
        return Err(Error::TooSmall);
    }
    // ...
}
```


## 深入阅读

**推荐资源：**
- [Magisk GitHub](https://github.com/topjohnwu/Magisk)
- [Magisk 文档](https://topjohnwu.github.io/Magisk/)

**相关章节：**
- [05 - Unsafe Rust](./05-unsafe.md) - FFI 和 unsafe
- [C 07 - KernelSU/Magisk](../c_essentials/07-ksu-magisk-native) - 内核层实现


## 系列总结

Rust Essentials 完成！你现在应该能够：

- ✅ 理解所有权和借用
- ✅ 使用 Option/Result 处理错误
- ✅ 编写并发安全的代码
- ✅ 理解和审计 unsafe 代码
- ✅ 分析 Android/Magisk 中的 Rust 组件


## 下一步

继续学习：
- [C Essentials](../c_essentials/) - 内核开发
- [Java Essentials](../java_essentials/) - Framework 分析
- [Android Security Notes](../android/) - 深入安全研究
