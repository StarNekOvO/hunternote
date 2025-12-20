# 0x02 - Android Build System

Android 构建系统从最初的 GNU Make 演进到 Soong/Blueprint，再到正在过渡的 Bazel。理解构建系统对安全研究至关重要：它决定了模块如何编译、系统镜像如何组装、SELinux 策略如何生成。

## 1. 构建系统演进

| 时期 | 系统 | 特点 |
|------|------|------|
| Android 6 及之前 | GNU Make (`Android.mk`) | 递归 Makefile，灵活但慢 |
| Android 7+ | Soong (`Android.bp`) | 声明式 Blueprint 语法，Ninja 后端 |
| Android 14+ (过渡中) | Bazel | 增量构建、远程缓存、更快的大规模构建 |

目前 AOSP 处于 Soong 为主、Bazel 逐步接管的混合阶段。老项目可能仍有 `Android.mk`，新代码推荐 `Android.bp`。

## 2. 核心构建文件

### Android.mk (Legacy)

传统 Makefile 风格，仍在部分旧模块和 vendor 代码中使用：

```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mylib
LOCAL_SRC_FILES := foo.c bar.c
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_SHARED_LIBRARY)
```

常用变量：
- `LOCAL_MODULE`：模块名
- `LOCAL_SRC_FILES`：源文件列表
- `LOCAL_C_INCLUDES`：头文件路径
- `LOCAL_SHARED_LIBRARIES` / `LOCAL_STATIC_LIBRARIES`：依赖库

### Android.bp (Soong/Blueprint)

声明式语法，更易读、更易并行处理：

```json
cc_library_shared {
    name: "mylib",
    srcs: ["foo.c", "bar.c"],
    shared_libs: ["liblog", "libcutils"],
    cflags: ["-Wall", "-Werror"],
}
```

两者功能等价，但 `Android.bp` 是现代 AOSP 的标准。Soong 在构建时会将 `.bp` 转换为 Ninja 构建规则。

## 3. 常见模块类型

Soong 支持丰富的模块类型，常见的包括：

| 模块类型 | 用途 |
|----------|------|
| `cc_library_shared` | 共享库 (.so) |
| `cc_library_static` | 静态库 (.a) |
| `cc_binary` | Native 可执行文件 |
| `java_library` | Java 库 |
| `android_app` | APK 应用 |
| `prebuilt_etc` | 预编译配置文件 |
| `filegroup` | 文件组，用于跨模块共享源文件 |
| `hidl_interface` / `aidl_interface` | HIDL/AIDL 接口定义 |

查看完整模块类型：`build/soong/androidmk/androidmk/android.go` 或官方文档。

## 4. 构建流程概览

```
┌─────────────────────────────────────────────────────────────┐
│  source build/envsetup.sh                                   │
│      ↓                                                      │
│  lunch <target>           # 选择构建目标                     │
│      ↓                                                      │
│  m / make / mmm / mma     # 触发构建                        │
│      ↓                                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Soong (go)                                          │   │
│  │    ├── 解析 Android.bp                               │   │
│  │    ├── 转换 Android.mk → Android.bp (androidmk)     │   │
│  │    └── 生成 Ninja 构建规则                           │   │
│  └─────────────────────────────────────────────────────┘   │
│      ↓                                                      │
│  Ninja 执行构建                                             │
│      ↓                                                      │
│  out/target/product/<device>/                              │
│      ├── system.img                                        │
│      ├── vendor.img                                        │
│      ├── boot.img                                          │
│      └── ...                                               │
└─────────────────────────────────────────────────────────────┘
```

### 常用构建命令

| 命令 | 作用 |
|------|------|
| `m` | 构建整个系统 |
| `m <module>` | 只构建指定模块 |
| `mm` | 构建当前目录下的模块 |
| `mma` | 构建当前目录及其依赖 |
| `m nothing` | 只解析依赖，不实际编译（用于检查语法） |
| `m clean` | 清理构建产物 |
| `m installclean` | 清理 out/target，保留 host 工具 |

### lunch 目标格式

```
lunch <product>-<release>-<variant>
```

- **product**：设备代号，如 `aosp_cf_x86_64_phone` (Cuttlefish), `aosp_oriole` (Pixel 6)
- **release**：发布类型，如 `trunk_staging`, `ap2a`
- **variant**：构建变体
  - `eng`：工程版，包含调试工具，root 权限
  - `userdebug`：调试版，接近用户版但可 root
  - `user`：正式发布版，无调试功能

安全研究通常选择 `userdebug` 或 `eng`。

## 5. 关键目录结构

```
build/
├── make/                    # 传统 Make 构建系统
├── soong/                   # Soong 构建系统 (Go 实现)
│   ├── androidmk/           # Android.mk → Android.bp 转换工具
│   ├── cc/                  # C/C++ 模块规则
│   ├── java/                # Java 模块规则
│   └── ...
└── blueprint/               # Blueprint 解析器

out/
├── host/                    # Host 工具链输出
├── target/
│   └── product/<device>/
│       ├── system/          # system 分区内容
│       ├── vendor/          # vendor 分区内容
│       ├── obj/             # 中间产物 (.o, .a)
│       ├── symbols/         # 带符号的二进制（用于调试）
│       └── *.img            # 最终镜像文件
└── soong/
    └── .intermediates/      # Soong 中间产物
```

**安全研究提示**：`out/target/product/<device>/symbols/` 下的文件保留了完整符号表，是逆向和调试的宝贵资源。

## 6. 模块编译实战

### 单独编译一个模块

```bash
# 编译 system_server
m services

# 编译 SurfaceFlinger
m surfaceflinger

# 编译某个 HAL
m android.hardware.camera.provider@2.4-service
```

### 查看模块信息

```bash
# 查看模块定义位置
m <module> --print-module-info

# 查看模块依赖
m <module> --dumpvars-mode
```

### 转换 Android.mk 到 Android.bp

```bash
# 使用 androidmk 工具
androidmk Android.mk > Android.bp
```

## 7. 分区与镜像

Android 设备通常包含多个分区，构建系统为每个分区生成独立镜像：

| 分区 | 内容 | 更新策略 |
|------|------|----------|
| `boot` | kernel + ramdisk | OTA |
| `system` | Android Framework、系统应用 | OTA |
| `vendor` | HAL 实现、厂商驱动 | OTA (Treble 后独立更新) |
| `product` | 产品定制内容 | OTA |
| `system_ext` | 系统扩展 | OTA |
| `odm` | ODM 定制 | OTA |

**Treble 架构** (Android 8+) 将 vendor 与 system 解耦，允许独立更新 Framework 而不影响 HAL。这对安全研究意味着需要分别关注不同分区的攻击面。

## 8. SELinux 策略构建

SELinux 策略也是构建系统的一部分，相关文件位于：

```
system/sepolicy/
├── public/          # 公共策略，vendor 可见
├── private/         # 私有策略，仅 system
├── vendor/          # vendor 策略基础
└── prebuilts/api/   # API 版本快照
```

构建时会合并这些策略生成最终的二进制策略文件。修改 SELinux 策略后需重新编译：

```bash
m selinux_policy
```

## 9. 调试构建问题

### 常见问题排查

```bash
# 查看详细构建日志
m <module> V=1

# 显示 Ninja 执行的命令
m <module> -v

# 检查为什么某个模块被重新编译
m <module> -d explain
```

### 增量编译失效

如果增量编译出现问题，可以尝试：

```bash
# 清理单个模块
m <module>-clean

# 清理整个 out 目录
rm -rf out/
```

## 10. 安全研究视角

理解构建系统对安全研究的价值：

1. **快速迭代**：修改代码后只编译受影响的模块，加速测试循环
2. **符号获取**：知道 `out/target/product/<device>/symbols/` 的位置
3. **策略分析**：理解 SELinux 策略的构建流程，定位策略文件
4. **依赖追踪**：分析模块依赖关系，理解攻击面
5. **定制镜像**：为研究目的构建特定配置的系统镜像

## 参考资源

- [Soong Build System](https://source.android.com/docs/setup/build)
- [Build System Overview](https://android.googlesource.com/platform/build/soong/+/master/README.md)
- [Android.bp 语法参考](https://ci.android.com/builds/submitted/latest/linux/view/soong_build.html)
- [Adding a New Device](https://source.android.com/docs/setup/create/new-device)
