# 2x02 - HIDL 与 AIDL (Treble 架构)

随着 Project Treble 的引入，Android 的 IPC 体系变得更加复杂，但也更加模块化。

这一章的研究目标不是记名词，而是回答三个问题：

1. Framework 与 Vendor 的边界在哪里？
2. HAL 进程/接口是如何被发现与约束的？
3. 为什么“把东西搬出 system_server”会显著改变攻击面？

## 1. Project Treble 的初衷

在 Treble 之前，框架层（Framework）与硬件抽象层（HAL）紧密耦合。升级系统往往需要芯片厂商（如高通）配合更新 HAL。
Treble 通过将 Framework 与 HAL 分离，实现了“一次编写，到处运行”的系统升级。

更具体地说：

- **接口稳定性**：Framework 通过稳定接口调用 Vendor 侧实现
- **可替换性**：Vendor 不需要跟着 Framework 每次大改
- **安全隔离**：让高风险解析/硬件交互跑在更合适的域里

## 2. HIDL (HAL Interface Definition Language)

HIDL 是专门为 HAL 设计的接口语言。

- **Binderized 模式**: HAL 运行在独立的进程中，通过 `/dev/hwbinder` 与 Framework 通信。这是最安全、最推荐的模式。
- **Passthrough 模式**: 为了兼容旧版 HAL，允许 Framework 直接加载共享库（.so）。

### 安全意义
通过将 HAL 移出 `system_server` 进程，即使某个驱动程序（如相机、传感器）存在漏洞，攻击者也只能控制该 HAL 进程，而无法直接获取系统核心权限。

补充：Passthrough 模式的安全语义更差，因为它把 vendor 的 .so 直接拉进了 framework 进程空间，等价于扩大了高权限进程的攻击面（这也是 Treble 推 binderized 的原因之一）。

## 3. `binder` 与 `hwbinder` 的差异（理解边界）

- `binder`：应用/系统服务广泛使用的通用 binder
- `hwbinder`：为 HAL 体系设计的 binder（历史上设备节点与服务发现体系不同）

从安全视角，关心的不是“哪个更高级”，而是：

- 哪些进程能访问对应的 binder 设备
- 服务运行在哪个 SELinux 域
- 接口是否稳定、是否容易被 fuzz

## 4. AIDL 的统一

在 Android 11 之后，AIDL 开始取代 HIDL 成为 HAL 的首选接口语言（称为 Stable AIDL）。

- **优势**: 统一了应用层和系统层的开发体验。
- **VNDK**: 供应商原生开发套件，确保了库的版本兼容性。

Stable AIDL 的关键词：

- **接口版本化**：明确兼容策略（新增方法、废弃方法）
- **跨分区稳定**：system/vendor 边界上更可控

## 5. VINTF 与服务发现（研究入口）

在 Treble 体系下，“系统有哪些 HAL 服务、版本是多少、由谁提供”通常由清单机制描述（设备厂商与系统镜像共同决定）。

研究时常需要回答：

- 目标设备上是否存在某 HAL 服务
- 服务是 binderized 还是 passthrough
- 接口版本与实现位置

这些信息往往可以通过系统工具/清单侧线索定位（具体命令与文件在不同版本/厂商上差异较大）。

## 6. 攻击面分析

HAL 进程是系统中最接近硬件的用户态代码，也是**内核漏洞利用的跳板**和**提权漏洞的热点**。

### 6.1 常见漏洞模式

**1. 共享内存越界**

HAL 经常使用共享内存（ashmem/memfd）传递大量数据（如视频流、音频缓冲）。

```cpp
// 典型的漏洞代码（Camera HAL）
void processCameraFrame(const native_handle_t* buffer, size_t size) {
    void* data = mmap(buffer->data[0], size, ...);  // size 来自 Framework
    
    // 危险：未校验 size 是否与 buffer 实际大小匹配
    memcpy(processingBuffer, data, size);  // 越界读取
}
```

**攻击思路**：
- Framework 传入一个小的 buffer 和一个大的 size
- HAL 越界读取 -> 信息泄露
- 或者 Framework 在 HAL 读取期间修改 buffer 内容（TOCTOU）

**2. 接口参数契约不一致**

```cpp
// Framework 侧（Java）
cameraService.setParameters(width, height, format);
// width/height 单位：像素

// HAL 侧（C++）
void setParameters(uint32_t width, uint32_t height, uint32_t format) {
    size_t bufferSize = width * height * getBytesPerPixel(format);  // 整数溢出！
    buffer = malloc(bufferSize);
}
```

**3. 句柄/FD 传递泄露**

```cpp
// 高权限 HAL 返回一个 camera FD 给应用
Return<void> getCameraFd(getCameraFd_cb _hidl_cb) {
    int fd = open("/dev/video0", O_RDWR);  // 敏感设备
    _hidl_cb(fd);  // 直接传给不可信调用方！
}
```

攻击者可以直接操作该 FD，绕过 HAL 的访问控制。

**4. 状态机与并发竞态**

```cpp
class MediaHal {
    bool isConfigured = false;
    
    void configure(const Config& config) {
        // 配置硬件
        isConfigured = true;
    }
    
    void processData(const Data& data) {
        if (!isConfigured) return;  // 竞态窗口
        // 使用硬件处理数据
    }
};
```

多线程同时调用 `configure` 和 `processData` 可能导致状态不一致。

### 6.2 真实案例：CVE-2020-0478 (MediaCodec HAL UAF)

**影响版本**：Android 8.0 - 11.0

**漏洞原理**：

MediaCodec HAL 在处理配置变更时存在 UAF 漏洞。

```cpp
// 简化的漏洞代码
void MediaCodecHal::reconfigure(const Config& newConfig) {
    freeOldBuffers();  // 释放旧的缓冲区
    
    // 竞态窗口：如果此时有回调正在访问缓冲区...
    
    allocateNewBuffers(newConfig);
}

void MediaCodecHal::onFrameRendered(int bufferId) {
    Buffer* buf = getBuffer(bufferId);  // UAF：可能访问已释放的内存
    // ...
}
```

**攻击流程**：
1. 应用调用 `reconfigure()` 触发缓冲区释放
2. 在重新分配之前，利用竞态条件触发 `onFrameRendered()` 回调
3. 回调访问已释放的内存 -> UAF
4. 通过堆喷射控制被释放内存的内容
5. 劫持控制流，实现 MediaCodec 进程内的代码执行
6. 结合其他漏洞提权到 system 或 root

**修复**：
- 添加引用计数和锁机制
- 确保回调执行前检查对象有效性

### 6.3 CVE-2019-2213 (Binder UAF in HAL)

这是另一个经典的 HAL 层漏洞，涉及 hwbinder 的对象生命周期管理。

**成因**：某些 HAL 服务在注销时未正确清理 Binder 引用，导致客户端仍持有指向已释放对象的 handle。

**利用价值**：UAF 漏洞在 Native 层通常可以直接转化为代码执行。

## 7. 研究与审计方法

### 7.1 从接口定义入手

**Step 1: 定位接口文件**

```bash
# 查找 HIDL 接口
find hardware/interfaces -name "*.hal"

# 查找 Stable AIDL 接口
find hardware/interfaces -name "*.aidl"

# 示例：Camera HAL
# hardware/interfaces/camera/device/3.2/ICameraDevice.hal
```

**Step 2: 查看接口版本与方法**

```cpp
// ICameraDevice.hal
package android.hardware.camera.device@3.2;

interface ICameraDevice {
    open(ICameraDeviceCallback callback) generates (Status status);
    
    configureStreams(StreamConfiguration config)
        generates (Status status, HalStreamConfiguration halConfig);
    
    processCaptureRequest(CaptureRequest request)
        generates (Status status);
    
    // ... 其他方法
};
```

**Step 3: 找到实现进程与 SELinux 域**

```bash
# 查看运行中的 HAL 进程
adb shell ps -A | grep "camera"
# 输出：system  1234  1  ... android.hardware.camera.provider@2.4-service

# 查看 SELinux 上下文
adb shell ps -Z | grep camera
# 输出：u:r:hal_camera_default:s0 ... android.hardware.camera.provider@2.4-service
```

**关键信息**：
- 进程名：`android.hardware.camera.provider@2.4-service`
- SELinux 域：`hal_camera_default`
- UID 通常是 `cameraserver` 或 `system`

### 7.2 枚举可访问的 HAL 服务

```bash
# 列出所有 hwbinder 服务（需要 root）
adb shell lshal

# 输出示例：
# android.hardware.camera.provider@2.4::ICameraProvider/legacy/0
#     Transport: hwbinder
#     Server: android.hardware.camera.provider@2.4-service
#     Clients: [cameraserver]
```

**关键字段**：
- `Transport`：hwbinder / passthrough
- `Server`：提供服务的进程
- `Clients`：当前连接的客户端（研究攻击路径）

### 7.3 Fuzzing HAL 接口

**使用 VTS (Vendor Test Suite) 作为起点**：

```bash
# VTS 包含了针对 HAL 接口的自动化测试
# 可以基于这些测试修改为 Fuzzer

# 示例：Camera HAL Fuzzer
adb shell /data/nativetest64/VtsHalCameraProviderV2_4TargetTest/VtsHalCameraProviderV2_4TargetTest
```

**自定义 Fuzzer（C++ 示例）**：

```cpp
#include <android/hardware/camera/device/3.2/ICameraDevice.h>

using android::hardware::camera::device::V3_2::ICameraDevice;
using android::sp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 获取 HAL 服务
    sp<ICameraDevice> device = ICameraDevice::getService();
    if (device == nullptr) return 0;
    
    // 从 fuzzer 输入构造配置
    StreamConfiguration config;
    // ... 解析 data 到 config
    
    // 调用目标接口
    auto ret = device->configureStreams(config, [](auto status, auto halConfig) {
        // 回调处理
    });
    
    return 0;
}
```

**编译与运行**：
```bash
# 添加到 Android.bp
cc_fuzz {
    name: "camera_hal_fuzzer",
    srcs: ["camera_hal_fuzzer.cpp"],
    shared_libs: [
        "android.hardware.camera.device@3.2",
        "libhidlbase",
    ],
}

# 编译
m camera_hal_fuzzer

# 在设备上运行
adb push $OUT/data/fuzz/arm64/camera_hal_fuzzer /data/local/tmp/
adb shell /data/local/tmp/camera_hal_fuzzer
```

### 7.4 动态追踪 HAL 调用

**使用 Frida Hook HAL 接口**：

```javascript
// Hook Camera HAL 的 configureStreams 方法
function hookCameraHAL() {
    // 加载 HAL 库
    var cameraHal = Process.findModuleByName("android.hardware.camera.device@3.2.so");
    
    // Hook 特定函数（需要符号表或 offset）
    var configureStreams = cameraHal.findExportByName("_ZN...configureStreamsE...");
    
    Interceptor.attach(configureStreams, {
        onEnter: function(args) {
            console.log("[Camera HAL] configureStreams called");
            console.log("  config pointer: " + args[1]);
            // 解析 StreamConfiguration 结构
        },
        onLeave: function(retval) {
            console.log("  returned: " + retval);
        }
    });
}

setImmediate(hookCameraHAL);
```

**使用 strace/systrace**：

```bash
# 追踪 HAL 进程的系统调用
adb shell strace -p $(pidof android.hardware.camera.provider@2.4-service) -e trace=ioctl,mmap,open

# 追踪 hwbinder 通信
adb shell cat /sys/kernel/debug/binder/proc/$(pidof android.hardware.camera.provider@2.4-service)
```

### 7.5 识别高风险 HAL 服务（按优先级）

| HAL 类型 | 风险等级 | 原因 |
|---------|---------|------|
| **Camera / Media** | 🔴 极高 | 处理复杂编解码、大量共享内存、历史漏洞多 |
| **Graphics / DRM** | 🔴 极高 | GPU 交互、受保护内容、内核驱动交互 |
| **Bluetooth / WiFi** | 🟠 高 | 网络输入、协议栈复杂 |
| **Sensors / GPS** | 🟡 中 | 数据流持续、但通常格式简单 |
| **Audio** | 🟡 中 | 音频处理、可能涉及 DSP |
| **Keymaster / Gatekeeper** | 🟢 低-中 | 安全关键但接口简单、有硬件保护 |

**选择策略**：
1. 优先选择**暴露给第三方应用**的 HAL（如 Camera）
2. 关注**处理外部数据**的 HAL（如 Media Codec）
3. 寻找**厂商定制**的 HAL（代码质量可能不如 AOSP）

## 参考（AOSP）

- 架构概览（含 HAL 层级、Treble 总体介绍入口）：https://source.android.com/docs/core/architecture
- HIDL（Android 10 起废弃，官方迁移口径）：https://source.android.com/docs/core/architecture/hidl
- AIDL 概览：https://source.android.com/docs/core/architecture/aidl
- 稳定的 AIDL（Stable AIDL）：https://source.android.com/docs/core/architecture/aidl/stable-aidl
