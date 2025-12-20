# 0x00 - Environment Setup & Technical Reference

## 1. AOSP 编译环境

本地 AOSP 源码是深入研究 Android 底层的基石。以下为编译 Android 14/15 的推荐配置与步骤。

### 硬件要求
- **内存**：至少 32GB (推荐 64GB+)。
- **硬盘**：至少 500GB 剩余空间 (推荐 NVMe SSD)。
- **系统**：Ubuntu 20.04/22.04 LTS。

### 基础依赖安装
```bash
sudo apt-get install git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
```

### repo 工具安装

`repo` 是 Google 用于管理多 Git 仓库的工具，AOSP 同步必备：

```bash
mkdir -p ~/.bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
chmod a+x ~/.bin/repo
export PATH="${HOME}/.bin:${PATH}"  # 建议加入 ~/.bashrc
```

如果宿主机是 macOS，更现实的选择通常是：

- 使用 Ubuntu 虚拟机（VMWare/UTM/Parallels）作为编译与调试环境
- 或用一台单独的 Linux 机器做 AOSP 编译（本地通过 `adb` 联调）

原因很简单：AOSP 的官方构建链路主要面向 Linux，很多工具链与依赖在 macOS 上不稳定或成本较高。

### 源码同步
```bash
repo init -u https://android.googlesource.com/platform/manifest -b android-14.0.0_r1
repo sync -j$(nproc)
```

实践建议：

- 初次 sync 建议预留足够空间与稳定网络；中断后可以继续 sync
- 研究时不一定需要全量编译：可优先阅读源码 + 只编译关键模块

### 基本构建流程（概念级）

常见步骤（不同版本/目标设备差异较大）：

```bash
source build/envsetup.sh
lunch <target>
m -j$(nproc)
```

常用 `lunch` target 示例：

| Target | 用途 |
|--------|------|
| `aosp_cf_x86_64_phone-userdebug` | Cuttlefish 模拟器（x86_64） |
| `aosp_cf_arm64_phone-userdebug` | Cuttlefish 模拟器（ARM64，适合 Apple Silicon 虚拟机） |
| `aosp_oriole-userdebug` | Pixel 6 |
| `aosp_panther-userdebug` | Pixel 7 |
| `aosp_shiba-userdebug` | Pixel 8 |

::: tip userdebug vs eng
- `userdebug`：带调试符号，接近生产环境，适合大多数研究场景
- `eng`：开发模式，权限更宽松但与真实环境差异较大
:::

如果是为了研究系统服务/Framework，很多时候优先关注 `frameworks/base/` 相关的编译与运行环境即可。

## 2. 调试与分析工具

### 调试器 (Debugger)
- **GDB / LLDB**：用于 Native 层调试。建议使用 AOSP 路径下的预编译版本：
  - `prebuilts/gdb/`
  - `prebuilts/clang/host/linux-x86/bin/lldb`
- **Frida**：动态 Hook 与追踪工具。
  ```bash
  pip install frida-tools
  ```

### Frida Server 部署

Frida 需要在目标 Android 设备上运行 `frida-server`：

```bash
# 1. 查看设备架构
adb shell getprop ro.product.cpu.abi
# 输出如 arm64-v8a

# 2. 下载对应版本（去 GitHub Releases 下载）
# https://github.com/frida/frida/releases
# 例如 frida-server-16.x.x-android-arm64.xz

# 3. 解压并推送到设备
xz -d frida-server-16.x.x-android-arm64.xz
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# 4. 启动（需要 root）
adb shell su -c /data/local/tmp/frida-server &

# 5. 验证连接
frida-ps -U
```

::: warning
Frida 需要 root 权限。模拟器或 userdebug 版本通常可以直接 `adb root`，正式版系统需要先解锁 + root。
:::

### LLDB 调试示例

Attach 到运行中的 Native 进程：

```bash
# 在设备上启动 lldb-server
adb push prebuilts/clang/host/linux-x86/bin/lldb-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/lldb-server
adb shell /data/local/tmp/lldb-server platform --listen "*:1234" --server &

# 端口转发
adb forward tcp:1234 tcp:1234

# 本地 LLDB 连接
lldb
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
(lldb) process attach --pid <target_pid>
```

### 运行环境选择
- **模拟器 (Cuttlefish)**：Google 官方推荐的虚拟化研究环境，支持内核调试与元数据追踪。
- **真机 (Pixel)**：建议使用 Pixel 6 及以上版本，以支持 MTE (Memory Tagging Extension) 等现代硬件安全特性。
### Cuttlefish 快速上手

Cuttlefish 是 Google 推荐的 AOSP 开发/研究模拟器，基于 KVM 虚拟化，比传统 emulator 更接近真机行为。

**安装依赖**（Ubuntu）：
```bash
sudo apt install -y git devscripts equivs config-package-dev debhelper-compat golang curl
git clone https://github.com/google/android-cuttlefish
cd android-cuttlefish
for dir in base frontend; do
  pushd $dir
  debuild -i -us -uc -b -d
  popd
done
sudo dpkg -i ./cuttlefish-base_*.deb ./cuttlefish-user_*.deb
sudo usermod -aG kvm,cvdnetwork,render $USER
# 需要重启或重新登录
```

**启动（AOSP 编译完成后）**：
```bash
launch_cvd --daemon
# 停止
stop_cvd
```

**连接 adb**：
```bash
adb connect 127.0.0.1:6520
```

**Web 界面**：启动后访问 `https://localhost:8443` 可获得图形界面（需要在编译时包含 webrtc 支持）。
补充：在“复现/验证漏洞”场景里，模拟器与真机的选择往往取决于目标组件。

- framework/service 逻辑问题：模拟器通常足够
- 硬件/驱动/HAL 问题：更依赖真机与厂商实现

## 3. 代码导航与关键路径

### 在线搜索
- **[cs.android.com](https://cs.android.com)**：支持交叉引用的官方代码搜索工具。

本地阅读技巧：

- 优先从“接口入口”找实现：AIDL/HIDL 接口、系统服务注册点、JNI 注册点
- 善用 `ripgrep` 在本地快速全文搜索（比 IDE 全局索引更直接）

### AOSP 关键目录索引
| 路径 | 说明 |
|------|------|
| `frameworks/base/` | Java Framework 核心实现 |
| `frameworks/native/` | Native Framework (Binder, SurfaceFlinger) |
| `system/core/` | 系统核心组件 (init, adbd, logd) |
| `system/sepolicy/` | SELinux 策略定义 |
| `bionic/` | Android C 库实现 |
| `packages/modules/Virtualization/` | AVF / pKVM 相关实现 |

## 4. 参考资源

- **官方文档**：[source.android.com](https://source.android.com)
- **安全公告**：[Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- **内核文档**：[source.android.com/docs/core/architecture/kernel](https://source.android.com/docs/core/architecture/kernel)
- **构建概览**：[source.android.com/docs/setup/build](https://source.android.com/docs/setup/build)
- **构建 Android**：[source.android.com/docs/setup/build/building](https://source.android.com/docs/setup/build/building)
- **下载源码（repo sync）**：[source.android.com/source/downloading](https://source.android.com/source/downloading)
- **构建要求**：[source.android.com/source/requirements](https://source.android.com/source/requirements)

## 5. 最小化联调工具（macOS 常用）

如果在 macOS 上主要做“看代码 + 连真机/模拟器”，最常用的是 platform-tools：

- `adb`：安装、启动组件、抓日志、取 tombstone
- `fastboot`：刷机/解锁相关（谨慎）

可以把“编译环境”和“联调环境”拆开：AOSP 在 Linux 上编译，macOS 仅用 `adb/logcat` 做交互与采样。
## 6. 常见问题

### repo sync 失败 / 网络问题
- 中断后直接重新运行 `repo sync -j4`（适当降低并发数）
- 国内环境可考虑使用镜像源（清华、中科大等）
- 设置 `export REPO_URL='https://mirrors.tuna.tsinghua.edu.cn/git/git-repo'`

### 编译内存不足 (OOM Killed)
- 降低并发：`m -j4` 而非 `m -j$(nproc)`
- 增加 swap 空间：
  ```bash
  sudo fallocate -l 16G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  ```

### Jack server out of memory（Android 8 及以前）
```bash
export JACK_SERVER_VM_ARGUMENTS="-Dfile.encoding=UTF-8 -XX:+TieredCompilation -Xmx4g"
```

### 找不到设备 / adb unauthorized
- 确认开发者选项已开启 USB 调试
- `adb kill-server && adb start-server`
- 检查设备上是否有授权弹窗