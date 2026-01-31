# 6x02 - Verified Boot (AVB)

Android Verified Boot (AVB) 是 Android 启动时验证（Verified Boot）的参考实现，目标是在启动链路中尽力保证关键组件的完整性与真实性（具体强制程度取决于设备配置与 bootloader 锁状态）。

AVB 的安全目标可以归纳为三点：

- **完整性**：启动链路上的关键组件不可被静默篡改
- **可验证性**：启动时可证明镜像来自可信签名
- **回滚保护**：阻止把系统降级到已知存在漏洞的旧版本

## 1. 信任链 (Chain of Trust)
1. **Root of Trust**: 固化在硬件中的公钥。
2. **Bootloader**: 验证 `vbmeta` 分区。
3. **Kernel**: 验证 `system`, `vendor` 等分区（通过 dm-verity）。

补充关键概念：

- **vbmeta**：包含分区摘要与签名等元数据，是启动链的核心锚点
- **dm-verity**：以 Merkle tree 的方式对块设备做完整性校验
- **verity 错误处理策略**：触发时是只读挂载失败、还是进入 recovery（实现与配置相关）

## 2. vbmeta 结构与工具

vbmeta 分区是 AVB 的核心数据结构，理解其布局对安全研究至关重要。

### 2.1 vbmeta 结构概览

vbmeta 镜像的基本布局：

```
+-------------------+
| Header            |  <- 魔数、版本、描述符偏移等
+-------------------+
| Authentication    |  <- 签名数据（RSA/ECDSA）
+-------------------+
| Auxiliary Data    |  <- 公钥、描述符、属性等
+-------------------+
```

**Header 关键字段**：

- `magic`：固定为 "AVB0"
- `required_libavb_version_major/minor`：最低兼容版本
- `algorithm_type`：签名算法（SHA256_RSA2048/4096/8192、SHA512 变体等）
- `rollback_index`：回滚保护版本号
- `flags`：控制验证行为（如 `AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED`）

**描述符类型**：

- `AVB_DESCRIPTOR_TAG_HASHTREE`：dm-verity 所需的 hash tree 信息
- `AVB_DESCRIPTOR_TAG_HASH`：单个分区的完整 hash
- `AVB_DESCRIPTOR_TAG_CHAIN_PARTITION`：链式验证到其他 vbmeta

### 2.2 avbtool：官方操作工具

`avbtool` 是 AOSP 提供的官方工具，位于 `external/avb/avbtool.py`。

**查看 vbmeta 信息**：

```bash
# 提取 vbmeta 分区
adb shell dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta.img
adb pull /data/local/tmp/vbmeta.img

# 解析 vbmeta 结构
avbtool info_image --image vbmeta.img
```

输出示例：

```
Footer version:           1.0
Image size:               4096 bytes
Original image size:      4096 bytes
VBMeta offset:            0
VBMeta size:              2112 bytes
--
Minimum libavb version:   1.0
Header Block:             256 bytes
Authentication Block:     576 bytes
Auxiliary Block:          1280 bytes
Algorithm:                SHA256_RSA4096
Rollback Index:           0
Flags:                    0
```

**生成自签名 vbmeta**：

```bash
# 生成测试密钥
openssl genrsa -out test_key.pem 4096
avbtool extract_public_key --key test_key.pem --output test_key.avbpubkey

# 创建空 vbmeta（用于解锁状态测试）
avbtool make_vbmeta_image \
    --key test_key.pem \
    --algorithm SHA256_RSA4096 \
    --rollback_index 0 \
    --output vbmeta_custom.img
```

### 2.3 avbroot：Root 与自定义签名工具

[avbroot](https://github.com/chenxiaolong/avbroot) 是一个专门用于修改 OTA 镜像并重新签名的工具，常用于保持 AVB 签名链完整的同时实现 root。

**核心功能**：

- 解包/重打包 OTA zip
- 替换 boot 镜像（如植入 Magisk）
- 使用自定义密钥重签所有 AVB 相关分区
- 保持 rollback index 不变以避免触发回滚保护

**典型使用流程**：

```bash
# 生成自定义 AVB 密钥
avbroot key generate-key -o custom.key
avbroot key generate-cert -k custom.key -o custom.crt

# 提取 OTA 中的 boot 镜像并 patch
avbroot ota extract -i ota.zip -d extracted/
# (手动 patch boot.img，如使用 Magisk)

# 使用自定义密钥重签 OTA
avbroot ota patch \
    -i original_ota.zip \
    -o patched_ota.zip \
    --key-avb custom.key \
    --key-ota custom.key \
    --cert-ota custom.crt
```

**安全研究价值**：

avbroot 展示了在 bootloader 解锁状态下，如何完整地替换 AVB 信任锚点。这对理解 AVB 的签名链结构和厂商实现差异很有帮助。

### 2.4 其他分析工具

- **android-simg2img**：处理 sparse image 格式
- **unpack_bootimg**：解包 boot.img（AOSP 自带）
- **magiskboot**：Magisk 的 boot 镜像处理工具，支持多种格式

## 3. 启动镜像与关键分区（boot / vendor_boot / system）

从 AVB 的视角理解启动链，通常需要把"启动镜像是什么、系统分区如何组织、更新如何切换"这三件事串起来。

### 3.1 `boot.img`：启动入口的镜像容器

`boot.img` 可以视为启动阶段的关键载体，常见组成包括：

- **kernel**：Linux 内核二进制
- **ramdisk**：早期启动使用的临时根文件系统（通常以 cpio 归档形式存在）
- **dtb/dtbo**：设备树相关数据，用于描述硬件拓扑与启动参数

安全研究中，`boot.img` 之所以重要，是因为它处在"最早期的可信边界"附近：它影响 `/init` 的启动上下文、内核启动参数的解释方式，以及后续分区挂载与完整性校验的策略落点。

### 3.2 ramdisk：早期用户态与挂载切换的过渡层

ramdisk 的核心作用是：在真正的 `system`/`vendor` 等分区被挂载前，提供一个可运行的最小用户态环境，启动 `/init` 并完成第一轮系统初始化（服务启动、分区挂载、SELinux 初始化与策略加载等）。

版本演进上，ramdisk 的内容总体趋向"最小化"：更多初始化逻辑被迁移到 system/vendor 侧，并通过更清晰的边界与校验机制约束。

### 3.3 `system.img`：框架与系统组件的主要载体

`system.img` 是框架与系统组件的重要承载分区，典型演进趋势包括：

- 从"可写分区"逐步过渡为"只读 + 完整性校验"（dm-verity）
- 文件系统从 ext4 向更偏只读场景的实现演进（如 EROFS，在部分版本/机型中常见）
- **动态分区**（super 分区）引入后，`system`/`vendor`/`product` 等可共享空间池，更新时按需分配

对安全研究而言，`system` 分区的核心关注点不在"是否能写入"，而在"完整性校验是否严格、错误策略是否可观测、更新/回滚是否存在边界条件"。

### 3.4 GKI 背景下的 `vendor_boot.img`

在 GKI 推进后，启动相关镜像可能进一步拆分：

- `boot.img` 更偏"通用内核 + 极简启动所需内容"
- `vendor_boot.img` 承载更多厂商特定的启动内容（如 vendor ramdisk、dtbo 等）

这会直接影响启动链的校验对象与实现复杂度：校验逻辑更依赖厂商 Bootloader 对多镜像、多分区元数据的正确处理。

## 4. 回滚保护（Rollback Protection）

回滚保护用于防止降级到旧版镜像：

- 通过版本号/rollback index 等机制
- 依赖硬件或安全存储记录不可逆的版本状态

该机制在安全更新策略中非常关键：补丁只有在"无法轻易回退"时才真正生效。

### 4.1 Rollback Index 机制

vbmeta 中的 `rollback_index` 字段与设备中存储的最低允许版本比较：

```
vbmeta.rollback_index >= device_stored_rollback_index
```

如果镜像的 rollback index 低于设备存储值，bootloader 应拒绝启动。

**存储位置**：

- 通常在 RPMB（Replay Protected Memory Block）或其他防篡改存储中
- 部分低端设备可能使用普通存储，削弱了保护效果

### 4.2 回滚保护绕过技术

**绕过思路 1：Rollback Index 未正确递增**

部分厂商在 OTA 更新时未正确递增 rollback index，导致：
- 所有历史版本的 rollback index 相同
- 可以刷入任意历史版本固件

检测方法：

```bash
# 比较不同版本 OTA 的 vbmeta rollback index
avbtool info_image --image vbmeta_v1.img | grep "Rollback Index"
avbtool info_image --image vbmeta_v2.img | grep "Rollback Index"
```

**绕过思路 2：RPMB 存储未启用或实现缺陷**

- 部分设备的 RPMB 未正确初始化
- 或使用软件模拟的存储，可通过其他漏洞清除

**绕过思路 3：多槽位状态混淆**

A/B 分区方案下，利用槽位切换逻辑的边界条件：
- 在特定时机切换到包含旧版本的槽位
- 利用更新失败回滚机制

**绕过思路 4：Bootloader 漏洞**

直接利用 bootloader 代码漏洞绕过检查，详见第 7 节。

## 5. AVB 绕过技术

### 5.1 测试密钥问题（AVBTestKeyInTheWild）

2024 年披露的 AVBTestKeyInTheWild 研究揭示了一个严重的供应链安全问题：多家 Android 设备厂商在量产设备中使用了 AOSP 公开的测试密钥。

**问题根源**：

AOSP 在 `external/avb/test/data/` 目录下提供了测试用的 AVB 密钥：

```
test/data/testkey_rsa2048.pem
test/data/testkey_rsa4096.pem
test/data/testkey_rsa8192.pem
```

这些密钥仅用于开发测试，私钥是公开的。但部分厂商错误地将这些测试密钥作为 Root of Trust 烧录到量产设备中。

**攻击影响**：

由于私钥公开，攻击者可以：

1. 签名任意 vbmeta 镜像
2. 绕过 AVB 验证刷入恶意系统
3. 在锁定 bootloader 状态下实现持久化攻击
4. 完全颠覆设备的启动信任链

**检测方法**：

```bash
# 提取设备的 AVB 公钥
avbtool info_image --image vbmeta.img --output-public-key device_pubkey.bin

# 与 AOSP 测试密钥比较
avbtool extract_public_key --key testkey_rsa4096.pem --output test_pubkey.bin
diff device_pubkey.bin test_pubkey.bin
```

**受影响厂商特征**：

- 主要集中在中小厂商和 ODM 方案
- 部分白牌设备、定制平板等
- 甚至包括部分运营商定制机型

**根本原因分析**：

- 供应链复杂：ODM/OEM 分离导致密钥管理责任不清
- 开发流程问题：测试固件直接转为量产版本
- 缺乏审计：没有自动化检测测试密钥的 CI/CD 流程

### 5.2 vbmeta Flags 滥用

vbmeta header 中的 flags 字段可以控制验证行为：

```c
#define AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED 0x01
#define AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED 0x02
```

**攻击场景**：

如果能控制 vbmeta 内容（如测试密钥场景），可以设置这些 flags 完全禁用验证：

```bash
avbtool make_vbmeta_image \
    --flags 2 \
    --key testkey_rsa4096.pem \
    --algorithm SHA256_RSA4096 \
    --output vbmeta_disabled.img
```

### 5.3 签名算法降级

部分旧设备或低端设备支持多种签名算法，可能存在算法选择漏洞：
- 强制使用弱算法（如 SHA256_RSA2048）
- 利用算法切换时的验证缝隙

### 5.4 Chained Partition 信任传递问题

AVB 支持 chained partition 机制，允许不同分区使用不同密钥。如果链式验证实现有缺陷：
- 可能跳过某些分区的验证
- 或利用优先级问题替换可信分区

## 6. 解锁 Bootloader

- **风险**: 解锁后，信任链断裂，系统可以加载未经签名的代码。
- **Root 的代价**: 许多依赖硬件安全的应用（如 Google Pay, 银行 App）会通过 **Play Integrity API** 检测到设备状态异常。

### 6.1 解锁状态检测

设备可通过多种方式暴露 bootloader 状态：

```bash
# fastboot 查询
fastboot getvar unlocked
fastboot getvar secure

# Android 系统属性
adb shell getprop ro.boot.verifiedbootstate
# green: 完全验证通过
# yellow: 使用自定义 Root of Trust
# orange: bootloader 解锁
# red: 验证失败
```

### 6.2 自定义 AVB 密钥风险

部分设备支持在解锁状态下设置自定义 AVB 公钥：

```bash
fastboot flash avb_custom_key custom_key.avbpubkey
fastboot oem avb_add_hash
```

**安全隐患**：

- 如果设备被物理访问并解锁，攻击者可以植入自己的信任锚点
- 重新锁定 bootloader 后，设备看起来"正常"但实际运行攻击者控制的系统
- 部分厂商实现中，自定义密钥的优先级处理存在问题

## 7. Bootloader 攻击面

Bootloader 是 AVB 验证的执行者，其自身安全性直接决定整个信任链的强度。

### 7.1 常见漏洞类型

**内存破坏类**：

- fastboot 协议解析中的缓冲区溢出
- 镜像头解析时的整数溢出
- USB 协议栈漏洞

**逻辑漏洞类**：

- fastboot 命令鉴权绕过
- 分区名校验不严导致任意分区读写
- 锁状态检查的竞态条件

**信息泄露类**：

- 通过 fastboot oem 命令泄露敏感信息
- 内存未清零导致密钥泄露

### 7.2 历史漏洞案例

**CVE-2017-5624 (OnePlus)**：
- fastboot oem 命令可在锁定状态下刷写任意分区
- 完全绕过 AVB 保护

**EDL (Emergency Download) 模式滥用**：
- 高通设备的 EDL 模式可绕过 bootloader
- 利用泄露的 firehose 程序实现底层读写

**MTK BootROM 漏洞**：
- MediaTek 设备的 BootROM 漏洞（如 mtk-bypass）
- 允许在最早期阶段获取代码执行

### 7.3 Bootloader 研究方法

**固件提取**：

```bash
# 从 OTA 包提取
unzip ota.zip -d ota_extracted/
# bootloader 通常在 bootloader.img 或特定分区

# 从设备直接读取（需要 root 或漏洞）
adb shell dd if=/dev/block/by-name/aboot of=/data/local/tmp/aboot.img
```

**逆向分析**：

- bootloader 通常为 ARM 架构，可用 IDA/Ghidra 分析
- 关注 fastboot 命令处理函数
- 识别 AVB 验证相关代码路径

**动态调试**：

- 部分设备支持 JTAG/SWD 调试接口
- 高通设备可能通过 EDL 模式进行调试
- QEMU 模拟（需要适配设备特定外设）

## 8. 与设备态检测的关系

很多应用侧的"设备可信度检测"会间接依赖 AVB/bootloader 状态：

- bootloader 解锁状态
- 系统分区完整性
- 设备是否处于可调试/非正式构建

## 9. OTA 更新机制与安全关注点

OTA 与 AVB 是"更新可被信任"的两个侧面：OTA 负责把新版本可靠落盘，AVB 负责在启动时拒绝被静默篡改/回退的镜像。

### 9.1 Recovery OTA 与 A/B OTA 的差异

- **Recovery OTA（早期常见）**：通过恢复环境写入关键分区；流程简单但容错依赖恢复环境与写入原子性。
- **A/B OTA（Android 7+ 常见）**：把系统分区分为 A/B 两套，后台写入非当前槽位，下次重启切换；失败可回滚到旧槽位，提高可用性。

### 9.2 虚拟 A/B 与动态分区带来的复杂度

虚拟 A/B 与动态分区常与 snapshot/合并流程相关，会引入更复杂的状态机与边界条件。安全研究中，关注点通常落在：

- 校验发生的时机与对象是否一致（元数据/分区内容/快照合并前后）
- 回滚/降级路径是否被正确约束（含 rollback index 与版本策略）
- 失败回滚的状态是否可能导致"不一致但可启动"的异常组合

## 10. 排查与验证（偏工程）

不同设备暴露的信息不同，但常见思路包括：

- 通过 bootloader/fastboot 侧信息确认锁状态
- 观察启动过程的 verity 相关日志（取决于可观测性）
- 确认 system/vendor 分区是否启用 verity 与其错误处理策略

### 10.1 完整性验证流程示例

```bash
# 1. 检查 bootloader 状态
fastboot getvar all 2>&1 | grep -E "(unlocked|secure|verifiedboot)"

# 2. 提取并分析 vbmeta
adb shell su -c "dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta.img"
adb pull /data/local/tmp/vbmeta.img
avbtool info_image --image vbmeta.img

# 3. 验证使用的密钥
avbtool info_image --image vbmeta.img --output-public-key current_key.bin

# 4. 检查 dm-verity 状态
adb shell su -c "cat /sys/block/dm-*/dm/name"
adb shell dmesg | grep -i verity
```

## 参考

**AOSP 官方文档**：

- https://source.android.com/docs/security/features/verifiedboot — 启动时验证总览
- https://source.android.com/docs/security/features/verifiedboot/avb — AVB 参考实现
- https://android.googlesource.com/platform/external/avb/ — AVB 源码仓库

**工具与项目**：

- https://github.com/chenxiaolong/avbroot — OTA 修改与重签名工具
- https://github.com/nicene/magiskboot — boot 镜像处理工具

**安全研究**：

- AVBTestKeyInTheWild — 供应链测试密钥滥用研究
- https://www.blackhat.com/docs/us-17/thursday/us-17-Shen-Defeating-Samsung-KNOX-With-Zero-Privilege.pdf — Samsung bootloader 研究
