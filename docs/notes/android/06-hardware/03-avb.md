# 6x02 - Verified Boot (AVB)

Android Verified Boot (AVB) 确保了从 Bootloader 到内核的每一行代码都是经过签名的。

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

## 2. 回滚保护（Rollback Protection）

回滚保护用于防止降级到旧版镜像：

- 通过版本号/rollback index 等机制
- 依赖硬件或安全存储记录不可逆的版本状态

该机制在安全更新策略中非常关键：补丁只有在“无法轻易回退”时才真正生效。

## 2. 解锁 Bootloader
- **风险**: 解锁后，信任链断裂，系统可以加载未经签名的代码。
- **Root 的代价**: 许多依赖硬件安全的应用（如 Google Pay, 银行 App）会通过 **Play Integrity API** 检测到设备状态异常。

## 3. 与设备态检测的关系

很多应用侧的“设备可信度检测”会间接依赖 AVB/bootloader 状态：

- bootloader 解锁状态
- 系统分区完整性
- 设备是否处于可调试/非正式构建

## 4. 排查与验证（偏工程）

不同设备暴露的信息不同，但常见思路包括：

- 通过 bootloader/fastboot 侧信息确认锁状态
- 观察启动过程的 verity 相关日志（取决于可观测性）
- 确认 system/vendor 分区是否启用 verity 与其错误处理策略

## 5. 关联阅读

- `/notes/android/06-hardware/04-keystore`（attestation 通常会把设备状态纳入证明链）
