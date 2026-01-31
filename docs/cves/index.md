# CVEs

漏洞复现、POC、EXP

## CVE 学习路径

本节提供 Android 安全漏洞的系统学习路径，从基础到高级逐步深入。

### 入门级 (Beginner)

建议从以下类型开始，这些漏洞原理清晰、复现相对简单：

| CVE | 年份 | 类型 | 组件 | 学习重点 |
|-----|------|------|------|----------|
| CVE-2019-2215 | 2019 | UAF | Binder 驱动 | 内核 UAF 基础、Binder 机制 |
| CVE-2020-0041 | 2020 | 越界写 | Binder | 内核堆操作、对象布局 |
| CVE-2021-0920 | 2021 | 条件竞争 | Unix Socket | 文件描述符生命周期 |
| CVE-2017-13156 | 2017 | 签名绕过 | APK 签名 | Janus 攻击、ZIP/DEX 解析 |
| CVE-2020-0096 | 2020 | 逻辑漏洞 | AMS | StrandHogg 2.0、任务栈劫持 |

**学习建议**：
1. 先阅读漏洞公告和补丁 diff
2. 搭建对应版本的测试环境
3. 尝试理解触发路径
4. 参考公开 PoC 进行复现

### 进阶级 (Intermediate)

需要更深入理解系统机制：

| CVE | 年份 | 类型 | 组件 | 学习重点 |
|-----|------|------|------|----------|
| CVE-2022-0847 | 2022 | 逻辑漏洞 | Pipe | Dirty Pipe、Page Cache |
| CVE-2022-20409 | 2022 | UAF | io_uring | 现代内核子系统 |
| CVE-2023-21036 | 2023 | 信息泄露 | aCropalypse | 截图编辑器数据残留 |
| CVE-2023-20938 | 2023 | UAF | Binder | 现代 Binder 利用 |
| CVE-2023-4863 | 2023 | 堆溢出 | libwebp | 图片解析漏洞 |
| CVE-2024-31320 | 2024 | 权限提升 | Framework | Android 12/12L 提权 |

**学习建议**：
1. 深入阅读相关子系统源码
2. 理解缓解机制如何被绕过
3. 尝试编写完整 exploit
4. 分析补丁的完整性

### 高级级 (Advanced) - 2024/2025 野外利用

涉及复杂利用链和现代缓解绕过，多为野外真实攻击：

| CVE | 年份 | 类型 | 组件 | 学习重点 |
|-----|------|------|------|----------|
| CVE-2024-53104 | 2024 | OOB 写 | USB UVC 驱动 | USB 攻击面、物理访问利用 |
| CVE-2024-50302 | 2024 | 信息泄露 | HID 子系统 | USB HID 报告解析 |
| CVE-2024-53150 | 2024 | OOB 读 | USB Audio | 利用链组件 |
| CVE-2024-53197 | 2024 | 权限提升 | ALSA USB | Cellebrite 利用链 |
| CVE-2024-43093 | 2024 | 权限提升 | Framework | 沙箱逃逸、数据目录访问 |
| CVE-2024-32896 | 2024 | 权限提升 | Framework | 本地提权无需额外权限 |
| CVE-2025-38352 | 2025 | 条件竞争 | POSIX Timer | Chronomaly、竞争窗口扩展 |
| CVE-2025-0091 | 2025 | 权限提升 | System | 最新系统组件漏洞 |

**野外利用案例 - Cellebrite UFED 攻击链**：
2024-2025 年间，安全研究人员发现 Cellebrite 数字取证工具利用 USB 漏洞链攻击目标设备：
1. CVE-2024-53104 (UVC) - 初始代码执行
2. CVE-2024-50302 (HID) - 泄露内核内存/凭据
3. CVE-2024-53150/53197 (Audio) - 完成提权

**学习建议**：
1. 学习现代缓解机制 (MTE/PAC/CFI)
2. 研究利用链构造方法
3. 关注安全会议最新研究
4. 尝试发现变种或绕过

## 按组件分类

### 内核漏洞 (2023-2025)
| CVE | 年份 | 组件 | 描述 |
|-----|------|------|------|
| CVE-2024-53104 | 2024 | USB UVC | 视频帧解析越界写 |
| CVE-2024-50302 | 2024 | USB HID | 未初始化内存读取 |
| CVE-2024-53150 | 2024 | USB Audio | 越界读 |
| CVE-2024-53197 | 2024 | ALSA | 提权 |
| CVE-2023-20938 | 2023 | Binder | UAF |
| CVE-2025-38352 | 2025 | POSIX Timer | 竞争条件 |

### Framework 漏洞 (2023-2025)
| CVE | 年份 | 组件 | 描述 |
|-----|------|------|------|
| CVE-2024-43093 | 2024 | Framework | 敏感目录访问 |
| CVE-2024-32896 | 2024 | Framework | 本地提权 |
| CVE-2024-31320 | 2024 | Framework | Android 12 提权 |
| CVE-2024-40650 | 2024 | System | 本地提权 |
| CVE-2024-40652 | 2024 | System | 本地提权 |
| CVE-2024-49721 | 2024 | Framework | 权限绕过 |

### 厂商驱动漏洞
| CVE | 年份 | 厂商 | 描述 |
|-----|------|------|------|
| CVE-2024-20832 | 2024 | Samsung | Bootloader 攻击 |
| CVE-2024-20865 | 2024 | Samsung | 启动链持久化 |
| CVE-2023-21492 | 2023 | Samsung | Kernel 信息泄露 |
| CVE-2023-4211 | 2023 | Arm Mali | GPU 驱动 UAF |

## 按年份索引

### 2025 年
- CVE-2025-38352: POSIX Timer 竞争条件
- CVE-2025-0091/0095/0096: System 组件提权
- 持续更新中...

### 2024 年 (重点)
**内核**:
- CVE-2024-53104, CVE-2024-50302, CVE-2024-53150, CVE-2024-53197 (USB 攻击链)

**Framework/System**:
- CVE-2024-43093 (野外利用)
- CVE-2024-32896 (野外利用)
- CVE-2024-31320, CVE-2024-40650/52/54/55/57

### 2023 年
- CVE-2023-21036: aCropalypse 截图信息泄露
- CVE-2023-20938: Binder UAF
- CVE-2023-4863: libwebp 堆溢出 (影响 Chrome/Android)
- CVE-2023-4211: Mali GPU 驱动 UAF
- CVE-2023-21492: Samsung 内核信息泄露

## 资源链接

### 官方资源
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [Google 2024 Android Security Paper](https://services.google.com/fh/files/misc/android-security-paper-2024.pdf)
- [NVD - Android CVEs](https://nvd.nist.gov/vuln/search/results?query=android)

### PoC 仓库
- [Chronomaly CVE-2025-38352](https://github.com/farazsth98/chronomaly)
- [Android Kernel CVE PoCs](https://github.com/ScottyBauer/Android_Kernel_CVE_POCs)
- [Google Project Zero Issues](https://bugs.chromium.org/p/project-zero/issues/list)

### 分析文章
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [Quarkslab Blog](https://blog.quarkslab.com/)
- [Amnesty International - Cellebrite 分析](https://www.amnesty.org/en/latest/research/)
