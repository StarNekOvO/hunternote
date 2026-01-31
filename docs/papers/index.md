# Papers

学术论文阅读笔记与研究方向追踪

## 论文学习路径

系统化阅读 Android/移动安全学术论文的推荐顺序。

### Phase 1: 基础论文 (Foundation)

建立安全研究基础概念，理解 Android 安全模型：

| 论文 | 会议 | 年份 | 主题 |
|------|------|------|------|
| Android Security: A Survey | ACM Computing Surveys | 2015 | Android 安全综述 |
| Dissecting Android Malware | IEEE S&P | 2012 | 恶意软件分析方法论 |
| SoK: Android Security | IEEE S&P | 2016 | Android 安全系统化知识 |

### Phase 2: 攻击技术 (Offensive) - 2023-2025

学习最新攻击方法论：

| 论文 | 会议 | 年份 | 主题 |
|------|------|------|------|
| DVa: Extracting Victims and Abuse Vectors from Android Accessibility Malware | USENIX Security | 2024 | 辅助功能滥用分析 |
| VoltSchemer: Use Voltage Noise to Manipulate Your Wireless Charger | USENIX Security | 2024 | 无线充电硬件攻击 |
| Born with a Silver Spoon: On the (In)Security of Native Granted App Privileges in Custom Android ROMs | IEEE S&P | 2025 | 定制 ROM 预装应用权限安全 |
| 50 Shades of Support: A Device-Centric Analysis of Android Security Updates | NDSS | 2024 | OEM 安全更新碎片化分析 |
| Vulnerability Management in Android Smartphone Chipsets | NDSS | 2025 | 芯片级漏洞管理 |

### Phase 3: 检测与防御 (Defensive) - 2023-2025

理解现代检测与防护技术：

| 论文 | 会议 | 年份 | 主题 |
|------|------|------|------|
| ForeDroid: Scenario-Aware Analysis for Android Malware Detection and Explanation | ACM CCS | 2025 | LLM 辅助恶意软件检测 |
| Combating Concept Drift with Explanatory Detection and Adaptation for Android Malware Classification | ACM CCS | 2025 | 对抗概念漂移的分类器 |
| MaDroid: A Maliciousness-aware Multifeatured Dataset | Computers & Security | 2024 | 恶意软件检测数据集 |
| Portal: Fast and Secure Device Access with Arm CCA | IEEE S&P | 2025 | Arm CCA 安全访问 |

### Phase 4: 前沿研究 (Cutting-edge) - 2024-2025

追踪最新研究方向：

| 论文 | 会议 | 年份 | 主题 |
|------|------|------|------|
| AI Psychiatry: Forensic Investigation of Deep Learning Networks in Memory Images | USENIX Security | 2024 | AI 模型取证分析 |
| CrowdGuard: Federated Backdoor Detection in Federated Learning | NDSS | 2024 | 联邦学习安全 |
| Eavesdropping on Black-box Mobile Devices via Audio Amplifier | NDSS | 2024 | 侧信道窃听攻击 |
| TEE Side-channel Analysis | CCS | 2024 | 硬件隔离攻击 |

## 按主题分类

### 内核安全 (Kernel Security)
| 论文 | 会议/年份 | 关键词 |
|------|----------|--------|
| SyzScope: Revealing High-Risk Security Impacts of Fuzzer-Exposed Bugs | USENIX Security 2022 | Syzkaller 漏洞分析 |
| GREBE: Unveiling Exploitation Potential for Linux Kernel Bugs | IEEE S&P 2022 | 内核漏洞可利用性 |
| Demystifying Pointer Authentication on Apple M1 | USENIX Security 2023 | PAC 安全分析 |

### 恶意软件分析 (Malware Analysis)
| 论文 | 会议/年份 | 关键词 |
|------|----------|--------|
| DVa: Android Accessibility Malware | USENIX Security 2024 | 辅助功能滥用 |
| ForeDroid: Scenario-Aware Detection | CCS 2025 | 场景感知检测 |
| Concept Drift in Malware Classification | CCS 2025 | 长期检测能力 |

### 系统安全 (System Security)
| 论文 | 会议/年份 | 关键词 |
|------|----------|--------|
| Born with a Silver Spoon | IEEE S&P 2025 | 定制 ROM 安全 |
| 50 Shades of Support | NDSS 2024 | 更新碎片化 |
| Chipset Vulnerability Management | NDSS 2025 | 固件安全 |

### 硬件安全 (Hardware Security)
| 论文 | 会议/年份 | 关键词 |
|------|----------|--------|
| VoltSchemer | USENIX Security 2024 | 无线充电攻击 |
| Portal: Arm CCA | IEEE S&P 2025 | 机密计算 |
| Audio Amplifier Eavesdropping | NDSS 2024 | 物理侧信道 |

### 隐私保护 (Privacy)
| 论文 | 会议/年份 | 关键词 |
|------|----------|--------|
| Android Privacy Analysis | Various 2023-2024 | 权限与数据流 |
| Federated Learning Security | NDSS 2024 | 分布式隐私 |

## 顶会列表与投稿周期

### Security 四大顶会
| 会议 | 全称 | 周期 | DDL (通常) |
|------|------|------|------------|
| USENIX Security | USENIX Security Symposium | 年度 (3轮) | 6月/10月/2月 |
| IEEE S&P | IEEE Symposium on Security and Privacy | 年度 (2轮) | 4月/12月 |
| ACM CCS | ACM Conference on Computer and Communications Security | 年度 (2轮) | 1月/5月 |
| NDSS | Network and Distributed System Security | 年度 (2轮) | 4月/7月 |

### 相关顶会
| 会议 | 主题 | 备注 |
|------|------|------|
| MobiSys | 移动系统 | ACM |
| MobiCom | 移动通信 | ACM |
| ACSAC | 应用安全 | ACM |
| AsiaCCS | 亚太区安全 | ACM |

## 2024-2025 必读论文

### 内核/系统层
1. **Born with a Silver Spoon** (S&P 2025) - 定制 ROM 安全
2. **Vulnerability Management in Chipsets** (NDSS 2025) - 芯片级漏洞
3. **Portal: Arm CCA** (S&P 2025) - 机密计算架构

### 应用层
1. **DVa** (USENIX 2024) - 辅助功能恶意软件
2. **ForeDroid** (CCS 2025) - 场景感知检测
3. **50 Shades of Support** (NDSS 2024) - 更新碎片化

### 硬件层
1. **VoltSchemer** (USENIX 2024) - 无线充电攻击
2. **Audio Amplifier Eavesdropping** (NDSS 2024) - 物理侧信道

## 资源链接

### 论文检索
- [DBLP](https://dblp.org/) - 计算机科学文献库
- [Google Scholar](https://scholar.google.com/) - 学术搜索
- [Semantic Scholar](https://www.semanticscholar.org/) - AI 辅助检索

### 会议官网
- [USENIX Security](https://www.usenix.org/conferences)
- [IEEE S&P](https://www.ieee-security.org/TC/SP-Index.html)
- [ACM CCS](https://www.sigsac.org/ccs/)
- [NDSS](https://www.ndss-symposium.org/)

### 排名与统计
- [Security Top-100](https://mlsec.org/topnotch/sec_ntop100.html)
- [Conference Ranking](http://jianying.space/conference-ranking.html)
- [CSRankings](https://csrankings.org/)

### 官方报告
- [Google 2024 Android Security Paper](https://services.google.com/fh/files/misc/android-security-paper-2024.pdf)
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
