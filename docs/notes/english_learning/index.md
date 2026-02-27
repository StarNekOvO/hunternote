# English Learning

> 跳过 ESL 教学，用语言学框架理解英语，用真实内容沉浸输入，用模仿输出倒逼写作。

## 学习策略

三条线并行推进：

| 线路 | 目标 | 核心动作 |
|------|------|----------|
| **语音学** | 建立发音的底层认知 | Geoff Lindsey 频道 + 教材 |
| **沉浸输入** | 日常信息流切换为英语 | 播客 + YouTube 内容频道 |
| **写作输出** | 模仿 native speaker 的表达 | 读博客 → 模仿风格 → 自己写 |

::: tip 关键原则
不要面面俱到。不要用 "学英语" 的方式学英语，而是 **用英语做你本来就在做的事**。
:::

---

## 0x00 语音学 / 音韵学

> 底层基础设施。理解发音不是靠 "跟读"，而是靠理解语音系统的规则。

### Dr Geoff Lindsey (YouTube)

UCL 语音学讲师。频道不是 "跟我读 ABC" 的教学，而是从语言学角度分析英语发音的实际演变。比如他会讲为什么词典里的音标已经过时了、为什么现代英国人的发音和 RP 不一样了。

对安全研究者来说，这就像是 **从规范到实现的 diff** —— 标准写的是一回事，实际跑起来是另一回事。

- YouTube: `Dr Geoff Lindsey`
- 推荐看他关于 TRAP-BATH split、GOAT vowel、happY tensing 的视频

### English After RP (书)

Geoff Lindsey 的书，分析当代英式英语发音相比传统 RP (Received Pronunciation) 的变化。

相当于语音学领域的 **changelog** —— 记录了从 "标准" 到 "实际" 的所有 breaking changes。

### CUBE Dictionary

- 网址: `cubedictionary.org`
- Geoff Lindsey 做的在线发音词典
- 反映的是**当代实际发音**而不是过时的词典标注
- 类比：其他词典是 spec，CUBE 是 implementation

### Peter Roach — English Phonetics and Phonology: A Practical Course

经典教材。如果你想系统地搞懂音标体系和语音规则，这本是标准参考。

适合从零建立完整的语音学 mental model。

### Peter Ladefoged — A Course in Phonetics

更偏通用语音学，讲人类语音的物理原理。

类比：如果 Roach 的书是 **应用层协议**，Ladefoged 的书就是 **物理层** —— 讲声带振动、气流动力学、共振腔形状这些硬件级别的东西。

---

## 0x01 语言学入门

> 理解 "语言" 这个系统本身的架构。从音韵到句法到语义，建立全栈认知。

### Essentials of Linguistics (开源教材)

- 免费在线阅读
- 从音韵到句法到语义都覆盖了
- 适合快速建立语言学的整体框架
- 类比：语言学的 **Architecture Overview**，先搞清楚各个子系统的职责和边界

### Because Internet — Gretchen McCulloch

讲互联网语言学的书，分析 emoji、缩写、网络用语怎么改变英语。

天天泡在英文互联网上的人读这本会很有共鸣 —— 你每天用的 "lol"、"tbh"、"ngl" 背后其实有语言学规律。

---

## 0x02 沉浸输入

> 不是 "教你英语"，而是 **用英语做有趣的事**。完全跳过 "English teacher" 类频道。

### YouTube 内容频道

直接看 native speakers 做的内容频道，而不是教英语的频道：

| 频道 | 类型 | 为什么推荐 |
|------|------|------------|
| **Tom Scott** | 语言 / 科技 / 地理 | 短视频，英语清晰，信息密度高 |
| **Veritasium** | 科普 | 表达方式非常好，适合学怎么用英语讲清楚复杂概念 |

### 播客

| 播客 | 领域 | 特点 |
|------|------|------|
| **Darknet Diaries** | 信息安全 | 讲真实的黑客故事，语言非常口语化，内容直接对口 |
| **Risky Business** | 信息安全新闻 | 澳洲口音，适合习惯不同英语变体 |

::: info 为什么要听不同口音？
英语不是一种语言，是一个**语言族**。美式、英式、澳式、印式英语差异巨大。只听标准美式等于只在 x86 上测试 —— 到了 ARM 环境就傻了。
:::

---

## 0x03 写作与表达

> 输出是最好的学习方式。但不要从零开始写，先从模仿开始。

### YouGlish

- 网址: `youglish.com`
- 输入任何英文词或短语，它会从 YouTube 视频中找到 native speaker 实际使用这个词的片段
- 比词典好用太多，因为你能看到**真实语境**中的用法
- 类比：词典是 API 文档，YouGlish 是 **实际调用示例**

### 模仿安全社区的写作风格

最高效的英语写作学习方式：

1. **找到你喜欢的英文安全博主** — 读他们的 blog posts、conference talk transcripts
2. **注意他们怎么组织论点** — 如何开头、如何过渡、如何收尾
3. **注意他们的语气** — 技术写作中的非正式语气怎么把握
4. **模仿着写** — 先抄结构，再换内容，最后形成自己的风格

::: tip 写作的 "逆向工程" 方法
把一篇你觉得写得好的英文博客当成一个 binary：
- 先看整体结构 (sections, flow)
- 再看句子级别的模式 (how they transition, hedge, emphasize)
- 最后看词汇选择 (informal vs formal, jargon usage)

这和逆向一个程序的思路完全一样。
:::

---

## 0x04 工具箱

| 工具 | 用途 | 说明 |
|------|------|------|
| **CUBE Dictionary** | 查发音 | 当代实际发音，不是过时标注 |
| **YouGlish** | 查用法 | 真实语境中的词句使用 |
| **Essentials of Linguistics** | 查概念 | 语言学基础概念参考 |

---

## 参考资源汇总

### 书籍

| 书名 | 作者 | 领域 |
|------|------|------|
| English After RP | Geoff Lindsey | 当代英式发音变迁 |
| English Phonetics and Phonology | Peter Roach | 语音学系统教材 |
| A Course in Phonetics | Peter Ladefoged | 通用语音学 (物理层) |
| Essentials of Linguistics | (开源) | 语言学全栈入门 |
| Because Internet | Gretchen McCulloch | 互联网语言学 |

### 视频 / 播客

| 名称 | 类型 | 领域 |
|------|------|------|
| Dr Geoff Lindsey | YouTube | 语音学分析 |
| Tom Scott | YouTube | 语言 / 科技 / 地理 |
| Veritasium | YouTube | 科普表达 |
| Darknet Diaries | 播客 | 信息安全故事 |
| Risky Business | 播客 | 信息安全新闻 |

### 在线工具

| 名称 | 用途 |
|------|------|
| CUBE Dictionary (`cubedictionary.org`) | 当代发音词典 |
| YouGlish (`youglish.com`) | 真实语境用法查询 |
