# English Learning

> 跳过 ESL 教学，用语言学框架理解英语，用真实内容沉浸输入，用 LLM 做交互式练习。

## 学习策略

三条线并行推进：

| 线路 | 目标 | 核心动作 |
|------|------|----------|
| **语音学** | 建立发音的底层认知 | Geoff Lindsey 频道 + 教材 |
| **沉浸输入** | 日常信息流切换为英语 | 播客 + YouTube 内容频道 |
| **写作输出** | 模仿 native speaker 的表达 | 读博客 → LLM 批改 → 迭代 |

::: tip 关键原则
不要面面俱到。不要用 "学英语" 的方式学英语，而是 **用英语做你本来就在做的事**。
:::

**资源书签** → [资源索引](/notes/english_learning/resources)

---

## 交互式 Skills

以下 4 个 Claude Code 自定义命令可以在项目目录下直接调用，用于交互式英语练习。

### `/english-review` — 写作批改

贴一段英文，返回语法纠错 → 翻译腔标注 → 词汇升级 → 整体评价。

像 code review 一样直接，不客套。

```
/english-review The vulnerability was discovered in the kernel module which allows...
```

### `/english-denativize` — 去翻译腔

贴中文原文 + 你的英文翻译，逐句对比标出翻译腔，给出更 native 的写法，并解释是哪个中文思维习惯导致的。

```
/english-denativize
中文：我们对该漏洞进行了深入分析。
英文：We performed a deep analysis on this vulnerability.
```

### `/english-reverse` — 逆向分析

贴一篇你觉得写得好的英文博客或文章片段，返回：结构骨架 → 表达手法 → 词汇特征 → 可直接复用的句式模板。

```
/english-reverse [粘贴文章内容]
```

### `/english-lesson` — Agent 主导课堂

Agent 选择安全/技术领域的英文材料，带你完成一次 10-15 分钟的互动练习。可指定方向：

```
/english-lesson writing
/english-lesson vocabulary
/english-lesson reading
```

不指定方向时 agent 自动选题。
