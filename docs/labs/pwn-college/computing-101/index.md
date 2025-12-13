# Computing 101 💻

**这个页面几乎是AI写的**

**虽然是后端工程师, 但是偏向用高级语言开发, 而汇编和 GDB 我都不太熟悉, 所以这个模块需要认真学习**


## 模块概述

Computing 101 是 pwn.college 平台的计算基础模块，从编程入门到汇编语言、调试和系统编程的全面学习路径。通过动手实践建立底层计算和系统交互的扎实基础

## 模块列表

### 编程入门
- **Your First Program** (5 个挑战) - 编写和运行第一个程序
- **Software Introspection** (3 个挑战) - 软件程序分析和理解

### 计算机基础
- **Computer Memory** (8 个挑战) - 计算机内存工作原理
- **Hello Hackers** (4 个挑战) - 平台熟悉和基础操作

### 汇编和调试
- **Assembly Crash Course** (30 个挑战) - x86_64 汇编语言快速入门
- **Debugging Refresher** (8 个挑战) - 调试技巧复习和实践

### 应用开发
- **Building a Web Server** (11 个挑战) - 构建基础 Web 服务器

## Assembly Crash Course 详细内容

作为模块的核心，Assembly Crash Course 包含30个挑战，涵盖：

### 基础汇编操作
- 寄存器操作和数据移动 (`mov` 指令)
- 算术和逻辑运算
- 内存访问和寻址模式

### 系统调用实践
- 系统调用号设置和 `syscall` 指令
- 常用系统调用：`exit`、`write`、`read`
- 系统调用参数传递约定

### 程序构建流程
- 使用 `as` (汇编器) 将汇编代码转换为目标文件
- 使用 `ld` (链接器) 创建可执行文件
- 链接脚本和可执行文件格式理解
