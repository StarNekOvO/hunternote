# 御坂晚的笨蛋笔记

[![Deploy](https://img.shields.io/badge/deploy-GitHub%20Pages-blue)](https://starneko.com)
[![VitePress](https://img.shields.io/badge/VitePress-1.6.4-brightgreen)](https://vitepress.dev)
[![Rust](https://img.shields.io/badge/Rust-WASM-orange)](https://www.rust-lang.org/)

基于 VitePress 构建的个人系统安全研究博客，专注于 CTF、PWN、漏洞利用等领域的学习笔记与 Writeup

**在线地址**：[https://starneko.com](https://starneko.com)

## 项目结构

```
hunternote/
├── docs/
│   ├── .vitepress/         # VitePress 配置
│   │   ├── theme/          # 自定义主题
│   │   │   ├── components/ # Vue 组件
│   │   │   │   ├── BAHero.vue        # 首页 Hero（毛玻璃卡片、打字特效）
│   │   │   │   ├── LinksPage.vue     # 友链页（carousel/grid 双视图）
│   │   │   │   ├── FriendCard.vue    # 友链卡片（彩虹光环头像）
│   │   │   │   ├── FriendsCarousel.vue # 友链滚动轮播
│   │   │   │   ├── Splash.vue        # 加载动画
│   │   │   │   ├── Fireworks.vue     # 点击烟花特效
│   │   │   │   ├── MusicPlayer.vue   # BGM 播放器
│   │   │   │   └── ...
│   │   │   └── wasm-loader.ts
│   │   └── wasm/           # wasm-pack 输出 (构建生成)
│   ├── public/             # 静态资源
│   │   ├── audio/          # BGM 音频
│   │   └── img/            # 图片资源
│   ├── ctfs/               # CTF 平台 Writeup
│   │   ├── buuctf/
│   │   ├── ctfshow/
│   │   │   └── pwnvip360/  # PWN VIP 360 课程
│   │   └── nssctf/
│   ├── labs/               # 实战平台 Writeup
│   │   ├── htb-academy/
│   │   ├── htb-lab/
│   │   └── pwn-college/
│   ├── cves/               # CVE 漏洞复现
│   │   └── vendor/         # 漏洞库
│   ├── notes/              # 技术学习笔记
│   │   └── android/        # Android 安全
│   ├── tools/              # 在线工具
│   ├── links/              # 友情链接
│   └── whoami/             # 关于作者
├── wasm-tools/             # Rust WebAssembly 源码
│   ├── Cargo.toml
│   └── src/lib.rs
├── .github/workflows/      # GitHub Actions
├── package.json
└── README.md
```

## 功能特性

### 主题效果
- **首页 Hero** - Blue Archive 风格毛玻璃卡片、3D 视差、打字机特效
- **友链页** - 双视图模式（桌面端滚动轮播、移动端卡片网格）、彩虹光环头像
- **加载动画** - BA 风格 Splash 呼吸动画
- **点击烟花** - 全局点击粒子特效
- **BGM 播放器** - 导航栏音乐控制
- **深色模式** - 完整的亮/暗主题支持
- **背景分层** - 首页/友链页清晰背景，文档页毛玻璃背景

### 技术工具
- **Rust + WebAssembly** 在线工具（Hash、编码、进制转换、时间戳、PWN 辅助、正则、IP/CIDR）
- 自动部署到 GitHub Pages
- 本地搜索功能
- 响应式设计
- SEO 优化

## 快速开始

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览构建结果
npm run preview
```

### 修改 WASM 工具（可选）

如需修改 Rust 代码，需要安装 Rust 工具链：

```bash
# 安装 Rust (通过 rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 添加 wasm target
rustup target add wasm32-unknown-unknown

# 安装 wasm-pack
cargo install wasm-pack

# 构建 WASM
npm run build:wasm
```

## 部署

项目使用 GitHub Actions 自动部署到 GitHub Pages。推送到 `main` 分支会自动触发部署

WASM 文件已预编译并提交到仓库，CI 只需运行 `npm run build`

## 更换头像/Favicon

将新头像图片（推荐 1024x1024 正方形）放入 `docs/public/img/` 目录，然后运行：

```bash
IMG=xxxxx.jpg && cd docs/public && \
magick img/$IMG -resize 16x16 favicon-16x16.png && \
magick img/$IMG -resize 32x32 favicon-32x32.png && \
magick img/$IMG -resize 180x180 apple-touch-icon.png && \
magick img/$IMG -resize 192x192 android-chrome-192x192.png && \
magick img/$IMG -resize 512x512 android-chrome-512x512.png && \
magick img/$IMG -define icon:auto-resize=48,32,16 favicon.ico && \
echo "Icons generated!"
```

然后更新以下文件中的图片路径：

| 文件 | 需要更新的字段 |
|------|---------------|
| `docs/.vitepress/config.ts` | `themeConfig.logo`, `og:image`, `twitter:image`, JSON-LD `image` |
| `docs/index.md` | `hero.image.src` |

## 在线工具

基于 Rust 编译为 WebAssembly，在浏览器中高性能运行：

| 工具 | 功能 | 实现 |
|------|------|------|
| Hash 计算 | MD5、SHA1、SHA256、SHA512 | Rust |
| 编码转换 | Base64、Hex、URL、HTML | Rust + JS |
| 进制转换 | 二进制、八进制、十进制、十六进制 | Rust |
| 时间戳 | Unix 时间戳与日期互转 | Rust |
| PWN 辅助 | 大小端、地址计算、字符串生成 | Rust |
| 正则测试 | 正则表达式在线测试 | JavaScript |
| IP/CIDR | 子网计算、IP 格式转换 | Rust |

## 内容分类

### CTF 平台
- **BUUCTF** - 北京联合大学 CTF 练习平台
- **CTFshow** - PWN VIP 360 系统化课程（360 个靶场）
- **NSSCTF** - 综合性 CTF 平台，CVE 复现、AI 安全

### 实战平台
- **HTB Academy** - 结构化网络安全学习平台
- **HTB Lab** - 渗透测试实战平台
- **pwn.college** - ASU 系统安全学习平台（腰带系统）

### 其他
- **Notes** - 技术学习笔记与研究总结（Android 安全等）
- **CVEs** - 漏洞复现、POC、EXP
- **Tools** - 在线安全工具集
- **Links** - 友情链接
- **Whoami** - 关于作者

## License

[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) - Creative Commons Attribution-NonCommercial 4.0 International

本作品采用知识共享署名-非商业性使用 4.0 国际许可协议进行许可
