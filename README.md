# 牛奶猫的猎人笔记

基于 VitePress 构建的个人博客，部署在 GitHub Pages。

## 项目结构

```
hunternote-blog/
├── docs/                    # 文档目录
│   ├── .vitepress/         # VitePress 配置
│   │   └── config.ts       # 配置文件
│   ├── public/             # 静态资源目录
│   │   └── img/            # 图片资源
│   ├── ctfs/               # CTF 相关文章
│   ├── cves/               # CVE 相关文章
│   ├── labs/               # 实验相关文章
│   ├── file/               # 文件资源
│   ├── index.md            # 首页
│   └── whoami/             # whoami 页面
├── .github/
│   └── workflows/
│       └── deploy.yml      # GitHub Actions 部署工作流
├── package.json
└── README.md
```

## 开发命令

```bash
# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览构建结果
npm run preview
```

## 部署

项目使用 GitHub Actions 自动部署到 GitHub Pages：

- **触发条件**：推送到 `main` 分支
- **部署地址**：https://starneko.com
- **工作流文件**：`.github/workflows/deploy.yml`

### 部署配置

1. 在 GitHub 仓库设置中启用 Pages，选择 "GitHub Actions" 作为源
2. 配置自定义域名（如需要）
3. 每次推送到 `main` 分支会自动触发部署

## 配置说明

配置文件位于 `docs/.vitepress/config.ts`，包含：
- 站点基本信息（标题、描述等）
- 导航栏配置
- 侧边栏配置
- 搜索功能
- SEO 元数据
- 自定义域名配置（`base: '/'`）

## 静态资源

静态资源（图片、文件等）应放在 `docs/public/` 目录下，构建时会被复制到输出根目录。

**注意**：在 Markdown 和配置文件中引用静态资源时，使用绝对路径，如 `/img/Milk.jpg`。

