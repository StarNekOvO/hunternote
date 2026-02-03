# VitePress 样式定制指南

本文档记录了 hunternote 主题中所有自定义样式的位置和作用，方便后续修改。

## 文件位置

主要样式文件：
- `docs/.vitepress/theme/CustomLayout.vue` - 全局布局和背景样式
- `docs/public/custom.css` - 通用自定义样式（头像、logo、工具徽章等）

## CustomLayout.vue 样式结构

### 1. 全局背景 (Global Background)

```css
.custom-layout { }      /* 根容器 */
.global-bg { }          /* 背景容器，fixed 定位 */
.global-bg-img { }      /* 背景图片 */
.global-bg-overlay { }  /* 背景遮罩层（模糊效果） */
```

**配置项：**
- 背景图片：`/img/banner-light.webp` 和 `/img/banner-dark.webp`
- 遮罩透明度：`.global-bg-overlay` 的 `background: rgba()`
- 模糊程度：`backdrop-filter: blur(Xpx)`

### 2. VitePress 组件透明化

```css
/* 需要透明化的组件 */
.VPNav,
.VPNavBar,
.VPSidebar,
.VPContent,
.VPDoc,
.VPFooter,
.vp-doc,
.main,
.VPDocAside,
.VPDocAsideOutline,
.aside,
.aside-container,
.aside-content,
.content,
.content-body,
.content-container,
.VPDocAsideCarbonAds
```

**作用：** 将所有 VitePress 默认组件背景设为透明

### 3. 内容区域样式

```css
.VPDoc .container { }   /* 文档内容容器 */
```

**可配置：**
- `background` - 背景色/透明度
- `backdrop-filter` - 毛玻璃效果
- `border-radius` - 圆角
- `box-shadow` - 阴影

### 4. 侧边栏样式

```css
.VPSidebar { }          /* 左侧导航栏 */
.VPSidebar .curtain { } /* 侧边栏遮罩 */
```

### 5. 导航栏样式

```css
.VPNavBar { }                   /* 顶部导航栏 */
.VPNavBar.has-sidebar { }       /* 有侧边栏时的导航栏 */
.VPNavBar .divider { }          /* 导航栏分隔线 */
.VPNavBar .divider-line { }     /* 导航栏分隔线 */
```

### 6. 首页特殊样式

```css
/* 隐藏默认首页内容 */
.VPHome .VPHero,
.VPHome .VPFeatures,
.VPHome .VPHomeContent,
.VPHome .VPHomeHero,
.VPHome > .vp-doc { display: none !important; }

/* 首页 footer 样式 */
.VPContent:has(.VPHome) ~ .VPFooter { }

/* 首页导航透明 */
.VPHome .VPNav { }
```

## 常见修改场景

### 场景 1：修改背景透明度

修改 `.global-bg-overlay`：
```css
/* 亮色模式 */
.global-bg-overlay {
  background: rgba(255, 255, 255, 0.3);  /* 调整最后一个值 0-1 */
  backdrop-filter: blur(8px);             /* 调整模糊程度 */
}

/* 暗色模式 */
:root.dark .global-bg-overlay {
  background: rgba(0, 0, 0, 0.4);
}
```

### 场景 2：添加毛玻璃效果

给任意组件添加：
```css
.component {
  background: rgba(255, 255, 255, 0.6) !important;
  backdrop-filter: blur(12px) saturate(150%);
  -webkit-backdrop-filter: blur(12px) saturate(150%);
  border-radius: 16px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
}
```

### 场景 3：完全透明

```css
.component {
  background: transparent !important;
  background-color: transparent !important;
  border: none !important;
}
```

### 场景 4：更换背景图片

在 `CustomLayout.vue` template 中修改：
```vue
<img :src="isDark ? '/img/新暗色背景.webp' : '/img/新亮色背景.webp'" ... />
```

## 组件文件列表

| 组件 | 文件路径 | 作用 |
|------|---------|------|
| BAHero | `components/BAHero.vue` | 首页 Hero 区域 |
| Splash | `components/Splash.vue` | 首次访问闪屏 |
| Fireworks | `components/Fireworks.vue` | 点击烟花效果 |
| MusicPlayer | `components/MusicPlayer.vue` | 背景音乐播放器 |
| ReadingTime | `components/ReadingTime.vue` | 阅读时间显示 |

## 注意事项

1. 使用 `!important` 覆盖 VitePress 默认样式
2. 同时处理 `:root.dark` 暗色模式
3. 使用 `-webkit-backdrop-filter` 兼容 Safari
4. 背景图片放在 `docs/public/img/` 目录

## 头像光环配色方案

### 方案 1：全彩虹（原版）
包含红、黄、青、蓝、紫色，适合热烈活泼风格。

```css
background: conic-gradient(
  from 0deg,
  #ff6b6b,  /* 红色 */
  #feca57,  /* 黄色 */
  #48dbfb,  /* 青色 */
  #54a0ff,  /* 蓝色 */
  #5f27cd,  /* 紫色 */
  #ff6b6b
);

/* 发光效果 */
box-shadow: 
  0 0 20px rgba(255, 107, 107, 0.5),
  0 0 40px rgba(254, 202, 87, 0.3),
  0 0 60px rgba(72, 219, 251, 0.2);
```

### 方案 2：青蓝紫粉（当前使用）
去掉红黄，只保留冷色调，适合清新柔和风格。

```css
background: conic-gradient(
  from 0deg,
  #48dbfb,  /* 青色 */
  #54a0ff,  /* 蓝色 */
  #a78bfa,  /* 淡紫 */
  #f472b6,  /* 粉色 */
  #48dbfb,
  #54a0ff,
  #a78bfa,
  #f472b6,
  #48dbfb
);

/* 发光效果 */
box-shadow: 
  0 0 20px rgba(72, 219, 251, 0.5),
  0 0 40px rgba(167, 139, 250, 0.4),
  0 0 60px rgba(244, 114, 182, 0.3);
```

### 方案 3：青蓝紫粉渐变（当前使用）
青色到淡紫到浅粉柔和过渡，去掉纯蓝纯粉，更加柔和细腻。

```css
background: conic-gradient(
  from 0deg,
  #7dd3fc,  /* 青色 */
  #93c5fd,  /* 浅蓝 */
  #a5b4fc,  /* 蓝紫 */
  #c4b5fd,  /* 淡紫 */
  #e9d5ff,  /* 浅紫 */
  #fce7f3,  /* 淡粉 */
  #fbcfe8,  /* 浅粉 */
  #e9d5ff,
  #c4b5fd,
  #a5b4fc,
  #93c5fd,
  #7dd3fc,
  /* 循环第二遍 */
  #93c5fd,
  #a5b4fc,
  #c4b5fd,
  #e9d5ff,
  #fce7f3,
  #fbcfe8,
  #e9d5ff,
  #c4b5fd,
  #a5b4fc,
  #93c5fd,
  #7dd3fc
);

/* 发光效果 */
box-shadow: 
  0 0 20px rgba(96, 165, 250, 0.5),
  0 0 40px rgba(255, 255, 255, 0.4),
  0 0 60px rgba(244, 114, 182, 0.3);
```

### 切换方法

修改 [BAHero.vue](components/BAHero.vue) 中的 `.info-card::before` 样式：
1. 替换 `background: conic-gradient(...)` 中的颜色
2. 替换 `box-shadow` 和 `@keyframes ssr-glow` 中的发光颜色
