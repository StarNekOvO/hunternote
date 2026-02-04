<template>
  <div class="friend-card" @mouseenter="isHovered = true" @mouseleave="isHovered = false">
    <a :href="link" target="_blank" rel="noopener noreferrer">
      <!-- 彩色光环头像 -->
      <div class="avatar-container">
        <div class="avatar-ring"></div>
        <img :src="avatar" :alt="name" class="avatar" loading="lazy" @error="onAvatarError" />
      </div>
      
      <!-- 信息区 -->
      <div class="info">
        <div class="name">{{ name }}</div>
        <div class="url">{{ displayUrl }}</div>
        <div v-if="desc" class="desc">{{ desc }}</div>
      </div>
      
      <!-- 社交图标 -->
      <div v-if="socialLinks && socialLinks.length" class="social-links">
        <a 
          v-for="social in socialLinks" 
          :key="social.url" 
          :href="social.url" 
          target="_blank" 
          rel="noopener noreferrer"
          :title="social.name"
          @click.stop
        >
          <component :is="getIcon(social.type)" class="social-icon" />
        </a>
      </div>
    </a>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, h } from 'vue'

const props = defineProps<{
  name: string
  link: string
  avatar: string
  desc?: string
  socialLinks?: Array<{ type: string; url: string; name: string }>
}>()

const isHovered = ref(false)

const displayUrl = computed(() => {
  try {
    const url = new URL(props.link)
    return url.hostname.replace('www.', '')
  } catch {
    return props.link
  }
})

const onAvatarError = (e: Event) => {
  const img = e.target as HTMLImageElement
  img.src = `https://www.google.com/s2/favicons?sz=128&domain=${props.link}`
}

// 图标组件
const GithubIcon = () => h('svg', { viewBox: '0 0 24 24', fill: 'currentColor' }, [
  h('path', { d: 'M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z' })
])

const TwitterIcon = () => h('svg', { viewBox: '0 0 24 24', fill: 'currentColor' }, [
  h('path', { d: 'M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z' })
])

const TelegramIcon = () => h('svg', { viewBox: '0 0 24 24', fill: 'currentColor' }, [
  h('path', { d: 'M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z' })
])

const BilibiliIcon = () => h('svg', { viewBox: '0 0 24 24', fill: 'currentColor' }, [
  h('path', { d: 'M17.813 4.653h.854c1.51.054 2.769.578 3.773 1.574 1.004.995 1.524 2.249 1.56 3.76v7.36c-.036 1.51-.556 2.769-1.56 3.773s-2.262 1.524-3.773 1.56H5.333c-1.51-.036-2.769-.556-3.773-1.56S.036 18.858 0 17.347v-7.36c.036-1.511.556-2.765 1.56-3.76 1.004-.996 2.262-1.52 3.773-1.574h.774l-1.174-1.12a1.234 1.234 0 0 1-.373-.906c0-.356.124-.659.373-.907l.027-.027c.267-.249.573-.373.92-.373.347 0 .653.124.92.373L9.653 4.44c.071.071.134.142.187.213h4.267a.836.836 0 0 1 .16-.213l2.853-2.747c.267-.249.573-.373.92-.373.347 0 .662.151.929.4.267.249.391.551.391.907 0 .355-.124.657-.373.906zM5.333 7.24c-.746.018-1.373.276-1.88.773-.506.498-.769 1.13-.786 1.894v7.52c.017.764.28 1.395.786 1.893.507.498 1.134.756 1.88.773h13.334c.746-.017 1.373-.275 1.88-.773.506-.498.769-1.129.786-1.893v-7.52c-.017-.765-.28-1.396-.786-1.894-.507-.497-1.134-.755-1.88-.773zM8 11.107c.373 0 .684.124.933.373.25.249.383.569.4.96v1.173c-.017.391-.15.711-.4.96-.249.25-.56.374-.933.374s-.684-.125-.933-.374c-.25-.249-.383-.569-.4-.96V12.44c0-.373.129-.689.386-.947.258-.257.574-.386.947-.386zm8 0c.373 0 .684.124.933.373.25.249.383.569.4.96v1.173c-.017.391-.15.711-.4.96-.249.25-.56.374-.933.374s-.684-.125-.933-.374c-.25-.249-.383-.569-.4-.96V12.44c.017-.391.15-.711.4-.96.249-.249.56-.373.933-.373z' })
])

const RssIcon = () => h('svg', { viewBox: '0 0 24 24', fill: 'currentColor' }, [
  h('path', { d: 'M6.18 15.64a2.18 2.18 0 0 1 2.18 2.18C8.36 19 7.38 20 6.18 20C5 20 4 19 4 17.82a2.18 2.18 0 0 1 2.18-2.18M4 4.44A15.56 15.56 0 0 1 19.56 20h-2.83A12.73 12.73 0 0 0 4 7.27V4.44m0 5.66a9.9 9.9 0 0 1 9.9 9.9h-2.83A7.07 7.07 0 0 0 4 12.93V10.1Z' })
])

const ZhihuIcon = () => h('img', { 
  src: 'https://jsd.gymxbl.com/gh/moezx/cdn@3.1.9/img/Sakura/images/sns/zhihu.png',
  alt: 'Zhihu',
  style: 'width: 18px; height: 18px;'
})

const getIcon = (type: string) => {
  const icons: Record<string, any> = {
    github: GithubIcon,
    twitter: TwitterIcon,
    x: TwitterIcon,
    telegram: TelegramIcon,
    bilibili: BilibiliIcon,
    rss: RssIcon,
    zhihu: ZhihuIcon,
  }
  return icons[type.toLowerCase()] || GithubIcon
}
</script>

<style scoped>
.friend-card {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.7), rgba(240, 248, 255, 0.6));
  backdrop-filter: blur(24px) saturate(180%);
  -webkit-backdrop-filter: blur(24px) saturate(180%);
  border-radius: 20px;
  padding: 1.5rem;
  padding-top: 3.5rem;
  position: relative;
  margin-top: 40px;
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  box-shadow: 
    0 8px 32px rgba(0, 0, 0, 0.1),
    0 0 0 1px rgba(255, 255, 255, 0.4) inset;
}

:root.dark .friend-card {
  background: linear-gradient(135deg, rgba(30, 30, 50, 0.7), rgba(40, 35, 60, 0.6));
  box-shadow: 
    0 8px 32px rgba(0, 0, 0, 0.4),
    0 0 0 1px rgba(255, 255, 255, 0.08) inset;
}

.friend-card:hover {
  transform: translateY(-8px) scale(1.02);
  box-shadow: 
    0 20px 40px rgba(0, 0, 0, 0.15),
    0 0 30px rgba(102, 126, 234, 0.2);
}

:root.dark .friend-card:hover {
  box-shadow: 
    0 20px 40px rgba(0, 0, 0, 0.4),
    0 0 30px rgba(102, 126, 234, 0.3);
}

.friend-card a {
  text-decoration: none;
  color: inherit;
  display: flex;
  flex-direction: column;
  align-items: center;
}

/* 头像容器 */
.avatar-container {
  position: absolute;
  top: -40px;
  left: 50%;
  transform: translateX(-50%);
  width: 80px;
  height: 80px;
}

/* 彩色光环 */
.avatar-ring {
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  background: conic-gradient(
    from 0deg,
    #7dd3fc,
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
  animation: ring-rotate 4s linear infinite;
  box-shadow: 
    0 0 15px rgba(96, 165, 250, 0.4),
    0 0 30px rgba(244, 114, 182, 0.2);
}

@keyframes ring-rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.avatar {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  object-fit: cover;
  z-index: 1;
  transition: transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.friend-card:hover .avatar {
  transform: scale(1.08) rotate(5deg);
}

/* 信息区 */
.info {
  text-align: center;
  width: 100%;
}

.name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #1a1a1a;
  margin-bottom: 0.25rem;
  transition: all 0.3s ease;
}

:root.dark .name {
  color: #f0f0f0;
}

.friend-card:hover .name {
  background: linear-gradient(135deg, #667eea, #764ba2, #f093fb);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.url {
  font-size: 0.85rem;
  color: #888;
  margin-bottom: 0.5rem;
}

:root.dark .url {
  color: #777;
}

.desc {
  font-size: 0.9rem;
  color: #555;
  line-height: 1.5;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

:root.dark .desc {
  color: #aaa;
}

/* 社交链接 */
.social-links {
  display: flex;
  gap: 0.8rem;
  margin-top: 1rem;
}

.social-links a {
  color: #666;
  transition: all 0.25s ease;
  padding: 4px;
  border-radius: 6px;
}

.social-links a:hover {
  color: #333;
  background: rgba(0, 0, 0, 0.05);
  transform: translateY(-2px);
}

:root.dark .social-links a {
  color: #999;
}

:root.dark .social-links a:hover {
  color: #fff;
  background: rgba(255, 255, 255, 0.1);
}

.social-icon {
  width: 18px;
  height: 18px;
}
</style>
