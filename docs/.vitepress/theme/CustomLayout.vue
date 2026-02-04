<template>
  <div class="custom-layout" :class="{ 'no-blur': isHome || isLinks }">
    <!-- Global background -->
    <div class="global-bg">
      <div class="global-bg-img" aria-hidden="true"></div>
      <div class="global-bg-overlay"></div>
    </div>
    
    <!-- Homepage: BA Hero with navbar -->
    <template v-if="isHome">
      <Layout>
        <template #nav-bar-content-after>
          <ClientOnly>
            <MusicPlayer />
          </ClientOnly>
        </template>
        <template #home-hero-before>
          <ClientOnly>
            <BAHero />
          </ClientOnly>
        </template>
        <template #home-hero-info><span></span></template>
        <template #home-hero-image><span></span></template>
        <template #home-hero-actions><span></span></template>
        <template #home-features-before><span></span></template>
        <template #home-features-after><span></span></template>
      </Layout>
    </template>

    <!-- Links page: custom full-width layout -->
    <template v-else-if="isLinks">
      <Layout>
        <template #nav-bar-content-after>
          <ClientOnly>
            <MusicPlayer />
          </ClientOnly>
        </template>
        <template #home-hero-before>
          <ClientOnly>
            <LinksPage />
          </ClientOnly>
        </template>
        <template #home-hero-info><span></span></template>
        <template #home-hero-image><span></span></template>
        <template #home-hero-actions><span></span></template>
        <template #home-features-before><span></span></template>
        <template #home-features-after><span></span></template>
      </Layout>
    </template>
    
    <!-- Other pages: use default Layout -->
    <Layout v-else>
      <template #doc-before>
        <ReadingTime />
      </template>
    </Layout>
    
    <!-- Global effects -->
    <ClientOnly>
      <Splash v-if="showSplash" />
      <Fireworks />
    </ClientOnly>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import DefaultTheme from 'vitepress/theme'
import { useData, useRoute } from 'vitepress'
import ReadingTime from './components/ReadingTime.vue'
import BAHero from './components/BAHero.vue'
import Splash from './components/Splash.vue'
import Fireworks from './components/Fireworks.vue'
import MusicPlayer from './components/MusicPlayer.vue'
import LinksPage from './components/LinksPage.vue'

const { Layout } = DefaultTheme
const { frontmatter } = useData()
const route = useRoute()

const isHome = computed(() => frontmatter.value.layout === 'home' && !route.path.includes('/links'))
const isLinks = computed(() => frontmatter.value.layout === 'home' && route.path.includes('/links'))

// 只在首次访问首页时显示 Splash
const showSplash = ref(false)

onMounted(() => {
  if (isHome.value && !sessionStorage.getItem('splashShown')) {
    showSplash.value = true
    sessionStorage.setItem('splashShown', 'true')
  }
})
</script>

<style>
/* Global background for all pages */
.custom-layout {
  position: relative;
  min-height: 100vh;
}

.global-bg {
  position: fixed;
  inset: 0;
  z-index: -10;
  background: linear-gradient(135deg, #e8f4fc 0%, #f0e6fa 50%, #fce4ec 100%);
}

:root.dark .global-bg {
  background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #172554 100%);
}

.global-bg-img {
  position: absolute;
  inset: 0;
  background-image: url('/img/banner-light.webp');
  background-size: cover;
  background-position: center;
  background-repeat: no-repeat;
  width: 100%;
  height: 100%;
}

:root.dark .global-bg-img {
  background-image: url('/img/banner-dark.webp');
}

.global-bg-overlay {
  position: absolute;
  inset: 0;
  background: rgba(255, 255, 255, 0.3);
  backdrop-filter: blur(8px);
}

:root.dark .global-bg-overlay {
  background: rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(8px);
}

/* 首页和友链页不要全局模糊 */
.no-blur .global-bg-overlay {
  background: transparent;
  backdrop-filter: none;
}

:root.dark .no-blur .global-bg-overlay {
  background: transparent;
  backdrop-filter: none;
}

/* Make VitePress components transparent */
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
.VPDocAsideCarbonAds {
  background: transparent !important;
  background-color: transparent !important;
}

/* Content area transparent */
.VPDoc .container {
  background: transparent !important;
}

:root.dark .VPDoc .container {
  background: transparent !important;
}

/* Sidebar transparent on desktop */
.VPSidebar {
  background: transparent !important;
  border-right: none !important;
}

:root.dark .VPSidebar {
  background: transparent !important;
  border-right: none !important;
}

/* Mobile sidebar needs solid background for readability */
@media (max-width: 959px) {
  .VPSidebar {
    background: rgba(255, 255, 255, 0.95) !important;
    backdrop-filter: blur(12px) !important;
  }
  
  :root.dark .VPSidebar {
    background: rgba(30, 30, 40, 0.95) !important;
    backdrop-filter: blur(12px) !important;
  }
}

/* Navbar transparent */
.VPNavBar,
.VPNavBar.has-sidebar {
  background: transparent !important;
  border-bottom: none !important;
}

:root.dark .VPNavBar,
:root.dark .VPNavBar.has-sidebar {
  background: transparent !important;
  border-bottom: none !important;
}

/* Remove all borders */
.VPNavBar .divider,
.VPNavBar .divider-line {
  background: transparent !important;
}

.VPSidebar .curtain {
  background: transparent !important;
}

.aside-curtain {
  display: none !important;
}

/* LocalNav (small screens) transparent */
.VPLocalNav,
.VPLocalNav.has-sidebar {
  background: transparent !important;
  border-bottom: none !important;
}

/* Sidebar and outline text contrast */
.VPSidebar .text,
.VPSidebar .link,
.VPSidebar .item .text,
.VPDocAsideOutline .outline-link {
  color: rgba(0, 0, 0, 0.85) !important;
}

.VPSidebarItem.is-active .text,
.VPDocAsideOutline .outline-link.active {
  color: rgba(0, 0, 0, 0.95) !important;
}

:root.dark .VPSidebar .text,
:root.dark .VPSidebar .link,
:root.dark .VPSidebar .item .text,
:root.dark .VPDocAsideOutline .outline-link {
  color: rgba(255, 255, 255, 0.85) !important;
}

:root.dark .VPSidebarItem.is-active .text,
:root.dark .VPDocAsideOutline .outline-link.active {
  color: rgba(255, 255, 255, 0.95) !important;
}

/* 搜索按钮透明 */
@media (min-width: 768px) {
  .DocSearch-Button {
    background: rgba(255, 255, 255, 0.5) !important;
    backdrop-filter: blur(8px) !important;
  }
  
  .DocSearch-Button:hover {
    background: rgba(255, 255, 255, 0.6) !important;
  }
}

:root.dark .DocSearch-Button {
  background: rgba(0, 0, 0, 0.4) !important;
}

:root.dark .DocSearch-Button:hover {
  background: rgba(0, 0, 0, 0.5) !important;
}

/* 隐藏首页所有默认内容 */
.VPHome .VPHero,
.VPHome .VPFeatures,
.VPHome .VPHomeContent,
.VPHome .VPHomeHero,
.VPHome > .vp-doc {
  display: none !important;
}

/* 首页 footer 透明 - footer 是 VPHome 的兄弟元素 */
.VPContent:has(.VPHome) ~ .VPFooter {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 8px 16px !important;
  background: transparent !important;
  border: none !important;
  font-size: 11px;
  z-index: 10;
}

.VPContent:has(.VPHome) ~ .VPFooter,
.VPContent:has(.VPHome) ~ .VPFooter a,
.VPContent:has(.VPHome) ~ .VPFooter p {
  color: rgba(255, 255, 255, 0.6) !important;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
}

.VPContent:has(.VPHome) ~ .VPFooter a:hover {
  color: rgba(255, 255, 255, 0.9) !important;
}

/* 首页导航透明 */
.VPHome .VPNav {
  background: transparent !important;
}
</style>
