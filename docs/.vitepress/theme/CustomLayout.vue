<template>
  <div>
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
import { useData } from 'vitepress'
import ReadingTime from './components/ReadingTime.vue'
import BAHero from './components/BAHero.vue'
import Splash from './components/Splash.vue'
import Fireworks from './components/Fireworks.vue'
import MusicPlayer from './components/MusicPlayer.vue'

const { Layout } = DefaultTheme
const { frontmatter } = useData()

const isHome = computed(() => frontmatter.value.layout === 'home')

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

.VPHome .VPNavBar {
  background: rgba(255, 255, 255, 0.85) !important;
  backdrop-filter: blur(12px);
}

.dark .VPHome .VPNavBar {
  background: rgba(20, 20, 35, 0.85) !important;
}
</style>
