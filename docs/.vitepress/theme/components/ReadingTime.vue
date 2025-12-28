<template>
  <div v-if="show" class="reading-time">
    <span class="reading-time-item">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
        <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
      </svg>
      {{ wordCount }} 字
    </span>
    <span class="reading-time-item">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <polyline points="12 6 12 12 16 14"></polyline>
      </svg>
      {{ readingTime }} 分钟
    </span>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useData, useRoute } from 'vitepress'

const { page } = useData()
const route = useRoute()

const wordCount = ref(0)
const readingTime = ref(0)
const show = ref(false)

function calculateReadingTime() {
  // 只在文章页面显示（排除首页、工具页等）
  const path = route.path
  if (path === '/' || path.includes('/tools/') || path.includes('/links/') || path.includes('/whoami/')) {
    show.value = false
    return
  }
  
  // 获取文章内容
  const content = document.querySelector('.vp-doc')
  if (!content) {
    show.value = false
    return
  }
  
  // 提取纯文本
  const text = content.textContent || ''
  
  // 计算字数（中文 + 英文单词）
  const chineseChars = (text.match(/[\u4e00-\u9fa5]/g) || []).length
  const englishWords = (text.match(/[a-zA-Z]+/g) || []).length
  const total = chineseChars + englishWords
  
  wordCount.value = total
  // 中文阅读速度约 300-500 字/分钟，取 400
  readingTime.value = Math.max(1, Math.ceil(total / 400))
  show.value = total > 100  // 少于100字不显示
}

onMounted(() => {
  setTimeout(calculateReadingTime, 100)
})

watch(() => route.path, () => {
  setTimeout(calculateReadingTime, 100)
})
</script>

<style scoped>
.reading-time {
  display: flex;
  gap: 1rem;
  font-size: 0.875rem;
  color: var(--vp-c-text-2);
  margin-bottom: 1rem;
}

.reading-time-item {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.reading-time-item svg {
  opacity: 0.7;
}
</style>
