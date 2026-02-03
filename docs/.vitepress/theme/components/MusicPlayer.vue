<template>
  <button 
    class="music-toggle" 
    @click="togglePlay" 
    :title="isPlaying ? 'Pause BGM' : 'Play BGM'"
    :class="{ playing: isPlaying }"
  >
    <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
      <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
    </svg>
  </button>
</template>

<script setup lang="ts">
import { ref, onUnmounted } from 'vue'

const props = withDefaults(defineProps<{
  src?: string
  volume?: number
}>(), {
  src: '/audio/bgm.mp3',
  volume: 0.3
})

const isPlaying = ref(false)
let audio: HTMLAudioElement | null = null

const togglePlay = () => {
  if (!audio) {
    audio = new Audio(props.src)
    audio.loop = true
    audio.volume = props.volume
  }
  
  if (isPlaying.value) {
    audio.pause()
  } else {
    audio.play().catch(e => console.warn('Audio playback failed:', e))
  }
  isPlaying.value = !isPlaying.value
}

onUnmounted(() => {
  if (audio) {
    audio.pause()
    audio = null
  }
})
</script>

<style scoped>
.music-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border: none;
  background: transparent;
  color: var(--vp-c-text-2);
  cursor: pointer;
  border-radius: 8px;
  transition: color 0.25s, background 0.25s;
}

.music-toggle:hover {
  color: var(--vp-c-text-1);
  background: var(--vp-c-default-soft);
}

.music-toggle.playing {
  color: var(--vp-c-brand-1);
}

.music-toggle.playing svg {
  animation: pulse 1s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
</style>

<style>
/* 调整导航栏元素顺序：把音乐按钮放到日夜切换和社交链接之间 */
.VPNavBar .content-body {
  display: flex;
  align-items: center;
}

/* 社交链接放到最后 */
.VPNavBar .VPNavBarSocialLinks {
  order: 100;
}

/* 音乐按钮放到社交链接前面（日夜切换后面） */
.VPNavBar .content-body > div:has(.music-toggle) {
  order: 50;
  margin: 0 4px;
}
</style>
