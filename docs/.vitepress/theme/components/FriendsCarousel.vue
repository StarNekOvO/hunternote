<template>
  <div class="carousel-container" @mouseenter="pauseScroll" @mouseleave="resumeScroll">
    <div class="carousel-track" :style="{ transform: `translateX(${offset}px)` }">
      <div 
        v-for="(friend, index) in duplicatedFriends" 
        :key="`${friend.name}-${index}`"
        class="carousel-item"
      >
        <FriendCard
          :name="friend.name"
          :link="friend.link"
          :avatar="friend.avatar"
          :desc="friend.desc"
          :social-links="friend.socialLinks"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import FriendCard from './FriendCard.vue'

interface SocialLink {
  type: string
  url: string
  name: string
}

interface Friend {
  name: string
  link: string
  avatar: string
  desc?: string
  socialLinks?: SocialLink[]
}

const props = defineProps<{
  friends: Friend[]
}>()

// 复制列表以实现无缝滚动
const duplicatedFriends = computed(() => [...props.friends, ...props.friends, ...props.friends])

const offset = ref(0)
const isPaused = ref(false)
let animationId: number | null = null
const speed = 0.5 // 滚动速度

const scroll = () => {
  if (!isPaused.value) {
    offset.value -= speed
    
    // 计算单组宽度并重置 (卡片宽度 340px + gap 2rem)
    const itemWidth = 372
    const groupWidth = props.friends.length * itemWidth
    
    if (Math.abs(offset.value) >= groupWidth) {
      offset.value += groupWidth
    }
  }
  animationId = requestAnimationFrame(scroll)
}

const pauseScroll = () => {
  isPaused.value = true
}

const resumeScroll = () => {
  isPaused.value = false
}

onMounted(() => {
  animationId = requestAnimationFrame(scroll)
})

onUnmounted(() => {
  if (animationId) {
    cancelAnimationFrame(animationId)
  }
})
</script>

<style scoped>
.carousel-container {
  width: 100%;
  overflow: hidden;
  padding: 3.5rem 0 2rem;
  margin: 1rem 0;
}

.carousel-track {
  display: flex;
  gap: 2rem;
  will-change: transform;
  padding-top: 48px;
}

.carousel-item {
  flex-shrink: 0;
  width: 340px;
}

/* 禁用卡片的 hover 缩放以避免滚动时的抖动 */
.carousel-item :deep(.friend-card) {
  margin-top: 0;
}

.carousel-item :deep(.friend-card:hover) {
  transform: translateY(-8px);
}
</style>
