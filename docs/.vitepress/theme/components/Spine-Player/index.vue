<template>
  <template v-if="enabled">
    <div
      ref="playerContainer"
      class="playerContainer"
      @click="handlePlayerClick"
      @touchstart="handlePlayerClick"
    ></div>
    <transition name="fade">
      <div v-if="showDialog" class="chatdialog-container">
        <div class="chatdialog-triangle"></div>
        <div class="chatdialog">{{ currentDialog }}</div>
      </div>
    </transition>
  </template>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch, computed } from 'vue'
import { useData } from 'vitepress'
import { spine } from './spine-player.js'

const { isDark } = useData()
const spineVoiceLang = 'jp'

const spineAssets = {
  arona: {
    skelUrl: "/spine_assets/arona/arona_spr.skel",
    atlasUrl: "/spine_assets/arona/arona_spr.atlas",
    idleAnimationName: "Idle_01",
    eyeCloseAnimationName: "Eye_Close_01",
    rightEyeBone: "R_Eye_01",
    leftEyeBone: "L_Eye_01",
    frontHeadBone: "Head_01",
    backHeadBone: "Head_Back",
    eyeRotationAngle: 76.307,
    voiceConfig: [
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_01.ogg`, animation: '12', text: '您回来了？我等您很久啦！' },
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_02.ogg`, animation: '03', text: '嗯，不错，今天也是个好天气。' },
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_03.ogg`, animation: '02', text: '天空真是广啊……\n另一边会有些什么呢？' },
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_04.ogg`, animation: '18', text: '偶尔也要为自己的健康着想啊，\n老师，我会很担心的。' },
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_05.ogg`, animation: '25', text: '来，加油吧，老师！' },
      { audio: `/spine_assets/arona/audio/${spineVoiceLang}/arona_06.ogg`, animation: '11', text: '今天又会有什么事情在等着我呢？' }
    ]
  },
  plana: {
    skelUrl: "/spine_assets/plana/plana_spr.skel",
    atlasUrl: "/spine_assets/plana/plana_spr.atlas",
    idleAnimationName: "Idle_01",
    eyeCloseAnimationName: "Eye_Close_01",
    rightEyeBone: "R_Eye_01",
    leftEyeBone: "L_Eye_01",
    frontHeadBone: "Head_Rot",
    backHeadBone: "Head_Back",
    eyeRotationAngle: 97.331,
    voiceConfig: [
      { audio: `/spine_assets/plana/audio/${spineVoiceLang}/plana_02.ogg`, animation: '06', text: '我明白了，\n老师现在无事可做，很无聊。' },
      { audio: `/spine_assets/plana/audio/${spineVoiceLang}/plana_01.ogg`, animation: '13', text: '混乱，该行动无法理解。\n请不要戳我，会出现故障。' },
      { audio: `/spine_assets/plana/audio/${spineVoiceLang}/plana_03.ogg`, animation: '15', text: '确认连接。' },
      { audio: `/spine_assets/plana/audio/${spineVoiceLang}/plana_04.ogg`, animation: '99', text: '正在待命，\n需要解决的任务还有很多。' },
      { audio: `/spine_assets/plana/audio/${spineVoiceLang}/plana_05.ogg`, animation: '17', text: '等您很久了。' },
    ]
  }
}

const enabled = ref(true)
const playerContainer = ref<HTMLElement | null>(null)
let player: any = null
let blinkInterval: any = null
const isEyeControlDisabled = ref(false)
let currentAnimationState: any = null
const currentCharacter = ref('arona')
const showDialog = ref(false)
const currentDialog = ref('')
let isPlaying = false
let lastPlayedIndex = -1
let moveBonesHandler: any = null
const resetBonesState = ref<(() => void) | null>(null)

const AudioManager = {
  context: null as AudioContext | null,
  buffers: new Map(),
  currentSource: null as AudioBufferSourceNode | null,
  gainNode: null as GainNode | null,

  initialize() {
    if (!this.context) {
      this.context = new (window.AudioContext || (window as any).webkitAudioContext)()
      this.gainNode = this.context.createGain()
      this.gainNode.gain.value = 0.5
      this.gainNode.connect(this.context.destination)
    }
  },

  async loadAudioFile(url: string) {
    if (this.buffers.has(url)) {
      return this.buffers.get(url).buffer
    }
    try {
      const response = await fetch(url)
      const arrayBuffer = await response.arrayBuffer()
      const audioBuffer = await this.context!.decodeAudioData(arrayBuffer)
      this.buffers.set(url, { buffer: audioBuffer, lastUsed: Date.now() })
      return audioBuffer
    } catch (error) {
      console.error('音频加载失败:', error)
      return null
    }
  },

  async playAudio(buffer: AudioBuffer) {
    if (this.currentSource) this.currentSource.stop()
    return new Promise<void>((resolve) => {
      const source = this.context!.createBufferSource()
      source.buffer = buffer
      source.connect(this.gainNode!)
      source.onended = () => {
        if (this.currentSource === source) this.currentSource = null
        resolve()
      }
      this.currentSource = source
      source.start()
    })
  },

  clear() {
    if (this.currentSource) {
      this.currentSource.stop()
      this.currentSource = null
    }
    this.buffers.clear()
  }
}

const debounce = (fn: Function, delay: number) => {
  let timer: any = null
  return function (this: any, ...args: any[]) {
    if (timer) clearTimeout(timer)
    timer = setTimeout(() => { fn.apply(this, args); timer = null }, delay)
  }
}

const currentAssets = computed(() => spineAssets[currentCharacter.value as keyof typeof spineAssets])

const preloadAudio = async () => {
  if (!currentAssets.value) return false
  AudioManager.initialize()
  const loadPromises = currentAssets.value.voiceConfig.map(pair => AudioManager.loadAudioFile(pair.audio))
  return Promise.all(loadPromises).catch(error => { console.error('音频预加载失败:', error); return false })
}

const handlePlayerClick = debounce(async (event: Event) => {
  event.preventDefault()
  event.stopPropagation()

  if (!isPlaying) {
    isPlaying = true
    isEyeControlDisabled.value = true
    resetBonesState.value?.()

    const currentConfig = currentAssets.value.voiceConfig
    let randomIndex
    do {
      randomIndex = Math.floor(Math.random() * currentConfig.length)
    } while (randomIndex === lastPlayedIndex && currentConfig.length > 1)

    lastPlayedIndex = randomIndex
    const selectedPair = currentConfig[randomIndex]

    try {
      const buffer = await AudioManager.loadAudioFile(selectedPair.audio)
      if (!buffer) throw new Error('音频加载失败')

      currentDialog.value = selectedPair.text
      showDialog.value = true
      currentAnimationState.addAnimation(2, selectedPair.animation, false, 0)

      await AudioManager.playAudio(buffer)

      isPlaying = false
      isEyeControlDisabled.value = false
      currentAnimationState.setEmptyAnimation(2, 0)
      showDialog.value = false
    } catch (error) {
      console.error('音频播放失败:', error)
      isPlaying = false
      isEyeControlDisabled.value = false
      showDialog.value = false
    }
  }
}, 300)

const isMobileDevice = () => /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)

const initializeSpinePlayer = async (assets: typeof spineAssets.arona) => {
  try {
    if (blinkInterval) clearTimeout(blinkInterval)
    if (playerContainer.value) playerContainer.value.innerHTML = ''

    player = new spine.SpinePlayer(playerContainer.value, {
      skelUrl: assets.skelUrl,
      atlasUrl: assets.atlasUrl,
      premultipliedAlpha: true,
      backgroundColor: '#00000000',
      alpha: true,
      showControls: false,
      success: function (playerInstance: any) {
        playerInstance.setAnimation(assets.idleAnimationName, true)
        const skeleton = playerInstance.skeleton
        const animationState = playerInstance.animationState
        currentAnimationState = animationState

        const rightEyeBone = skeleton.findBone(assets.rightEyeBone)
        const leftEyeBone = skeleton.findBone(assets.leftEyeBone)
        const frontHeadBone = skeleton.findBone(assets.frontHeadBone)
        const backHeadBone = skeleton.findBone(assets.backHeadBone)

        const rightEyeCenterX = rightEyeBone?.data.x ?? 0
        const rightEyeCenterY = rightEyeBone?.data.y ?? 0
        const leftEyeCenterX = leftEyeBone?.data.x ?? 0
        const leftEyeCenterY = leftEyeBone?.data.y ?? 0
        const frontHeadCenterX = frontHeadBone?.data.x ?? 0
        const frontHeadCenterY = frontHeadBone?.data.y ?? 0
        const backHeadCenterX = backHeadBone?.data.x ?? 0
        const backHeadCenterY = backHeadBone?.data.y ?? 0

        const maxRadius = 15
        const frontHeadMaxRadius = 2
        const backHeadMaxRadius = 1

        function rotateVector(x: number, y: number, angle: number) {
          const cos = Math.cos(angle), sin = Math.sin(angle)
          return { x: x * cos - y * sin, y: x * sin + y * cos }
        }

        function moveBones(event: MouseEvent) {
          if (isEyeControlDisabled.value || !playerContainer.value) return
          const containerRect = playerContainer.value.getBoundingClientRect()
          const mouseX = event.clientX - (containerRect.right - containerRect.width / 2)
          const mouseY = event.clientY - (containerRect.bottom - containerRect.height * 4 / 5)
          const eyeRotation = assets.eyeRotationAngle * (Math.PI / 180)
          const rotatedMouse = rotateVector(mouseX, mouseY, -eyeRotation)
          const offsetX = rotatedMouse.x, offsetY = rotatedMouse.y
          const distance = Math.sqrt(offsetX * offsetX + offsetY * offsetY)
          const angle = Math.atan2(offsetY, offsetX)
          const maxDistance = Math.min(distance, maxRadius)
          const dx = -maxDistance * Math.cos(angle)
          const dy = maxDistance * Math.sin(angle)

          if (rightEyeBone) { rightEyeBone.x = rightEyeCenterX + dx; rightEyeBone.y = rightEyeCenterY + dy }
          if (leftEyeBone) { leftEyeBone.x = leftEyeCenterX + dx; leftEyeBone.y = leftEyeCenterY + dy }

          const frontHeadDx = Math.min(distance, frontHeadMaxRadius) * Math.cos(angle)
          const frontHeadDy = Math.min(distance, frontHeadMaxRadius) * Math.sin(angle)
          const backHeadDx = Math.min(distance, backHeadMaxRadius) * Math.cos(angle)
          const backHeadDy = Math.min(distance, backHeadMaxRadius) * Math.sin(angle)

          if (frontHeadBone) { frontHeadBone.x = frontHeadCenterX - frontHeadDx; frontHeadBone.y = frontHeadCenterY + frontHeadDy }
          if (backHeadBone) { backHeadBone.x = backHeadCenterX + backHeadDx; backHeadBone.y = backHeadCenterY - backHeadDy }

          skeleton.updateWorldTransform()
        }

        function resetBones() {
          if (rightEyeBone) { rightEyeBone.x = rightEyeCenterX; rightEyeBone.y = rightEyeCenterY }
          if (leftEyeBone) { leftEyeBone.x = leftEyeCenterX; leftEyeBone.y = leftEyeCenterY }
          if (frontHeadBone) { frontHeadBone.x = frontHeadCenterX; frontHeadBone.y = frontHeadCenterY }
          if (backHeadBone) { backHeadBone.x = backHeadCenterX; backHeadBone.y = backHeadCenterY }
          skeleton.updateWorldTransform()
        }

        resetBonesState.value = resetBones

        function playBlinkAnimation() {
          const randomTime = Math.random() * 3 + 3
          const shouldDoubleBlink = Math.random() > 0.5
          animationState.setAnimation(1, assets.eyeCloseAnimationName, false)
          if (shouldDoubleBlink) animationState.addAnimation(1, assets.eyeCloseAnimationName, false, 0.1)
          blinkInterval = setTimeout(playBlinkAnimation, randomTime * 1000)
        }

        if (!isMobileDevice()) {
          moveBonesHandler = moveBones
          window.addEventListener('mousemove', moveBonesHandler)
        }
        playBlinkAnimation()
      },
      error: function (_: any, reason: string) {
        console.error('Spine加载失败: ' + reason)
      }
    })
  } catch (err) {
    console.error('Failed to initialize spine player:', err)
  }
}

const cleanup = () => {
  if (blinkInterval) clearTimeout(blinkInterval)
  if (moveBonesHandler && !isMobileDevice()) {
    window.removeEventListener('mousemove', moveBonesHandler)
    moveBonesHandler = null
  }
  if (playerContainer.value) playerContainer.value.innerHTML = ''
  if (player) {
    AudioManager.clear()
    player = null
    currentAnimationState = null
  }
}

const initializeCharacter = async () => {
  cleanup()
  if (!enabled.value) {
    console.log('[SpinePlayer] disabled')
    return
  }
  if (!playerContainer.value) {
    console.log('[SpinePlayer] playerContainer not ready, retrying...')
    setTimeout(initializeCharacter, 100)
    return
  }
  currentCharacter.value = isDark.value ? 'plana' : 'arona'
  console.log('[SpinePlayer] Initializing:', currentCharacter.value)
  try {
    await Promise.all([preloadAudio(), initializeSpinePlayer(currentAssets.value)])
    console.log('[SpinePlayer] Initialized successfully')
  } catch (err) {
    console.error('[SpinePlayer] 初始化失败:', err)
  }
}

const debouncedInitialize = debounce(initializeCharacter, 300)

watch(isDark, () => {
  if (enabled.value) debouncedInitialize()
})

onMounted(() => {
  if (enabled.value) debouncedInitialize()
})

onUnmounted(() => {
  cleanup()
})
</script>

<style scoped>
@import './spine-player.css';

.playerContainer {
  position: fixed;
  bottom: 25px;
  left: 0%;
  z-index: 100;
  width: 12vw;
  height: 24vw;
  filter: drop-shadow(0 0 3px rgba(40, 42, 44, 0.42));
  transition: all 1s;
  cursor: pointer;
}

.chatdialog-container {
  position: fixed;
  bottom: 10vw;
  left: 2vw;
  z-index: 101;
  transition: all 1s;
  pointer-events: none;
  filter: drop-shadow(0 0 3px rgba(36, 36, 36, 0.6));
}

.chatdialog-triangle {
  position: absolute;
  left: 2vw;
  top: -10px;
  width: 0;
  height: 0;
  border-left: 10px solid transparent;
  border-right: 10px solid transparent;
  border-bottom: 10px solid rgba(255, 255, 255, 0.9);
  z-index: 101;
}

.chatdialog {
  background-color: rgba(255, 255, 255, 0.9);
  border-radius: 25px;
  padding: 12px 24px;
  word-wrap: break-word;
  white-space: pre-wrap;
  line-height: 1.4;
  color: #000000;
  font-size: 0.8vw;
  user-select: none;
  pointer-events: auto;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

@media (max-width: 768px) {
  .chatdialog-container {
    left: 2vh;
    bottom: 10vh;
  }
  .chatdialog {
    min-width: auto;
    padding: 12px 20px;
    font-size: 1vh;
    border-radius: 20px;
  }
  .chatdialog-triangle {
    left: 35px;
    border-width: 8px;
    top: -8px;
  }
  .playerContainer {
    width: 15vh;
    height: 30vh;
  }
}
</style>
