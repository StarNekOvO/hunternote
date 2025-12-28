<template>
  <div class="encoder-tool">
    <div class="tool-controls">
      <div class="mode-select">
        <button 
          v-for="m in modes" 
          :key="m.value"
          :class="['mode-btn', { active: mode === m.value }]"
          @click="mode = m.value"
        >
          {{ m.label }}
        </button>
      </div>
      <div class="direction-toggle">
        <span :class="{ active: direction === 'encode' }">编码</span>
        <button class="swap-btn" @click="swap">⇄</button>
        <span :class="{ active: direction === 'decode' }">解码</span>
      </div>
    </div>

    <div class="io-area">
      <div class="input-section">
        <div class="section-header">
          <span>输入</span>
          <button class="action-btn" @click="clearAll">清空</button>
        </div>
        <textarea v-model="input" placeholder="在此输入文本..." rows="6"></textarea>
      </div>

      <div class="output-section">
        <div class="section-header">
          <span>输出</span>
          <button class="action-btn" @click="copyOutput">复制</button>
        </div>
        <textarea :value="output" readonly placeholder="结果将显示在这里..." rows="6"></textarea>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const input = ref('')
const mode = ref('base64')
const direction = ref<'encode' | 'decode'>('encode')

const modes = [
  { value: 'base64', label: 'Base64' },
  { value: 'hex', label: 'Hex' },
  { value: 'url', label: 'URL' },
  { value: 'html', label: 'HTML 实体' },
  { value: 'unicode', label: 'Unicode' },
]

const output = computed(() => {
  if (!input.value) return ''
  try {
    return direction.value === 'encode' 
      ? encode(input.value, mode.value)
      : decode(input.value, mode.value)
  } catch (e: any) {
    return `错误: ${e.message}`
  }
})

function encode(str: string, type: string): string {
  switch (type) {
    case 'base64':
      return btoa(unescape(encodeURIComponent(str)))
    case 'hex':
      return Array.from(new TextEncoder().encode(str))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ')
    case 'url':
      return encodeURIComponent(str)
    case 'html':
      return str.replace(/[&<>"']/g, c => 
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as any)[c])
    case 'unicode':
      return Array.from(str).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('')
    default:
      return str
  }
}

function decode(str: string, type: string): string {
  switch (type) {
    case 'base64':
      return decodeURIComponent(escape(atob(str.trim())))
    case 'hex':
      const hexStr = str.replace(/\s+/g, '').replace(/0x/gi, '')
      const bytes = hexStr.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || []
      return new TextDecoder().decode(new Uint8Array(bytes))
    case 'url':
      return decodeURIComponent(str)
    case 'html':
      const textarea = document.createElement('textarea')
      textarea.innerHTML = str
      return textarea.value
    case 'unicode':
      return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    default:
      return str
  }
}

function swap() {
  const temp = output.value
  direction.value = direction.value === 'encode' ? 'decode' : 'encode'
  if (temp && !temp.startsWith('错误')) {
    input.value = temp
  }
}

function copyOutput() {
  navigator.clipboard.writeText(output.value)
}

function clearAll() {
  input.value = ''
}
</script>

<style scoped>
.encoder-tool {
  margin-top: 1.5rem;
}

.tool-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
  margin-bottom: 1rem;
}

.mode-select {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.mode-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.2s;
}

.mode-btn:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-brand);
}

.mode-btn.active {
  background: var(--vp-c-brand);
  border-color: var(--vp-c-brand);
  color: white;
}

.direction-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.direction-toggle span {
  color: var(--vp-c-text-3);
  font-size: 0.9rem;
}

.direction-toggle span.active {
  color: var(--vp-c-brand);
  font-weight: 600;
}

.swap-btn {
  padding: 0.25rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  cursor: pointer;
  font-size: 1.1rem;
}

.swap-btn:hover {
  background: var(--vp-c-bg-mute);
}

.io-area {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

@media (max-width: 768px) {
  .io-area {
    grid-template-columns: 1fr;
  }
}

.input-section, .output-section {
  display: flex;
  flex-direction: column;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.action-btn {
  padding: 0.25rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
  cursor: pointer;
}

.action-btn:hover {
  background: var(--vp-c-bg-mute);
}

textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  resize: vertical;
}

textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

textarea[readonly] {
  background: var(--vp-c-bg-alt);
}
</style>
