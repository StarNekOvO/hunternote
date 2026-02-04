<template>
  <div class="encoder-tool">
    <!-- 模式选择和方向控制 -->
    <div class="tool-header">
      <div class="mode-buttons">
        <button 
          v-for="m in modes" 
          :key="m.value"
          :class="['mode-btn', { active: mode === m.value }]"
          @click="mode = m.value"
        >
          {{ m.label }}
        </button>
      </div>
      <div class="direction-control">
        <span :class="['direction-label', { active: direction === 'encode' }]">编码</span>
        <button class="direction-btn" @click="swap" title="切换方向">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M7 16V4m0 0L3 8m4-4l4 4M17 8v12m0 0l4-4m-4 4l-4-4"/>
          </svg>
        </button>
        <span :class="['direction-label', { active: direction === 'decode' }]">解码</span>
      </div>
    </div>

    <!-- 输入输出区域 -->
    <div class="io-grid">
      <div class="io-panel">
        <div class="panel-header">
          <span class="panel-title">输入</span>
          <button class="btn-sm" @click="clearAll">清空</button>
        </div>
        <textarea 
          v-model="input" 
          class="io-textarea" 
          placeholder="在此输入文本..." 
          rows="8"
        ></textarea>
      </div>

      <div class="io-panel">
        <div class="panel-header">
          <span class="panel-title">输出</span>
          <button class="btn-sm" @click="copyOutput" :disabled="!output">复制</button>
        </div>
        <textarea 
          :value="output" 
          class="io-textarea" 
          readonly 
          placeholder="结果将显示在这里..." 
          rows="8"
        ></textarea>
      </div>
    </div>

    <div v-if="!wasmReady" class="loading-hint">
      正在加载 WebAssembly 模块...
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ensureWasmLoaded, wasm } from '../wasm-loader'

const input = ref('')
const mode = ref('base64')
const direction = ref<'encode' | 'decode'>('encode')
const wasmReady = ref(false)

const modes = [
  { value: 'base64', label: 'Base64' },
  { value: 'hex', label: 'Hex' },
  { value: 'url', label: 'URL' },
  { value: 'html', label: 'HTML 实体' },
  { value: 'unicode', label: 'Unicode' },
]

onMounted(async () => {
  await ensureWasmLoaded()
  wasmReady.value = true
})

const output = computed(() => {
  if (!input.value || !wasmReady.value) return ''
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
    case 'base64': {
      const data = new TextEncoder().encode(str)
      return wasm.encode_base64(data)
    }
    case 'hex': {
      const data = new TextEncoder().encode(str)
      return wasm.encode_hex(data)
    }
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
    case 'base64': {
      const bytes = wasm.decode_base64(str.trim())
      return new TextDecoder().decode(bytes)
    }
    case 'hex': {
      const hexStr = str.replace(/\s+/g, '').replace(/0x/gi, '')
      const bytes = wasm.decode_hex(hexStr)
      return new TextDecoder().decode(bytes)
    }
    case 'url':
      return decodeURIComponent(str)
    case 'html': {
      const textarea = document.createElement('textarea')
      textarea.innerHTML = str
      return textarea.value
    }
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
  margin-top: 1rem;
}

.tool-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
  margin-bottom: 1.25rem;
}

.mode-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.mode-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: transparent;
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.mode-btn:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-text-1);
  background: rgba(255, 255, 255, 0.3);
}

:root.dark .mode-btn:hover {
  background: rgba(0, 0, 0, 0.3);
}

.mode-btn.active {
  border-color: var(--vp-c-brand);
  background: rgba(255, 255, 255, 0.5);
  color: var(--vp-c-brand);
  font-weight: 500;
}

:root.dark .mode-btn.active {
  background: rgba(0, 0, 0, 0.4);
}

.direction-control {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.direction-label {
  font-size: 0.9rem;
  color: var(--vp-c-text-3);
  transition: all 0.15s ease;
}

.direction-label.active {
  color: var(--vp-c-brand);
  font-weight: 600;
}

.direction-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: transparent;
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.15s ease;
}

.direction-btn:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand);
  color: white;
}

.io-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

@media (max-width: 640px) {
  .io-grid {
    grid-template-columns: 1fr;
  }
}

.io-panel {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.panel-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.btn-sm {
  padding: 0.3rem 0.6rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: transparent;
  color: var(--vp-c-text-3);
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-sm:hover:not(:disabled) {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand);
  color: white;
}

.btn-sm:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.io-textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(8px);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  resize: vertical;
  transition: border-color 0.15s ease;
}

:root.dark .io-textarea {
  background: rgba(0, 0, 0, 0.4);
}

.io-textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.io-textarea::placeholder {
  color: var(--vp-c-text-3);
}

.loading-hint {
  margin-top: 1rem;
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.85rem;
}
</style>
