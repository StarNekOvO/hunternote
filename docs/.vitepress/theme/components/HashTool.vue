<template>
  <div class="hash-tool">
    <!-- 输入类型切换 -->
    <div class="mode-buttons">
      <button 
        :class="['mode-btn', { active: inputType === 'text' }]"
        @click="inputType = 'text'; fileInfo = null"
      >
        文本输入
      </button>
      <button 
        :class="['mode-btn', { active: inputType === 'file' }]"
        @click="inputType = 'file'; input = ''"
      >
        文件上传
      </button>
    </div>

    <!-- 文本输入区域 -->
    <div v-if="inputType === 'text'" class="text-section">
      <textarea 
        v-model="input" 
        class="input-textarea"
        placeholder="输入要计算哈希的文本..."
        rows="5"
      ></textarea>
      <div class="action-bar">
        <button class="btn-primary" @click="calculateAll" :disabled="!input || isCalculating || !wasmReady">
          {{ isCalculating ? '计算中...' : '计算哈希' }}
        </button>
        <button class="btn-secondary" @click="clear">清空</button>
      </div>
    </div>

    <!-- 文件上传区域 -->
    <div v-else class="file-section">
      <label class="upload-zone">
        <input type="file" @change="handleFile" />
        <svg class="upload-icon" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
        </svg>
        <p class="upload-text">
          <template v-if="!fileInfo">点击或拖拽文件到这里</template>
          <template v-else>{{ fileInfo.name }} ({{ formatSize(fileInfo.size) }})</template>
        </p>
      </label>
    </div>

    <!-- 结果展示 -->
    <div v-if="Object.keys(hashResults).length" class="results-panel">
      <div class="panel-header">
        <span class="panel-title">计算结果</span>
      </div>
      <div class="results-list">
        <div v-for="algo in algorithms" :key="algo" class="result-item">
          <span class="algo-label">{{ algo }}</span>
          <div class="hash-content">
            <code class="hash-value">{{ hashResults[algo] || '计算中...' }}</code>
            <button class="btn-sm" @click="copyHash(hashResults[algo])" :disabled="!hashResults[algo]">复制</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="!wasmReady" class="loading-hint">
      正在加载 WebAssembly 模块...
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ensureWasmLoaded, wasm } from '../wasm-loader'

const input = ref('')
const inputType = ref<'text' | 'file'>('text')
const fileInfo = ref<{ name: string; size: number; data: Uint8Array } | null>(null)
const hashResults = ref<Record<string, string>>({})
const isCalculating = ref(false)
const wasmReady = ref(false)

const algorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512']

onMounted(async () => {
  await ensureWasmLoaded()
  wasmReady.value = true
})

async function calculateAll() {
  if (!wasmReady.value) return
  if (!input.value && !fileInfo.value) return
  
  isCalculating.value = true
  hashResults.value = {}
  
  const data = inputType.value === 'text'
    ? new TextEncoder().encode(input.value)
    : fileInfo.value!.data
  
  hashResults.value['MD5'] = wasm.hash_md5(data)
  hashResults.value['SHA-1'] = wasm.hash_sha1(data)
  hashResults.value['SHA-256'] = wasm.hash_sha256(data)
  hashResults.value['SHA-512'] = wasm.hash_sha512(data)
  
  isCalculating.value = false
}

async function handleFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  
  const arrayBuffer = await file.arrayBuffer()
  fileInfo.value = {
    name: file.name,
    size: file.size,
    data: new Uint8Array(arrayBuffer)
  }
  
  await calculateAll()
}

function copyHash(hash: string) {
  navigator.clipboard.writeText(hash)
}

function clear() {
  input.value = ''
  fileInfo.value = null
  hashResults.value = {}
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}
</script>

<style scoped>
.hash-tool {
  margin-top: 1rem;
}

.mode-buttons {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
}

.mode-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.mode-btn:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-text-1);
}

.mode-btn.active {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
  font-weight: 500;
}

.text-section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.input-textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  resize: vertical;
  transition: border-color 0.15s ease;
}

.input-textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.input-textarea::placeholder {
  color: var(--vp-c-text-3);
}

.action-bar {
  display: flex;
  gap: 0.5rem;
}

.btn-primary {
  padding: 0.6rem 1.25rem;
  border: none;
  border-radius: 6px;
  background: var(--vp-c-brand);
  color: white;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-primary:hover:not(:disabled) {
  background: var(--vp-c-brand-dark);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  padding: 0.6rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-secondary:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-text-1);
}

.file-section {
  margin-bottom: 1rem;
}

.upload-zone {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2.5rem 1.5rem;
  border: 2px dashed var(--vp-c-divider);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.upload-zone:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-bg-soft);
}

.upload-zone input {
  display: none;
}

.upload-icon {
  color: var(--vp-c-text-3);
  margin-bottom: 0.75rem;
}

.upload-text {
  margin: 0;
  font-size: 0.95rem;
  color: var(--vp-c-text-2);
}

.results-panel {
  margin-top: 1.5rem;
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  overflow: hidden;
}

.panel-header {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.panel-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.results-list {
  padding: 0.5rem 1rem;
}

.result-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 0;
}

.result-item:not(:last-child) {
  border-bottom: 1px solid var(--vp-c-divider);
}

.algo-label {
  width: 72px;
  flex-shrink: 0;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--vp-c-brand);
}

.hash-content {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
}

.hash-value {
  flex: 1;
  padding: 0.35rem 0.5rem;
  background: var(--vp-c-bg);
  border-radius: 4px;
  font-size: 0.8rem;
  word-break: break-all;
}

.btn-sm {
  flex-shrink: 0;
  padding: 0.3rem 0.6rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
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

.loading-hint {
  margin-top: 1rem;
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.85rem;
}
</style>
