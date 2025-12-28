<template>
  <div class="hash-tool">
    <div class="input-type-toggle">
      <button 
        :class="['toggle-btn', { active: inputType === 'text' }]"
        @click="inputType = 'text'; fileInfo = null"
      >
        文本输入
      </button>
      <button 
        :class="['toggle-btn', { active: inputType === 'file' }]"
        @click="inputType = 'file'; input = ''"
      >
        文件上传
      </button>
    </div>

    <div v-if="inputType === 'text'" class="text-input">
      <textarea 
        v-model="input" 
        placeholder="输入要计算哈希的文本..."
        rows="5"
      ></textarea>
      <div class="input-actions">
        <button class="calc-btn" @click="calculateAll" :disabled="!input || isCalculating || !wasmReady">
          {{ isCalculating ? '计算中...' : '计算哈希' }}
        </button>
        <button class="clear-btn" @click="clear">清空</button>
      </div>
    </div>

    <div v-else class="file-input">
      <label class="file-drop">
        <input type="file" @change="handleFile" />
        <div class="drop-content">
          <template v-if="!fileInfo">点击或拖拽文件到这里</template>
          <template v-else>{{ fileInfo.name }} ({{ formatSize(fileInfo.size) }})</template>
        </div>
      </label>
    </div>

    <div v-if="Object.keys(hashResults).length" class="results">
      <h3>计算结果</h3>
      <div v-for="algo in algorithms" :key="algo" class="result-row">
        <div class="algo-name">{{ algo }}</div>
        <div class="hash-value">
          <code>{{ hashResults[algo] || '计算中...' }}</code>
          <button class="copy-btn" @click="copyHash(hashResults[algo])">复制</button>
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
  margin-top: 1.5rem;
}

.loading-hint {
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.9rem;
}

.input-type-toggle {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.toggle-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.2s;
}

.toggle-btn.active {
  background: var(--vp-c-brand);
  border-color: var(--vp-c-brand);
  color: white;
}

.text-input textarea {
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

.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}

.calc-btn, .clear-btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.calc-btn {
  background: var(--vp-c-brand);
  color: white;
}

.calc-btn:hover:not(:disabled) {
  background: var(--vp-c-brand-dark);
}

.calc-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.clear-btn {
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-2);
}

.file-input {
  margin-bottom: 1rem;
}

.file-drop {
  display: block;
  padding: 2rem;
  border: 2px dashed var(--vp-c-divider);
  border-radius: 8px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}

.file-drop:hover {
  border-color: var(--vp-c-brand);
}

.file-drop input {
  display: none;
}

.results {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
}

.results h3 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
  color: var(--vp-c-text-1);
}

.result-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--vp-c-divider);
}

.result-row:last-child {
  border-bottom: none;
}

.algo-name {
  width: 80px;
  font-weight: 600;
  color: var(--vp-c-brand);
}

.hash-value {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.hash-value code {
  flex: 1;
  padding: 0.25rem 0.5rem;
  background: var(--vp-c-bg);
  border-radius: 4px;
  font-size: 0.8rem;
  word-break: break-all;
}

.copy-btn {
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.75rem;
  cursor: pointer;
}

.copy-btn:hover {
  background: var(--vp-c-brand);
  color: white;
}
</style>
