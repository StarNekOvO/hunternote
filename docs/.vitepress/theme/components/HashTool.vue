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
        <button class="calc-btn" @click="calculateAll" :disabled="!input || isCalculating">
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
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const input = ref('')
const inputType = ref<'text' | 'file'>('text')
const fileInfo = ref<{ name: string; size: number; arrayBuffer: ArrayBuffer } | null>(null)
const hashResults = ref<Record<string, string>>({})
const isCalculating = ref(false)

const algorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512']

async function calculateHash(data: ArrayBuffer, algorithm: string): Promise<string> {
  if (algorithm === 'MD5') {
    return md5(data)
  }
  
  const hashBuffer = await crypto.subtle.digest(algorithm, data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

function md5(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data)
  
  function rotateLeft(x: number, n: number) { return (x << n) | (x >>> (32 - n)) }
  function toHex(n: number) { return n.toString(16).padStart(8, '0').match(/../g)!.reverse().join('') }
  
  const k = new Uint32Array(64)
  for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000)
  
  const s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21]
  
  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  
  const len = bytes.length
  const padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64)
  padded.set(bytes)
  padded[len] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(padded.length - 8, len * 8, true)
  
  for (let i = 0; i < padded.length; i += 64) {
    const M = new Uint32Array(16)
    for (let j = 0; j < 16; j++) M[j] = view.getUint32(i + j * 4, true)
    
    let [A, B, C, D] = [a0, b0, c0, d0]
    
    for (let j = 0; j < 64; j++) {
      let F: number, g: number
      if (j < 16) { F = (B & C) | (~B & D); g = j }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16 }
      else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * j) % 16 }
      
      F = (F + A + k[j] + M[g]) >>> 0
      A = D; D = C; C = B; B = (B + rotateLeft(F, s[j])) >>> 0
    }
    
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0
  }
  
  return toHex(a0) + toHex(b0) + toHex(c0) + toHex(d0)
}

async function calculateAll() {
  if (!input.value && !fileInfo.value) return
  
  isCalculating.value = true
  hashResults.value = {}
  
  try {
    const data = inputType.value === 'text'
      ? new TextEncoder().encode(input.value).buffer
      : fileInfo.value!.arrayBuffer
    
    for (const algo of algorithms) {
      hashResults.value[algo] = await calculateHash(data, algo)
    }
  } catch (e) {
    console.error(e)
  }
  
  isCalculating.value = false
}

async function handleFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  
  fileInfo.value = {
    name: file.name,
    size: file.size,
    arrayBuffer: await file.arrayBuffer()
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

.text-input textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.input-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}

.calc-btn {
  padding: 0.5rem 1.5rem;
  border: none;
  border-radius: 6px;
  background: var(--vp-c-brand);
  color: white;
  cursor: pointer;
  font-weight: 500;
}

.calc-btn:hover:not(:disabled) {
  opacity: 0.9;
}

.calc-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.clear-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
}

.file-drop {
  display: block;
  border: 2px dashed var(--vp-c-divider);
  border-radius: 8px;
  padding: 3rem;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  color: var(--vp-c-text-2);
}

.file-drop:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-bg-soft);
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
}

.result-row {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--vp-c-divider);
}

.result-row:last-child {
  border-bottom: none;
}

.algo-name {
  font-weight: 600;
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
}

.hash-value {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.hash-value code {
  flex: 1;
  font-size: 0.85rem;
  word-break: break-all;
  padding: 0.25rem 0.5rem;
  background: var(--vp-c-bg-alt);
  border-radius: 4px;
}

.copy-btn {
  padding: 0.2rem 0.6rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
  white-space: nowrap;
}

.copy-btn:hover {
  background: var(--vp-c-bg-mute);
}
</style>
