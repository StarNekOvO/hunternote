<template>
  <div class="pwn-helper">
    <!-- 标签页导航 -->
    <div class="tool-tabs">
      <button :class="['tab-btn', { active: activeTab === 'address' }]" @click="activeTab = 'address'">地址计算</button>
      <button :class="['tab-btn', { active: activeTab === 'endian' }]" @click="activeTab = 'endian'">字节序</button>
      <button :class="['tab-btn', { active: activeTab === 'shellcode' }]" @click="activeTab = 'shellcode'">Shellcode</button>
      <button :class="['tab-btn', { active: activeTab === 'padding' }]" @click="activeTab = 'padding'">Padding</button>
    </div>

    <!-- 地址计算 -->
    <div v-if="activeTab === 'address'" class="tab-content">
      <div class="form-grid">
        <div class="form-item">
          <label class="form-label">基地址</label>
          <input type="text" class="form-input" v-model="baseAddr" placeholder="0x7fff12340000" />
        </div>
        <div class="form-item">
          <label class="form-label">偏移量 (可为负数)</label>
          <input type="text" class="form-input" v-model="offset" placeholder="0x1000 或 -0x100" />
        </div>
      </div>
      <div v-if="addressResult" class="result-card">
        <div class="result-row">
          <span class="result-label">结果</span>
          <code class="result-code">{{ addressResult }}</code>
          <button class="btn-sm" @click="copy(addressResult)">复制</button>
        </div>
      </div>
    </div>

    <!-- 字节序转换 -->
    <div v-if="activeTab === 'endian'" class="tab-content">
      <div class="form-grid">
        <div class="form-item">
          <label class="form-label">输入值 (hex)</label>
          <input type="text" class="form-input" v-model="byteInput" placeholder="0xdeadbeef" />
        </div>
        <div class="form-item">
          <label class="form-label">字节数</label>
          <select class="form-select" v-model="byteSize">
            <option value="4">4 字节 (32-bit)</option>
            <option value="8">8 字节 (64-bit)</option>
          </select>
        </div>
      </div>
      <div class="result-card">
        <div class="result-row">
          <span class="result-label">大端序 (BE)</span>
          <code class="result-code">{{ bigEndian }}</code>
          <button class="btn-sm" @click="copy(bigEndian)" :disabled="!bigEndian">复制</button>
        </div>
        <div class="result-row">
          <span class="result-label">小端序 (LE)</span>
          <code class="result-code">{{ littleEndian }}</code>
          <button class="btn-sm" @click="copy(littleEndian)" :disabled="!littleEndian">复制</button>
        </div>
      </div>
    </div>

    <!-- Shellcode 格式化 -->
    <div v-if="activeTab === 'shellcode'" class="tab-content">
      <div class="form-item">
        <label class="form-label">输入 Shellcode</label>
        <textarea class="form-textarea" v-model="shellcodeInput" placeholder="\x31\xc0\x50\x68... 或 31 c0 50 68..." rows="4"></textarea>
      </div>
      <div class="form-item">
        <label class="form-label">输出格式</label>
        <div class="mode-buttons">
          <button :class="['mode-btn', { active: shellcodeFormat === 'c' }]" @click="shellcodeFormat = 'c'">C</button>
          <button :class="['mode-btn', { active: shellcodeFormat === 'python' }]" @click="shellcodeFormat = 'python'">Python</button>
          <button :class="['mode-btn', { active: shellcodeFormat === 'hex' }]" @click="shellcodeFormat = 'hex'">Hex</button>
          <button :class="['mode-btn', { active: shellcodeFormat === 'array' }]" @click="shellcodeFormat = 'array'">Array</button>
          <button :class="['mode-btn', { active: shellcodeFormat === 'nasm' }]" @click="shellcodeFormat = 'nasm'">NASM</button>
        </div>
      </div>
      <div v-if="formattedShellcode" class="result-card">
        <div class="result-header">
          <span class="result-meta">长度: {{ shellcodeLength }} 字节</span>
          <button class="btn-sm" @click="copy(formattedShellcode)">复制</button>
        </div>
        <pre class="result-pre">{{ formattedShellcode }}</pre>
      </div>
    </div>

    <!-- Padding 生成 -->
    <div v-if="activeTab === 'padding'" class="tab-content">
      <div class="form-grid">
        <div class="form-item">
          <label class="form-label">长度</label>
          <input type="number" class="form-input" v-model="paddingLength" placeholder="64" />
        </div>
        <div class="form-item">
          <label class="form-label">填充字符</label>
          <input type="text" class="form-input" v-model="paddingPattern" placeholder="A" maxlength="1" />
        </div>
      </div>
      <div class="result-card">
        <div class="result-header">
          <span class="result-meta">重复填充</span>
          <button class="btn-sm" @click="copy(generatedPadding)">复制</button>
        </div>
        <pre class="result-pre result-scroll">{{ generatedPadding }}</pre>
      </div>
      <div class="result-card">
        <div class="result-header">
          <span class="result-meta">循环模式 (用于定位偏移)</span>
          <button class="btn-sm" @click="copy(cyclicPadding)">复制</button>
        </div>
        <pre class="result-pre result-scroll">{{ cyclicPadding }}</pre>
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

const activeTab = ref('address')
const wasmReady = ref(false)

onMounted(async () => {
  await ensureWasmLoaded()
  wasmReady.value = true
})

// 地址计算
const baseAddr = ref('')
const offset = ref('')
const addressResult = computed(() => {
  if (!baseAddr.value || !wasmReady.value) return ''
  try {
    return wasm.calc_address(baseAddr.value, offset.value || '0')
  } catch (e: any) {
    return '计算错误: ' + e.message
  }
})

// 字节序转换
const byteInput = ref('')
const byteSize = ref('8')

const littleEndian = computed(() => {
  if (!byteInput.value || !wasmReady.value) return ''
  try {
    return wasm.to_little_endian(byteInput.value, parseInt(byteSize.value))
  } catch (e: any) {
    return '转换错误'
  }
})

const bigEndian = computed(() => {
  if (!byteInput.value || !wasmReady.value) return ''
  try {
    return wasm.to_big_endian(byteInput.value, parseInt(byteSize.value))
  } catch (e: any) {
    return '转换错误'
  }
})

// Shellcode 格式化
const shellcodeInput = ref('')
const shellcodeFormat = ref('c')

const formattedShellcode = computed(() => {
  if (!shellcodeInput.value || !wasmReady.value) return ''
  return wasm.format_shellcode(shellcodeInput.value, shellcodeFormat.value)
})

const shellcodeLength = computed(() => {
  if (!shellcodeInput.value || !wasmReady.value) return 0
  return wasm.shellcode_length(shellcodeInput.value)
})

// Padding 生成
const paddingLength = ref('64')
const paddingPattern = ref('A')

const generatedPadding = computed(() => {
  if (!wasmReady.value) return ''
  const len = parseInt(paddingLength.value) || 0
  if (len > 10000) return '长度过大'
  return wasm.generate_padding(len, paddingPattern.value || 'A')
})

const cyclicPadding = computed(() => {
  if (!wasmReady.value) return ''
  const len = parseInt(paddingLength.value) || 0
  if (len > 10000) return '长度过大'
  return wasm.generate_cyclic(len)
})

function copy(text: string) {
  navigator.clipboard.writeText(text)
}
</script>

<style scoped>
.pwn-helper {
  margin-top: 1rem;
}

/* 标签页导航 */
.tool-tabs {
  display: flex;
  gap: 0.5rem;
  border-bottom: 1px solid var(--vp-c-divider);
  padding-bottom: 0.75rem;
  margin-bottom: 1.25rem;
  flex-wrap: wrap;
}

.tab-btn {
  padding: 0.5rem 1rem;
  border: none;
  background: transparent;
  color: var(--vp-c-text-2);
  font-size: 0.95rem;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.15s ease;
}

.tab-btn:hover {
  color: var(--vp-c-text-1);
  background: rgba(255, 255, 255, 0.3);
}

:root.dark .tab-btn:hover {
  background: rgba(0, 0, 0, 0.3);
}

.tab-btn.active {
  color: var(--vp-c-brand);
  background: rgba(255, 255, 255, 0.5);
  font-weight: 500;
}

:root.dark .tab-btn.active {
  background: rgba(0, 0, 0, 0.4);
}

.tab-content {
  animation: fadeIn 0.15s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* 表单布局 */
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}

@media (max-width: 640px) {
  .form-grid {
    grid-template-columns: 1fr;
  }
}

.form-item {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  margin-bottom: 1rem;
}

.form-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.form-input,
.form-select,
.form-textarea {
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(8px);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  transition: border-color 0.15s ease;
}

:root.dark .form-input,
:root.dark .form-select,
:root.dark .form-textarea {
  background: rgba(0, 0, 0, 0.4);
}

.form-input:focus,
.form-select:focus,
.form-textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.form-textarea {
  resize: vertical;
}

/* 模式按钮组 */
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
  font-size: 0.85rem;
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

/* 结果卡片 */
.result-card {
  background: rgba(255, 255, 255, 0.4);
  backdrop-filter: blur(8px);
  border-radius: 8px;
  padding: 0.85rem;
  margin-bottom: 0.75rem;
}

:root.dark .result-card {
  background: rgba(0, 0, 0, 0.3);
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.result-meta {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
}

.result-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0;
}

.result-row:not(:last-child) {
  border-bottom: 1px solid var(--vp-c-divider);
}

.result-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  min-width: 90px;
  flex-shrink: 0;
}

.result-code {
  flex: 1;
  padding: 0.35rem 0.5rem;
  background: rgba(255, 255, 255, 0.4);
  border-radius: 4px;
  font-size: 0.85rem;
  word-break: break-all;
}

:root.dark .result-code {
  background: rgba(0, 0, 0, 0.3);
}

.result-pre {
  margin: 0;
  padding: 0.65rem;
  background: rgba(255, 255, 255, 0.4);
  border-radius: 6px;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-all;
}

:root.dark .result-pre {
  background: rgba(0, 0, 0, 0.3);
}

.result-scroll {
  max-height: 100px;
  overflow: auto;
}

/* 小按钮 */
.btn-sm {
  flex-shrink: 0;
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

.loading-hint {
  margin-top: 1rem;
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.85rem;
}
</style>
