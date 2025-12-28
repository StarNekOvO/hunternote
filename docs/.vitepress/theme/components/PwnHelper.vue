<template>
  <div class="pwn-helper">
    <div class="tabs">
      <button :class="['tab', { active: activeTab === 'address' }]" @click="activeTab = 'address'">地址计算</button>
      <button :class="['tab', { active: activeTab === 'endian' }]" @click="activeTab = 'endian'">字节序</button>
      <button :class="['tab', { active: activeTab === 'shellcode' }]" @click="activeTab = 'shellcode'">Shellcode</button>
      <button :class="['tab', { active: activeTab === 'padding' }]" @click="activeTab = 'padding'">Padding</button>
    </div>

    <!-- 地址计算 -->
    <div v-if="activeTab === 'address'" class="tab-content">
      <div class="form-group">
        <label>基地址</label>
        <input type="text" v-model="baseAddr" placeholder="0x7fff12340000" />
      </div>
      <div class="form-group">
        <label>偏移量 (可为负数)</label>
        <input type="text" v-model="offset" placeholder="0x1000 或 -0x100" />
      </div>
      <div v-if="addressResult" class="result-box">
        <span class="label">结果:</span>
        <code>{{ addressResult }}</code>
        <button class="copy-btn" @click="copy(addressResult)">复制</button>
      </div>
    </div>

    <!-- 字节序转换 -->
    <div v-if="activeTab === 'endian'" class="tab-content">
      <div class="form-group">
        <label>输入值 (hex)</label>
        <input type="text" v-model="byteInput" placeholder="0xdeadbeef" />
      </div>
      <div class="form-group">
        <label>字节数</label>
        <select v-model="byteSize">
          <option value="4">4 字节 (32-bit)</option>
          <option value="8">8 字节 (64-bit)</option>
        </select>
      </div>
      <div class="endian-results">
        <div class="result-box">
          <span class="label">大端序 (BE):</span>
          <code>{{ bigEndian }}</code>
          <button class="copy-btn" @click="copy(bigEndian)">复制</button>
        </div>
        <div class="result-box">
          <span class="label">小端序 (LE):</span>
          <code>{{ littleEndian }}</code>
          <button class="copy-btn" @click="copy(littleEndian)">复制</button>
        </div>
      </div>
    </div>

    <!-- Shellcode 格式化 -->
    <div v-if="activeTab === 'shellcode'" class="tab-content">
      <div class="form-group">
        <label>输入 Shellcode</label>
        <textarea v-model="shellcodeInput" placeholder="\x31\xc0\x50\x68... 或 31 c0 50 68..." rows="4"></textarea>
      </div>
      <div class="form-group">
        <label>输出格式</label>
        <div class="format-btns">
          <button :class="{ active: shellcodeFormat === 'c' }" @click="shellcodeFormat = 'c'">C</button>
          <button :class="{ active: shellcodeFormat === 'python' }" @click="shellcodeFormat = 'python'">Python</button>
          <button :class="{ active: shellcodeFormat === 'hex' }" @click="shellcodeFormat = 'hex'">Hex</button>
          <button :class="{ active: shellcodeFormat === 'array' }" @click="shellcodeFormat = 'array'">Array</button>
          <button :class="{ active: shellcodeFormat === 'nasm' }" @click="shellcodeFormat = 'nasm'">NASM</button>
        </div>
      </div>
      <div v-if="formattedShellcode" class="result-box">
        <div class="result-header">
          <span class="label">长度: {{ shellcodeLength }} 字节</span>
          <button class="copy-btn" @click="copy(formattedShellcode)">复制</button>
        </div>
        <pre>{{ formattedShellcode }}</pre>
      </div>
    </div>

    <!-- Padding 生成 -->
    <div v-if="activeTab === 'padding'" class="tab-content">
      <div class="form-row">
        <div class="form-group">
          <label>长度</label>
          <input type="number" v-model="paddingLength" placeholder="64" />
        </div>
        <div class="form-group">
          <label>填充字符</label>
          <input type="text" v-model="paddingPattern" placeholder="A" maxlength="1" />
        </div>
      </div>
      <div class="result-box">
        <div class="result-header">
          <span class="label">重复填充:</span>
          <button class="copy-btn" @click="copy(generatedPadding)">复制</button>
        </div>
        <pre class="padding-output">{{ generatedPadding }}</pre>
      </div>
      <div class="result-box">
        <div class="result-header">
          <span class="label">循环模式 (用于定位偏移):</span>
          <button class="copy-btn" @click="copy(cyclicPadding)">复制</button>
        </div>
        <pre class="padding-output">{{ cyclicPadding }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const activeTab = ref('address')

// 地址计算
const baseAddr = ref('')
const offset = ref('')
const addressResult = computed(() => {
  if (!baseAddr.value) return ''
  try {
    const base = BigInt(baseAddr.value.startsWith('0x') ? baseAddr.value : '0x' + baseAddr.value)
    const off = offset.value 
      ? BigInt(offset.value.startsWith('0x') || offset.value.startsWith('-') ? offset.value : '0x' + offset.value) 
      : 0n
    return '0x' + (base + off).toString(16)
  } catch (e) {
    return '计算错误'
  }
})

// 字节序转换
const byteInput = ref('')
const byteSize = ref('8')
const littleEndian = computed(() => {
  if (!byteInput.value) return ''
  try {
    let hex = byteInput.value.replace(/^0x/i, '').replace(/\s+/g, '')
    const size = parseInt(byteSize.value)
    hex = hex.padStart(size * 2, '0').slice(0, size * 2)
    const bytes = hex.match(/.{2}/g) || []
    return '0x' + bytes.reverse().join('')
  } catch (e) {
    return '转换错误'
  }
})

const bigEndian = computed(() => {
  if (!byteInput.value) return ''
  try {
    let hex = byteInput.value.replace(/^0x/i, '').replace(/\s+/g, '')
    const size = parseInt(byteSize.value)
    hex = hex.padStart(size * 2, '0').slice(0, size * 2)
    return '0x' + hex
  } catch (e) {
    return '转换错误'
  }
})

// Shellcode 格式化
const shellcodeInput = ref('')
const shellcodeFormat = ref('c')

function parseShellcode(input: string): string[] {
  return input
    .replace(/\\x/gi, ' ')
    .replace(/0x/gi, ' ')
    .replace(/,/g, ' ')
    .replace(/[^0-9a-fA-F\s]/g, '')
    .trim()
    .split(/\s+/)
    .filter(b => b.length === 2)
}

const formattedShellcode = computed(() => {
  if (!shellcodeInput.value) return ''
  const hex = parseShellcode(shellcodeInput.value)
  if (!hex.length) return '无法解析'
  
  switch (shellcodeFormat.value) {
    case 'c': return '"' + hex.map(b => '\\x' + b.toLowerCase()).join('') + '"'
    case 'python': return 'b"' + hex.map(b => '\\x' + b.toLowerCase()).join('') + '"'
    case 'hex': return hex.join(' ').toUpperCase()
    case 'array': return '{ ' + hex.map(b => '0x' + b.toUpperCase()).join(', ') + ' }'
    case 'nasm': return 'db ' + hex.map(b => '0x' + b.toLowerCase()).join(', ')
    default: return hex.join('')
  }
})

const shellcodeLength = computed(() => parseShellcode(shellcodeInput.value).length)

// Padding 生成
const paddingLength = ref('64')
const paddingPattern = ref('A')

const generatedPadding = computed(() => {
  const len = parseInt(paddingLength.value) || 0
  if (len > 10000) return '长度过大'
  return paddingPattern.value.repeat(len)
})

const cyclicPadding = computed(() => {
  const len = parseInt(paddingLength.value) || 0
  if (len > 10000) return '长度过大'
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < len; i++) {
    result += charset[i % charset.length]
  }
  return result
})

function copy(text: string) {
  navigator.clipboard.writeText(text)
}
</script>

<style scoped>
.pwn-helper {
  margin-top: 1.5rem;
}

.tabs {
  display: flex;
  gap: 0.5rem;
  border-bottom: 1px solid var(--vp-c-divider);
  padding-bottom: 0.5rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}

.tab {
  padding: 0.5rem 1rem;
  border: none;
  background: none;
  color: var(--vp-c-text-2);
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
}

.tab:hover {
  background: var(--vp-c-bg-soft);
}

.tab.active {
  background: var(--vp-c-brand);
  color: white;
}

.tab-content {
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.result-box {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1rem;
  margin-top: 1rem;
}

.result-box .label {
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
}

.result-box code {
  font-family: var(--vp-font-family-mono);
  margin-left: 0.5rem;
}

.result-box pre {
  margin: 0.5rem 0 0 0;
  font-size: 0.9rem;
  white-space: pre-wrap;
  word-break: break-all;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.copy-btn {
  padding: 0.25rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
}

.copy-btn:hover {
  background: var(--vp-c-bg-mute);
}

.format-btns {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.format-btns button {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
}

.format-btns button:hover {
  border-color: var(--vp-c-brand);
}

.format-btns button.active {
  background: var(--vp-c-brand);
  border-color: var(--vp-c-brand);
  color: white;
}

.endian-results {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.padding-output {
  max-height: 100px;
  overflow: auto;
}
</style>
