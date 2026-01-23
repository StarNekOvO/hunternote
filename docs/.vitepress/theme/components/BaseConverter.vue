<template>
  <div class="base-converter">
    <div class="converter-grid">
      <div class="field-group">
        <div class="field-header">
          <label class="field-label">十进制 (Decimal)</label>
          <button class="btn-sm" @click="copy(dec)" :disabled="!dec">复制</button>
        </div>
        <input type="text" class="field-input" v-model="dec" @input="onInput('dec', 10)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label class="field-label">二进制 (Binary)</label>
          <button class="btn-sm" @click="copy(bin)" :disabled="!bin">复制</button>
        </div>
        <input type="text" class="field-input" v-model="bin" @input="onInput('bin', 2)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label class="field-label">八进制 (Octal)</label>
          <button class="btn-sm" @click="copy(oct)" :disabled="!oct">复制</button>
        </div>
        <input type="text" class="field-input" v-model="oct" @input="onInput('oct', 8)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label class="field-label">十六进制 (Hexadecimal)</label>
          <button class="btn-sm" @click="copy(hex)" :disabled="!hex">复制</button>
        </div>
        <input type="text" class="field-input" v-model="hex" @input="onInput('hex', 16)" placeholder="0" />
      </div>
    </div>

    <div class="action-bar">
      <button class="btn-secondary" @click="clear">清空全部</button>
    </div>

    <div class="reference-panel">
      <div class="panel-header">
        <span class="panel-title">常用值参考</span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>描述</th>
            <th>十进制</th>
            <th>十六进制</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>1 字节最大值</td><td class="mono">255</td><td class="mono">FF</td></tr>
          <tr><td>2 字节最大值</td><td class="mono">65535</td><td class="mono">FFFF</td></tr>
          <tr><td>4 字节最大值</td><td class="mono">4294967295</td><td class="mono">FFFFFFFF</td></tr>
          <tr><td>32 位有符号最大</td><td class="mono">2147483647</td><td class="mono">7FFFFFFF</td></tr>
          <tr><td>页大小 (4KB)</td><td class="mono">4096</td><td class="mono">1000</td></tr>
        </tbody>
      </table>
    </div>

    <div v-if="!wasmReady" class="loading-hint">
      正在加载 WebAssembly 模块...
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ensureWasmLoaded, wasm } from '../wasm-loader'

const dec = ref('')
const bin = ref('')
const oct = ref('')
const hex = ref('')
const activeField = ref('')
const wasmReady = ref(false)

const patterns: Record<number, RegExp> = {
  2: /^[01]+$/,
  8: /^[0-7]+$/,
  10: /^-?\d+$/,
  16: /^[0-9a-fA-F]+$/
}

onMounted(async () => {
  await ensureWasmLoaded()
  wasmReady.value = true
})

function isValidNumber(str: string, base: number): boolean {
  if (!str) return true
  return patterns[base].test(str)
}

function convert(value: string, fromBase: number) {
  if (!value || !wasmReady.value) {
    dec.value = bin.value = oct.value = hex.value = ''
    return
  }
  
  try {
    const result = wasm.convert_base(value, fromBase)
    const parsed = JSON.parse(result)
    
    if (activeField.value !== 'dec') dec.value = parsed.dec
    if (activeField.value !== 'bin') bin.value = parsed.bin
    if (activeField.value !== 'oct') oct.value = parsed.oct
    if (activeField.value !== 'hex') hex.value = parsed.hex
  } catch (e) {
    // invalid input
  }
}

function onInput(field: string, base: number) {
  activeField.value = field
  const values: Record<string, typeof dec> = { dec, bin, oct, hex }
  const value = values[field].value
  if (isValidNumber(value, base)) {
    convert(value, base)
  }
}

function clear() {
  dec.value = bin.value = oct.value = hex.value = ''
}

function copy(value: string) {
  navigator.clipboard.writeText(value)
}
</script>

<style scoped>
.base-converter {
  margin-top: 1rem;
}

.converter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.field-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.field-label {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.btn-sm {
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

.field-input {
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.95rem;
  transition: border-color 0.15s ease;
}

.field-input:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.field-input::placeholder {
  color: var(--vp-c-text-3);
}

.action-bar {
  margin-top: 1.25rem;
}

.btn-secondary {
  padding: 0.5rem 1rem;
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

.reference-panel {
  margin-top: 2rem;
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

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: 0.6rem 1rem;
  text-align: left;
}

.data-table th {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  border-bottom: 1px solid var(--vp-c-divider);
}

.data-table td {
  font-size: 0.9rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.data-table tr:last-child td {
  border-bottom: none;
}

.data-table .mono {
  font-family: var(--vp-font-family-mono);
}

.loading-hint {
  margin-top: 1rem;
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.85rem;
}
</style>
