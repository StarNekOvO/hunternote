<template>
  <div class="base-converter">
    <div class="converter-grid">
      <div class="field-group">
        <div class="field-header">
          <label>十进制 (Decimal)</label>
          <button class="copy-btn" @click="copy(dec)" :disabled="!dec">复制</button>
        </div>
        <input type="text" v-model="dec" @input="onInput('dec', 10)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label>二进制 (Binary)</label>
          <button class="copy-btn" @click="copy(bin)" :disabled="!bin">复制</button>
        </div>
        <input type="text" v-model="bin" @input="onInput('bin', 2)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label>八进制 (Octal)</label>
          <button class="copy-btn" @click="copy(oct)" :disabled="!oct">复制</button>
        </div>
        <input type="text" v-model="oct" @input="onInput('oct', 8)" placeholder="0" />
      </div>

      <div class="field-group">
        <div class="field-header">
          <label>十六进制 (Hexadecimal)</label>
          <button class="copy-btn" @click="copy(hex)" :disabled="!hex">复制</button>
        </div>
        <input type="text" v-model="hex" @input="onInput('hex', 16)" placeholder="0" />
      </div>
    </div>

    <div class="actions">
      <button class="clear-btn" @click="clear">清空全部</button>
    </div>

    <div class="tips">
      <h3>常用值参考</h3>
      <table>
        <thead>
          <tr>
            <th>描述</th>
            <th>十进制</th>
            <th>十六进制</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>1 字节最大值</td><td>255</td><td>FF</td></tr>
          <tr><td>2 字节最大值</td><td>65535</td><td>FFFF</td></tr>
          <tr><td>4 字节最大值</td><td>4294967295</td><td>FFFFFFFF</td></tr>
          <tr><td>32 位有符号最大</td><td>2147483647</td><td>7FFFFFFF</td></tr>
          <tr><td>页大小 (4KB)</td><td>4096</td><td>1000</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const dec = ref('')
const bin = ref('')
const oct = ref('')
const hex = ref('')
const activeField = ref('')

const patterns: Record<number, RegExp> = {
  2: /^[01]+$/,
  8: /^[0-7]+$/,
  10: /^-?\d+$/,
  16: /^[0-9a-fA-F]+$/
}

function isValidNumber(str: string, base: number): boolean {
  if (!str) return true
  return patterns[base].test(str)
}

function convert(value: string, fromBase: number) {
  if (!value) {
    dec.value = bin.value = oct.value = hex.value = ''
    return
  }
  
  try {
    const prefix = { 2: '0b', 8: '0o', 16: '0x' } as Record<number, string>
    const num = BigInt(fromBase === 10 ? value : prefix[fromBase] + value)
    
    if (activeField.value !== 'dec') dec.value = num.toString(10)
    if (activeField.value !== 'bin') bin.value = num.toString(2)
    if (activeField.value !== 'oct') oct.value = num.toString(8)
    if (activeField.value !== 'hex') hex.value = num.toString(16).toUpperCase()
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
  margin-top: 1.5rem;
}

.converter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

.field-group {
  display: flex;
  flex-direction: column;
}

.field-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.field-header label {
  font-weight: 500;
  color: var(--vp-c-text-1);
}

.copy-btn {
  padding: 0.2rem 0.6rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
}

.copy-btn:hover:not(:disabled) {
  background: var(--vp-c-bg-mute);
}

.copy-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 1rem;
}

input:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.actions {
  margin-top: 1rem;
}

.clear-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
}

.clear-btn:hover {
  background: var(--vp-c-bg-mute);
}

.tips {
  margin-top: 2rem;
  padding: 1rem;
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
}

.tips h3 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
}

.tips table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
}

.tips th, .tips td {
  padding: 0.5rem;
  text-align: left;
  border-bottom: 1px solid var(--vp-c-divider);
}

.tips th {
  color: var(--vp-c-text-2);
  font-weight: 500;
}
</style>
