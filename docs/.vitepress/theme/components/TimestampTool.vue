<template>
  <div class="timestamp-tool">
    <div class="current-time">
      <div class="current-label">当前 Unix 时间戳</div>
      <div class="current-value" @click="useCurrentTimestamp">
        {{ currentTimestamp }}
        <span class="click-hint">点击使用</span>
      </div>
    </div>

    <div class="converter-sections">
      <div class="section">
        <h3>时间戳 → 日期</h3>
        <div class="input-row">
          <input 
            type="text" 
            v-model="timestampInput"
            @input="timestampToDate"
            placeholder="输入时间戳（秒或毫秒）"
          />
        </div>
        <div v-if="convertedDate" class="result">
          <pre>{{ convertedDate }}</pre>
          <button class="copy-btn" @click="copy(convertedDate)">复制</button>
        </div>
      </div>

      <div class="section">
        <h3>日期 → 时间戳</h3>
        <div class="input-row">
          <input 
            type="datetime-local" 
            v-model="dateInput"
            @input="dateToTimestamp"
          />
          <button class="now-btn" @click="useNow">现在</button>
        </div>
        <div v-if="convertedTimestamp" class="result">
          <pre>{{ convertedTimestamp }}</pre>
          <button class="copy-btn" @click="copy(convertedTimestamp)">复制</button>
        </div>
      </div>
    </div>

    <div class="reference">
      <h3>常用时间戳参考</h3>
      <table>
        <thead>
          <tr>
            <th>描述</th>
            <th>时间戳</th>
            <th>日期</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Unix 纪元</td><td>0</td><td>1970-01-01 00:00:00 UTC</td></tr>
          <tr><td>Y2K</td><td>946684800</td><td>2000-01-01 00:00:00 UTC</td></tr>
          <tr><td>32 位溢出</td><td>2147483647</td><td>2038-01-19 03:14:07 UTC</td></tr>
        </tbody>
      </table>
    </div>

    <div v-if="!wasmReady" class="loading-hint">
      正在加载 WebAssembly 模块...
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { ensureWasmLoaded, wasm } from '../wasm-loader'

const currentTimestamp = ref(0)
const timestampInput = ref('')
const dateInput = ref('')
const convertedDate = ref('')
const convertedTimestamp = ref('')
const wasmReady = ref(false)

let timer: ReturnType<typeof setInterval> | null = null

onMounted(async () => {
  await ensureWasmLoaded()
  wasmReady.value = true
  updateCurrent()
  timer = setInterval(updateCurrent, 1000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

function updateCurrent() {
  currentTimestamp.value = Math.floor(Date.now() / 1000)
}

function timestampToDate() {
  if (!timestampInput.value || !wasmReady.value) {
    convertedDate.value = ''
    return
  }
  
  try {
    let ts = parseInt(timestampInput.value)
    if (isNaN(ts)) {
      convertedDate.value = '无效时间戳'
      return
    }
    
    // Use Wasm for UTC calculation
    const result = wasm.timestamp_to_date(ts)
    const parsed = JSON.parse(result)
    
    const pad = (n: number) => n.toString().padStart(2, '0')
    const utc = `${parsed.year}-${pad(parsed.month)}-${pad(parsed.day)} ${pad(parsed.hours)}:${pad(parsed.minutes)}:${pad(parsed.seconds)}`
    
    // Calculate local time using JS Date (because timezone info needed)
    let localTs = ts
    if (localTs > 9999999999) localTs = Math.floor(localTs / 1000)
    const date = new Date(localTs * 1000)
    const local = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
    
    const relative = getRelativeTime(date)
    
    convertedDate.value = `本地时间: ${local}\nUTC: ${utc}\n相对时间: ${relative}`
  } catch (e) {
    convertedDate.value = '转换错误'
  }
}

function dateToTimestamp() {
  if (!dateInput.value || !wasmReady.value) {
    convertedTimestamp.value = ''
    return
  }
  
  try {
    // Parse datetime-local input
    const [datePart, timePart] = dateInput.value.split('T')
    const [year, month, day] = datePart.split('-').map(Number)
    const [hours, minutes] = timePart.split(':').map(Number)
    
    // Use Wasm for calculation (UTC)
    const ts = wasm.date_to_timestamp(year, month, day, hours, minutes, 0)
    
    // Also calculate local using JS for comparison
    const date = new Date(dateInput.value)
    const localTs = Math.floor(date.getTime() / 1000)
    
    convertedTimestamp.value = `本地: ${localTs}\n本地(毫秒): ${localTs * 1000}\nUTC: ${ts}`
  } catch (e) {
    convertedTimestamp.value = '转换错误'
  }
}

function getRelativeTime(date: Date): string {
  const now = new Date()
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000)
  
  if (diff < 0) {
    const absDiff = Math.abs(diff)
    if (absDiff < 60) return `${absDiff} 秒后`
    if (absDiff < 3600) return `${Math.floor(absDiff / 60)} 分钟后`
    if (absDiff < 86400) return `${Math.floor(absDiff / 3600)} 小时后`
    return `${Math.floor(absDiff / 86400)} 天后`
  }
  
  if (diff < 60) return `${diff} 秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  if (diff < 2592000) return `${Math.floor(diff / 86400)} 天前`
  if (diff < 31536000) return `${Math.floor(diff / 2592000)} 个月前`
  return `${Math.floor(diff / 31536000)} 年前`
}

function useCurrentTimestamp() {
  timestampInput.value = currentTimestamp.value.toString()
  timestampToDate()
}

function useNow() {
  const now = new Date()
  const pad = (n: number) => n.toString().padStart(2, '0')
  dateInput.value = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}`
  dateToTimestamp()
}

function copy(text: string) {
  const firstLine = text.split('\n')[0].replace(/.*: /, '')
  navigator.clipboard.writeText(firstLine)
}
</script>

<style scoped>
.timestamp-tool {
  margin-top: 1.5rem;
}

.loading-hint {
  padding: 1rem;
  text-align: center;
  color: var(--vp-c-text-3);
  font-size: 0.9rem;
}

.current-time {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1.5rem;
  text-align: center;
  margin-bottom: 1.5rem;
}

.current-label {
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
  margin-bottom: 0.5rem;
}

.current-value {
  font-family: var(--vp-font-family-mono);
  font-size: 2rem;
  font-weight: 600;
  color: var(--vp-c-brand);
  cursor: pointer;
  position: relative;
}

.click-hint {
  position: absolute;
  bottom: -1.5rem;
  left: 50%;
  transform: translateX(-50%);
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
  opacity: 0;
  transition: opacity 0.2s;
}

.current-value:hover .click-hint {
  opacity: 1;
}

.converter-sections {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}

.section {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1rem;
}

.section h3 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
  color: var(--vp-c-text-1);
}

.input-row {
  display: flex;
  gap: 0.5rem;
}

.input-row input {
  flex: 1;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
}

.input-row input:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.now-btn {
  padding: 0.75rem 1rem;
  border: 1px solid var(--vp-c-brand);
  border-radius: 6px;
  background: var(--vp-c-brand);
  color: white;
  cursor: pointer;
}

.result {
  margin-top: 1rem;
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
}

.result pre {
  flex: 1;
  margin: 0;
  padding: 0.75rem;
  background: var(--vp-c-bg);
  border-radius: 6px;
  font-size: 0.85rem;
  white-space: pre-wrap;
}

.copy-btn {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
}

.copy-btn:hover {
  background: var(--vp-c-brand);
  color: white;
}

.reference {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1rem;
}

.reference h3 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
  color: var(--vp-c-text-1);
}

.reference table {
  width: 100%;
  border-collapse: collapse;
}

.reference th,
.reference td {
  padding: 0.5rem;
  text-align: left;
  border-bottom: 1px solid var(--vp-c-divider);
}

.reference th {
  color: var(--vp-c-text-2);
  font-weight: 500;
}

.reference td {
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
}
</style>
