<template>
  <div class="timestamp-tool">
    <!-- 当前时间戳显示 -->
    <div class="current-panel" @click="useCurrentTimestamp">
      <span class="current-label">当前 Unix 时间戳</span>
      <span class="current-value">{{ currentTimestamp }}</span>
      <span class="current-hint">点击使用</span>
    </div>

    <!-- 转换区域 -->
    <div class="converter-grid">
      <!-- 时间戳转日期 -->
      <div class="converter-card">
        <div class="card-header">
          <span class="card-title">时间戳 → 日期</span>
        </div>
        <div class="card-body">
          <input 
            type="text" 
            class="field-input"
            v-model="timestampInput"
            @input="timestampToDate"
            placeholder="输入时间戳（秒或毫秒）"
          />
          <div v-if="convertedDate" class="result-box">
            <pre class="result-content">{{ convertedDate }}</pre>
            <button class="btn-sm" @click="copy(convertedDate)">复制</button>
          </div>
        </div>
      </div>

      <!-- 日期转时间戳 -->
      <div class="converter-card">
        <div class="card-header">
          <span class="card-title">日期 → 时间戳</span>
        </div>
        <div class="card-body">
          <div class="input-group">
            <input 
              type="datetime-local" 
              class="field-input"
              v-model="dateInput"
              @input="dateToTimestamp"
            />
            <button class="btn-primary" @click="useNow">现在</button>
          </div>
          <div v-if="convertedTimestamp" class="result-box">
            <pre class="result-content">{{ convertedTimestamp }}</pre>
            <button class="btn-sm" @click="copy(convertedTimestamp)">复制</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 参考表 -->
    <div class="reference-panel">
      <div class="panel-header">
        <span class="panel-title">常用时间戳参考</span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>描述</th>
            <th>时间戳</th>
            <th>日期</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Unix 纪元</td><td class="mono">0</td><td class="mono">1970-01-01 00:00:00 UTC</td></tr>
          <tr><td>Y2K</td><td class="mono">946684800</td><td class="mono">2000-01-01 00:00:00 UTC</td></tr>
          <tr><td>32 位溢出</td><td class="mono">2147483647</td><td class="mono">2038-01-19 03:14:07 UTC</td></tr>
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
  margin-top: 1rem;
}

/* 当前时间戳面板 */
.current-panel {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1.5rem;
  background: var(--vp-c-bg-soft);
  border-radius: 10px;
  margin-bottom: 1.5rem;
  cursor: pointer;
  transition: all 0.2s ease;
}

.current-panel:hover {
  background: var(--vp-c-bg-elv);
}

.current-panel:hover .current-hint {
  opacity: 1;
}

.current-label {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  margin-bottom: 0.25rem;
}

.current-value {
  font-family: var(--vp-font-family-mono);
  font-size: 2rem;
  font-weight: 600;
  color: var(--vp-c-brand);
}

.current-hint {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
  margin-top: 0.5rem;
  opacity: 0;
  transition: opacity 0.2s ease;
}

/* 转换卡片网格 */
.converter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.converter-card {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  overflow: hidden;
}

.card-header {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.card-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.card-body {
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.input-group {
  display: flex;
  gap: 0.5rem;
}

.field-input {
  flex: 1;
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  transition: border-color 0.15s ease;
}

.field-input:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.btn-primary {
  flex-shrink: 0;
  padding: 0.7rem 1rem;
  border: none;
  border-radius: 6px;
  background: var(--vp-c-brand);
  color: white;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-primary:hover {
  background: var(--vp-c-brand-dark);
}

.result-box {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
}

.result-content {
  flex: 1;
  margin: 0;
  padding: 0.65rem 0.75rem;
  background: var(--vp-c-bg);
  border-radius: 6px;
  font-size: 0.85rem;
  line-height: 1.5;
  white-space: pre-wrap;
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

.btn-sm:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand);
  color: white;
}

/* 参考表 */
.reference-panel {
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
