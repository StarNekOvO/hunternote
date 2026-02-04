<template>
  <div class="ip-calculator">
    <!-- 输入区域 -->
    <div class="input-section">
      <label class="input-label">IP 地址 / CIDR</label>
      <input 
        v-model="input" 
        @input="calculate"
        class="input-field"
        placeholder="例如: 192.168.1.0/24 或 10.0.0.1"
      />
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>

    <!-- CIDR 信息 -->
    <div v-if="result" class="info-panel">
      <div class="panel-header">
        <span class="panel-title">CIDR 信息</span>
      </div>
      <table class="data-table">
        <tbody>
          <tr><td class="label-cell">IP 地址</td><td class="value-cell">{{ result.ip }}</td></tr>
          <tr><td class="label-cell">前缀长度</td><td class="value-cell">/{{ result.prefix }}</td></tr>
          <tr><td class="label-cell">子网掩码</td><td class="value-cell">{{ result.netmask }}</td></tr>
          <tr><td class="label-cell">通配符掩码</td><td class="value-cell">{{ result.wildcard }}</td></tr>
          <tr><td class="label-cell">网络地址</td><td class="value-cell">{{ result.network }}</td></tr>
          <tr><td class="label-cell">广播地址</td><td class="value-cell">{{ result.broadcast }}</td></tr>
          <tr><td class="label-cell">第一个主机</td><td class="value-cell">{{ result.firstHost }}</td></tr>
          <tr><td class="label-cell">最后一个主机</td><td class="value-cell">{{ result.lastHost }}</td></tr>
          <tr><td class="label-cell">可用主机数</td><td class="value-cell">{{ result.hostCount.toLocaleString() }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- IP 格式转换 -->
    <div v-if="result" class="info-panel">
      <div class="panel-header">
        <span class="panel-title">IP 格式转换</span>
      </div>
      <table class="data-table">
        <tbody>
          <tr><td class="label-cell">二进制</td><td class="value-cell mono">{{ ipBinary }}</td></tr>
          <tr><td class="label-cell">十六进制</td><td class="value-cell mono">0x{{ ipHex }}</td></tr>
          <tr><td class="label-cell">十进制</td><td class="value-cell mono">{{ ipDecimal }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- IP 属性 -->
    <div v-if="result" class="info-panel">
      <div class="panel-header">
        <span class="panel-title">IP 属性</span>
      </div>
      <table class="data-table">
        <tbody>
          <tr><td class="label-cell">IP 类别</td><td class="value-cell">{{ ipClass }}</td></tr>
          <tr><td class="label-cell">私有地址</td><td class="value-cell">{{ isPrivate ? '是' : '否' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 十进制转换 -->
    <div class="converter-panel">
      <div class="panel-header">
        <span class="panel-title">十进制 IP 转换</span>
      </div>
      <div class="converter-body">
        <input 
          v-model="decimalInput" 
          @input="convertDecimal"
          class="input-field compact"
          placeholder="输入十进制数字"
          type="number"
        />
        <span class="arrow-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M5 12h14M12 5l7 7-7 7"/>
          </svg>
        </span>
        <input :value="decimalResult" class="input-field compact" readonly placeholder="IP 地址" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ensureWasmLoaded, wasm as wasmModule } from '../wasm-loader'

const input = ref('192.168.1.0/24')
const result = ref(null)
const error = ref('')
const ipBinary = ref('')
const ipHex = ref('')
const ipDecimal = ref('')
const ipClass = ref('')
const isPrivate = ref(false)

const decimalInput = ref('')
const decimalResult = ref('')

let wasm = null

onMounted(async () => {
  await ensureWasmLoaded()
  wasm = wasmModule
  calculate()
})

function calculate() {
  if (!wasm || !input.value.trim()) {
    result.value = null
    error.value = ''
    return
  }

  try {
    // 如果没有前缀，默认加 /32
    let cidr = input.value.trim()
    if (!cidr.includes('/')) {
      cidr += '/32'
    }

    const json = wasm.parse_cidr(cidr)
    result.value = JSON.parse(json)
    error.value = ''

    // 获取额外信息
    const ip = result.value.ip
    ipBinary.value = wasm.ip_to_binary(ip)
    ipHex.value = wasm.ip_to_hex(ip)
    ipDecimal.value = wasm.ip_to_decimal(ip)
    ipClass.value = wasm.get_ip_class(ip)
    isPrivate.value = wasm.is_private_ip(ip)
  } catch (e) {
    result.value = null
    error.value = e.message || '解析失败'
  }
}

function convertDecimal() {
  if (!wasm || !decimalInput.value) {
    decimalResult.value = ''
    return
  }

  try {
    const num = parseInt(decimalInput.value)
    if (num < 0 || num > 4294967295) {
      decimalResult.value = '超出范围'
      return
    }
    decimalResult.value = wasm.decimal_to_ip(num)
  } catch (e) {
    decimalResult.value = '转换失败'
  }
}
</script>

<style scoped>
.ip-calculator {
  margin-top: 1rem;
}

/* 输入区域 */
.input-section {
  margin-bottom: 1.25rem;
}

.input-label {
  display: block;
  margin-bottom: 0.4rem;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.input-field {
  width: 100%;
  max-width: 400px;
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(8px);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.95rem;
  transition: border-color 0.15s ease;
}

:root.dark .input-field {
  background: rgba(0, 0, 0, 0.4);
}

.input-field:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.input-field.compact {
  max-width: 180px;
}

.error-box {
  padding: 0.65rem 0.85rem;
  background: var(--vp-c-danger-soft);
  color: var(--vp-c-danger-1);
  border-radius: 6px;
  font-size: 0.85rem;
  margin-bottom: 1rem;
}

/* 信息面板 */
.info-panel,
.converter-panel {
  background: rgba(255, 255, 255, 0.4);
  backdrop-filter: blur(8px);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 1rem;
}

:root.dark .info-panel,
:root.dark .converter-panel {
  background: rgba(0, 0, 0, 0.3);
}

.panel-header {
  padding: 0.65rem 0.85rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.panel-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

/* 数据表格 */
.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table td {
  padding: 0.55rem 0.85rem;
  font-size: 0.9rem;
}

.data-table tr:not(:last-child) td {
  border-bottom: 1px solid var(--vp-c-divider);
}

.label-cell {
  width: 130px;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.value-cell {
  font-family: var(--vp-font-family-mono);
}

.mono {
  word-break: break-all;
}

/* 转换区域 */
.converter-body {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.85rem;
  flex-wrap: wrap;
}

.arrow-icon {
  color: var(--vp-c-text-3);
  display: flex;
  align-items: center;
}
</style>
