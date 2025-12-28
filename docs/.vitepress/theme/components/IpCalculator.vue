<template>
  <div class="ip-calculator">
    <div class="input-section">
      <label>IP 地址 / CIDR</label>
      <input 
        v-model="input" 
        @input="calculate"
        placeholder="例如: 192.168.1.0/24 或 10.0.0.1"
      />
    </div>

    <div v-if="result" class="result-section">
      <h3>CIDR 信息</h3>
      <table class="info-table">
        <tbody>
          <tr><td>IP 地址</td><td>{{ result.ip }}</td></tr>
          <tr><td>前缀长度</td><td>/{{ result.prefix }}</td></tr>
          <tr><td>子网掩码</td><td>{{ result.netmask }}</td></tr>
          <tr><td>通配符掩码</td><td>{{ result.wildcard }}</td></tr>
          <tr><td>网络地址</td><td>{{ result.network }}</td></tr>
          <tr><td>广播地址</td><td>{{ result.broadcast }}</td></tr>
          <tr><td>第一个主机</td><td>{{ result.firstHost }}</td></tr>
          <tr><td>最后一个主机</td><td>{{ result.lastHost }}</td></tr>
          <tr><td>可用主机数</td><td>{{ result.hostCount.toLocaleString() }}</td></tr>
        </tbody>
      </table>

      <h3>IP 格式转换</h3>
      <table class="info-table">
        <tbody>
          <tr><td>二进制</td><td class="mono">{{ ipBinary }}</td></tr>
          <tr><td>十六进制</td><td class="mono">0x{{ ipHex }}</td></tr>
          <tr><td>十进制</td><td class="mono">{{ ipDecimal }}</td></tr>
        </tbody>
      </table>

      <h3>IP 属性</h3>
      <table class="info-table">
        <tbody>
          <tr><td>IP 类别</td><td>{{ ipClass }}</td></tr>
          <tr><td>私有地址</td><td>{{ isPrivate ? '是' : '否' }}</td></tr>
        </tbody>
      </table>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div class="converter-section">
      <h3>十进制 IP 转换</h3>
      <div class="inline-convert">
        <input 
          v-model="decimalInput" 
          @input="convertDecimal"
          placeholder="输入十进制数字"
          type="number"
        />
        <span class="arrow">→</span>
        <input :value="decimalResult" readonly placeholder="IP 地址" />
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
  padding: 1rem 0;
}

.input-section {
  margin-bottom: 1.5rem;
}

.input-section label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.input-section input {
  width: 100%;
  max-width: 400px;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-border);
  border-radius: 6px;
  font-size: 1rem;
  font-family: var(--vp-font-family-mono);
}

.result-section h3 {
  margin-top: 1.5rem;
  margin-bottom: 0.75rem;
  font-size: 1rem;
  color: var(--vp-c-text-1);
}

.info-table {
  width: 100%;
  max-width: 500px;
  border-collapse: collapse;
}

.info-table td {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--vp-c-border);
}

.info-table tr td:first-child {
  width: 140px;
  font-weight: 500;
  background: var(--vp-c-bg-soft);
}

.info-table tr td:last-child {
  font-family: var(--vp-font-family-mono);
}

.mono {
  font-family: var(--vp-font-family-mono);
  word-break: break-all;
}

.error {
  color: var(--vp-c-danger-1);
  padding: 0.75rem;
  background: var(--vp-c-danger-soft);
  border-radius: 6px;
  margin-top: 1rem;
}

.converter-section {
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--vp-c-border);
}

.converter-section h3 {
  margin-bottom: 0.75rem;
  font-size: 1rem;
}

.inline-convert {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.inline-convert input {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--vp-c-border);
  border-radius: 6px;
  font-family: var(--vp-font-family-mono);
  width: 180px;
}

.arrow {
  color: var(--vp-c-text-3);
  font-size: 1.2rem;
}
</style>
