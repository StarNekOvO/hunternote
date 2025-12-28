<template>
  <div class="regex-tool">
    <div class="pattern-input">
      <div class="input-wrapper">
        <span class="delimiter">/</span>
        <input 
          type="text" 
          v-model="pattern"
          placeholder="输入正则表达式"
          class="pattern-field"
        />
        <span class="delimiter">/{{ flags.join('') }}</span>
      </div>
      <button class="copy-btn" @click="copyPattern" :disabled="!pattern">复制</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div class="flags">
      <span class="flags-label">标志:</span>
      <button 
        v-for="f in availableFlags" 
        :key="f.value"
        :class="['flag-btn', { active: flags.includes(f.value) }]"
        @click="toggleFlag(f.value)"
      >
        {{ f.label }}
      </button>
    </div>

    <div class="examples">
      <span class="examples-label">快速示例:</span>
      <button 
        v-for="ex in examples" 
        :key="ex.name"
        class="example-btn"
        @click="useExample(ex)"
      >
        {{ ex.name }}
      </button>
    </div>

    <div class="test-area">
      <div class="input-section">
        <label>测试文本</label>
        <textarea v-model="testText" placeholder="输入要测试的文本..." rows="6"></textarea>
      </div>

      <div class="result-section">
        <label>匹配结果 <span class="match-count" v-if="matches.length">({{ matches.length }} 处匹配)</span></label>
        <div class="highlighted-text" v-html="highlightedText || '结果将高亮显示...'"></div>
      </div>
    </div>

    <div v-if="matches.length" class="match-details">
      <h3>匹配详情</h3>
      <div class="match-list">
        <div v-for="(m, i) in matches" :key="i" class="match-item">
          <div class="match-header">
            <span class="match-index">#{{ i + 1 }}</span>
            <span class="match-pos">位置: {{ m.index }}</span>
          </div>
          <code class="match-value">{{ m.match }}</code>
          <div v-if="m.groups.length" class="match-groups">
            <span v-for="(g, gi) in m.groups" :key="gi" class="group">
              ${{ gi + 1 }}: {{ g || '(空)' }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const pattern = ref('')
const flags = ref(['g'])
const testText = ref('')
const error = ref('')

const availableFlags = [
  { value: 'g', label: 'g (全局)' },
  { value: 'i', label: 'i (忽略大小写)' },
  { value: 'm', label: 'm (多行)' },
  { value: 's', label: 's (dotAll)' },
]

const examples = [
  { name: '邮箱', pattern: '[\\w.-]+@[\\w.-]+\\.\\w+' },
  { name: 'IP 地址', pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b' },
  { name: 'URL', pattern: 'https?://[\\w.-]+(?:/[\\w./?%&=-]*)?' },
  { name: '十六进制', pattern: '0x[0-9a-fA-F]+' },
  { name: '中文字符', pattern: '[\\u4e00-\\u9fa5]+' },
]

function toggleFlag(flag: string) {
  const idx = flags.value.indexOf(flag)
  if (idx === -1) {
    flags.value.push(flag)
  } else {
    flags.value.splice(idx, 1)
  }
}

const regex = computed(() => {
  if (!pattern.value) return null
  try {
    error.value = ''
    return new RegExp(pattern.value, flags.value.join(''))
  } catch (e: any) {
    error.value = e.message
    return null
  }
})

interface Match {
  match: string
  index: number
  groups: string[]
}

const matches = computed<Match[]>(() => {
  if (!regex.value || !testText.value) return []
  
  const results: Match[] = []
  const re = new RegExp(pattern.value, flags.value.join(''))
  
  if (flags.value.includes('g')) {
    let match: RegExpExecArray | null
    while ((match = re.exec(testText.value)) !== null) {
      results.push({
        match: match[0],
        index: match.index,
        groups: match.slice(1)
      })
      if (match.index === re.lastIndex) re.lastIndex++
    }
  } else {
    const match = re.exec(testText.value)
    if (match) {
      results.push({
        match: match[0],
        index: match.index,
        groups: match.slice(1)
      })
    }
  }
  
  return results
})

const highlightedText = computed(() => {
  if (!regex.value || !testText.value || matches.value.length === 0) {
    return escapeHtml(testText.value)
  }
  
  let result = ''
  let lastIndex = 0
  
  for (const m of matches.value) {
    result += escapeHtml(testText.value.slice(lastIndex, m.index))
    result += `<mark>${escapeHtml(m.match)}</mark>`
    lastIndex = m.index + m.match.length
  }
  result += escapeHtml(testText.value.slice(lastIndex))
  
  return result
})

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function copyPattern() {
  navigator.clipboard.writeText(`/${pattern.value}/${flags.value.join('')}`)
}

function useExample(ex: { name: string; pattern: string }) {
  pattern.value = ex.pattern
}
</script>

<style scoped>
.regex-tool {
  margin-top: 1.5rem;
}

.pattern-input {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.input-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 0 0.75rem;
}

.delimiter {
  color: var(--vp-c-text-3);
  font-family: var(--vp-font-family-mono);
}

.pattern-field {
  flex: 1;
  border: none;
  background: none;
  padding: 0.75rem 0.5rem;
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 1rem;
}

.pattern-field:focus {
  outline: none;
}

.input-wrapper:focus-within {
  border-color: var(--vp-c-brand);
}

.copy-btn {
  padding: 0.75rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
}

.copy-btn:hover:not(:disabled) {
  background: var(--vp-c-bg-mute);
}

.copy-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error {
  margin-top: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--vp-c-danger-soft);
  color: var(--vp-c-danger-1);
  border-radius: 6px;
  font-size: 0.9rem;
}

.flags, .examples {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 1rem;
  flex-wrap: wrap;
}

.flags-label, .examples-label {
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
}

.flag-btn, .example-btn {
  padding: 0.35rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
  cursor: pointer;
}

.flag-btn:hover, .example-btn:hover {
  border-color: var(--vp-c-brand);
}

.flag-btn.active {
  background: var(--vp-c-brand);
  border-color: var(--vp-c-brand);
  color: white;
}

.test-area {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-top: 1.5rem;
}

@media (max-width: 768px) {
  .test-area {
    grid-template-columns: 1fr;
  }
}

.input-section label, .result-section label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.match-count {
  color: var(--vp-c-brand);
  font-weight: normal;
}

.input-section textarea {
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

.input-section textarea:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.highlighted-text {
  min-height: 150px;
  padding: 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--vp-c-text-2);
}

.highlighted-text :deep(mark) {
  background: var(--vp-c-brand);
  color: white;
  padding: 0 2px;
  border-radius: 2px;
}

.match-details {
  margin-top: 1.5rem;
}

.match-details h3 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
}

.match-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.match-item {
  background: var(--vp-c-bg-soft);
  border-radius: 6px;
  padding: 0.75rem;
}

.match-header {
  display: flex;
  gap: 1rem;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
}

.match-index {
  color: var(--vp-c-brand);
  font-weight: 600;
}

.match-pos {
  color: var(--vp-c-text-3);
}

.match-value {
  display: block;
  background: var(--vp-c-bg-alt);
  padding: 0.5rem;
  border-radius: 4px;
  word-break: break-all;
}

.match-groups {
  margin-top: 0.5rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.group {
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg-alt);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}
</style>
