<template>
  <div class="regex-tool">
    <!-- 正则表达式输入 -->
    <div class="pattern-row">
      <div class="pattern-wrapper">
        <span class="pattern-delim">/</span>
        <input 
          type="text" 
          v-model="pattern"
          placeholder="输入正则表达式"
          class="pattern-input"
        />
        <span class="pattern-delim">/{{ flags.join('') }}</span>
      </div>
      <button class="btn-sm" @click="copyPattern" :disabled="!pattern">复制</button>
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>

    <!-- 标志选择 -->
    <div class="option-row">
      <span class="option-label">标志</span>
      <div class="mode-buttons">
        <button 
          v-for="f in availableFlags" 
          :key="f.value"
          :class="['mode-btn', { active: flags.includes(f.value) }]"
          @click="toggleFlag(f.value)"
        >
          {{ f.label }}
        </button>
      </div>
    </div>

    <!-- 快速示例 -->
    <div class="option-row">
      <span class="option-label">示例</span>
      <div class="mode-buttons">
        <button 
          v-for="ex in examples" 
          :key="ex.name"
          class="mode-btn"
          @click="useExample(ex)"
        >
          {{ ex.name }}
        </button>
      </div>
    </div>

    <!-- 测试区域 -->
    <div class="test-grid">
      <div class="test-panel">
        <div class="panel-header">
          <span class="panel-title">测试文本</span>
        </div>
        <textarea 
          v-model="testText" 
          class="test-textarea"
          placeholder="输入要测试的文本..." 
          rows="8"
        ></textarea>
      </div>

      <div class="test-panel">
        <div class="panel-header">
          <span class="panel-title">匹配结果</span>
          <span class="match-badge" v-if="matches.length">{{ matches.length }} 处匹配</span>
        </div>
        <div class="result-display" v-html="highlightedText || '<span class=&quot;placeholder&quot;>结果将高亮显示...</span>'"></div>
      </div>
    </div>

    <!-- 匹配详情 -->
    <div v-if="matches.length" class="details-panel">
      <div class="panel-header">
        <span class="panel-title">匹配详情</span>
      </div>
      <div class="details-list">
        <div v-for="(m, i) in matches" :key="i" class="detail-item">
          <div class="detail-meta">
            <span class="detail-index">#{{ i + 1 }}</span>
            <span class="detail-pos">位置: {{ m.index }}</span>
          </div>
          <code class="detail-value">{{ m.match }}</code>
          <div v-if="m.groups.length" class="detail-groups">
            <span v-for="(g, gi) in m.groups" :key="gi" class="group-tag">
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
  margin-top: 1rem;
}

/* 正则输入行 */
.pattern-row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-bottom: 1rem;
}

.pattern-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 0 0.75rem;
  transition: border-color 0.15s ease;
}

.pattern-wrapper:focus-within {
  border-color: var(--vp-c-brand);
}

.pattern-delim {
  color: var(--vp-c-text-3);
  font-family: var(--vp-font-family-mono);
}

.pattern-input {
  flex: 1;
  border: none;
  background: none;
  padding: 0.75rem 0.5rem;
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.95rem;
}

.pattern-input:focus {
  outline: none;
}

.btn-sm {
  flex-shrink: 0;
  padding: 0.6rem 0.85rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
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

.error-box {
  margin-bottom: 1rem;
  padding: 0.6rem 0.85rem;
  background: var(--vp-c-danger-soft);
  color: var(--vp-c-danger-1);
  border-radius: 6px;
  font-size: 0.85rem;
}

/* 选项行 */
.option-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}

.option-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  min-width: 36px;
}

.mode-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.mode-btn {
  padding: 0.4rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 5px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.mode-btn:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-text-1);
}

.mode-btn.active {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
  font-weight: 500;
}

/* 测试区域 */
.test-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-top: 1.25rem;
}

@media (max-width: 768px) {
  .test-grid {
    grid-template-columns: 1fr;
  }
}

.test-panel {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  overflow: hidden;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.65rem 0.85rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.panel-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.match-badge {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
}

.test-textarea {
  width: 100%;
  padding: 0.75rem;
  border: none;
  background: transparent;
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  resize: vertical;
}

.test-textarea:focus {
  outline: none;
}

.result-display {
  min-height: 190px;
  padding: 0.75rem;
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--vp-c-text-1);
}

.result-display :deep(.placeholder) {
  color: var(--vp-c-text-3);
}

.result-display :deep(mark) {
  background: var(--vp-c-brand);
  color: white;
  padding: 0.05em 0.15em;
  border-radius: 2px;
}

/* 详情面板 */
.details-panel {
  margin-top: 1.25rem;
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  overflow: hidden;
}

.details-list {
  padding: 0.5rem 0.85rem;
}

.detail-item {
  padding: 0.65rem 0;
}

.detail-item:not(:last-child) {
  border-bottom: 1px solid var(--vp-c-divider);
}

.detail-meta {
  display: flex;
  gap: 1rem;
  margin-bottom: 0.4rem;
  font-size: 0.8rem;
}

.detail-index {
  color: var(--vp-c-brand);
  font-weight: 600;
}

.detail-pos {
  color: var(--vp-c-text-3);
}

.detail-value {
  display: block;
  background: var(--vp-c-bg);
  padding: 0.4rem 0.6rem;
  border-radius: 4px;
  font-size: 0.85rem;
  word-break: break-all;
}

.detail-groups {
  margin-top: 0.5rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.group-tag {
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
}
</style>
