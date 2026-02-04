<template>
  <div class="terminal-container">
    <div class="scanlines"></div>
    <div class="terminal-content" ref="terminalBody">
      <pre class="ascii-art"> ____  _              _   _      _
/ ___|| |_ __ _ _ __ | \ | | ___| | _____
\___ \| __/ _` | '__|  \| |/ _ \ |/ / _ \
 ___) | || (_| | |  | |\  |  __/   &lt; (_) |
|____/ \__\__,_|_|  |_| \_|\___|_|\_\___/</pre>
      <div v-for="(block, idx) in visibleBlocks" :key="idx" class="output-block">
        <div class="command-line" v-if="block.command">
          <span class="prompt">$</span>
          <span class="command">{{ block.command }}</span>
        </div>
        <div class="output" v-html="block.output"></div>
      </div>
      <div class="command-line current" v-if="currentTyping">
        <span class="prompt">$</span>
        <span class="command">{{ currentCommand }}</span>
        <span class="cursor" :class="{ blink: !isTyping }"></span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'

interface OutputBlock {
  command: string
  output: string
}

const terminalBody = ref<HTMLElement | null>(null)
const visibleBlocks = ref<OutputBlock[]>([])
const currentCommand = ref('')
const currentTyping = ref(true)
const isTyping = ref(false)

const commands: OutputBlock[] = [
  {
    command: 'whoami',
    output: 'starneko <span class="dim">// aka misakabit</span>'
  },
  {
    command: 'cat /etc/profile',
    output: `System Security Hunter
Python / Go / Rust
MSCS @ CU Boulder
Freelancer`
  },
  {
    command: 'cat /proc/self/status',
    output: `Gender:   non-binary / queer
State:    unstable (with humans)
Memory:   volatile
Uptime:   timeless
Type:     INFJ-ish
Mode:     global-perfectionist`
  },
  {
    command: 'ps aux | grep career',
    output: `starneko  mscs         CU_Boulder          running
starneko  security     top10_fintech       running
starneko  audio_ml     prev_algo_company   exited
starneko  server_sec   prev_cybersec       exited`
  },
  {
    command: 'ls -la ~/interests',
    output: `drwxr-x---  irl/        shopping archery driving concerts
drwxr-x---  games/      arpg mmorpg fps sandbox maimaiDX
drwxr-x---  lang/       python go rust c c++
drwxr-x---  fields/     security gamedev graphics vr nlp
drwxr-x---  music/      yorushika`
  },
  {
    command: 'cat TODO.2026',
    output: `[ ] voice surgery prep
[ ] toefl <span class="dim"># no human examiners pls</span>
[ ] become a qualified system bug bounty hunter`
  },
  {
    command: '',
    output: ''
  }
]

const typeCommand = async (cmd: string): Promise<void> => {
  isTyping.value = true
  currentCommand.value = ''
  
  for (const char of cmd) {
    currentCommand.value += char
    await sleep(30 + Math.random() * 50)
  }
  
  isTyping.value = false
  await sleep(200)
}

const sleep = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms))
}

const scrollToBottom = () => {
  if (terminalBody.value) {
    terminalBody.value.scrollTop = terminalBody.value.scrollHeight
  }
}

const runTerminal = async () => {
  await sleep(800)
  
  for (let i = 0; i < commands.length - 1; i++) {
    const block = commands[i]
    
    await typeCommand(block.command)
    await sleep(150)
    
    visibleBlocks.value.push(block)
    currentCommand.value = ''
    
    await nextTick()
    scrollToBottom()
    
    await sleep(600)
  }
  
  currentTyping.value = true
  currentCommand.value = ''
}

onMounted(() => {
  runTerminal()
})
</script>

<style scoped>
.terminal-container {
  position: relative;
  min-height: calc(100vh - 64px);
  padding: 40px 20px;
  overflow: hidden;
}

.scanlines {
  position: absolute;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
  pointer-events: none;
  z-index: 10;
}

:root.dark .scanlines {
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 255, 65, 0.015) 2px,
    rgba(0, 255, 65, 0.015) 4px
  );
}

.terminal-content {
  max-width: 720px;
  margin: 0 auto;
  font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', Consolas, monospace;
  font-size: 14px;
  line-height: 1.7;
  color: #1a1a2e;
}

:root.dark .terminal-content {
  color: #00ff41;
  text-shadow: 0 0 5px rgba(0, 255, 65, 0.4);
}

.ascii-art {
  white-space: pre;
  font-size: 12px;
  line-height: 1.2;
  margin-bottom: 32px;
  color: #6366f1;
  opacity: 0.8;
}

:root.dark .ascii-art {
  color: #00ff41;
  text-shadow: 0 0 10px rgba(0, 255, 65, 0.6);
}

.output-block {
  margin-bottom: 20px;
}

.command-line {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.prompt {
  color: #10b981;
  font-weight: 700;
}

:root.dark .prompt {
  color: #00ff41;
}

.command {
  color: #3b82f6;
}

:root.dark .command {
  color: #fff;
  text-shadow: none;
}

.cursor {
  display: inline-block;
  width: 8px;
  height: 16px;
  background: #3b82f6;
  margin-left: 2px;
}

:root.dark .cursor {
  background: #00ff41;
  box-shadow: 0 0 8px rgba(0, 255, 65, 0.8);
}

.cursor.blink {
  animation: blink 1s step-end infinite;
}

@keyframes blink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0; }
}

.output {
  color: #374151;
  white-space: pre-wrap;
  word-break: break-word;
  padding-left: 16px;
  border-left: 2px solid rgba(99, 102, 241, 0.3);
}

:root.dark .output {
  color: rgba(0, 255, 65, 0.85);
  border-left-color: rgba(0, 255, 65, 0.3);
}

.output :deep(.dim) {
  opacity: 0.5;
}

/* Mobile */
@media (max-width: 640px) {
  .terminal-container {
    padding: 20px 16px;
  }
  
  .terminal-content {
    font-size: 12px;
  }
  
  .ascii-art {
    font-size: 8px;
    margin-bottom: 24px;
  }
}
</style>
