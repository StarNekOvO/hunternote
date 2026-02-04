<template>
  <div class="terminal-container">
    <div class="scanlines"></div>
    <div class="terminal-content" ref="terminalBody" @click="focusInput">
      <pre class="ascii-art"> ____  _              _   _      _
/ ___|| |_ __ _ _ __ | \ | | ___| | _____
\___ \| __/ _` | '__|  \| |/ _ \ |/ / _ \
 ___) | || (_| | |  | |\  |  __/   &lt; (_) |
|____/ \__\__,_|_|  |_| \_|\___|_|\_\___/</pre>
      <div v-for="(block, idx) in visibleBlocks" :key="idx" class="output-block">
        <div class="command-line" v-if="block.command">
          <span class="prompt">{{ block.prompt }}</span>
          <span class="command">{{ block.command }}</span>
        </div>
        <div class="output" v-html="block.output"></div>
      </div>
      <!-- Interactive input -->
      <div class="command-line interactive" v-if="isInteractive">
        <span class="prompt">{{ getPrompt() }}</span>
        <span class="input-display">{{ userInput }}</span>
        <span class="cursor" :class="{ blink: true }"></span>
        <input
          ref="inputEl"
          v-model="userInput"
          @keydown="handleKeydown"
          type="text"
          class="terminal-input-hidden"
          spellcheck="false"
          autocomplete="off"
          aria-hidden="true"
          tabindex="-1"
        />
      </div>
      <!-- Typing animation -->
      <div class="command-line current" v-else-if="currentTyping">
        <span class="prompt">{{ getPrompt() }}</span>
        <span class="command">{{ currentCommand }}</span>
        <span class="cursor" :class="{ blink: !isTyping }"></span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'

interface OutputBlock {
  prompt?: string
  command: string
  output: string
}

interface FSNode {
  type: 'file' | 'dir'
  content?: string
  children?: Record<string, FSNode>
}

interface CTFConfig {
  version: number
  name: string
  difficulty: string
  category: string
  binary: string
  binaryType?: string
  hint: string
  tools: string
  keyHash: string
  encryptedFlag: string
  successMessage: string
}

// Virtual File System
const fileSystem: Record<string, FSNode> = {
  '/': {
    type: 'dir',
    children: {
      'bin': { type: 'dir', children: {} },
      'ctf': {
        type: 'dir',
        children: {
          // This is a virtual placeholder for the downloadable challenge binary.
          // Real file is served from docs/public (same URL path).
          're_checkin': { type: 'file', content: '::BINARY::' }
        }
      },
      'etc': {
        type: 'dir',
        children: {
          'profile': {
            type: 'file',
            content: `System Security Hunter
Python / Go / Rust
MSCS @ CU Boulder
Freelancer`
          }
        }
      },
      'flag': {
        type: 'file',
        content: '::ENCRYPTED::'
      },
      'home': {
        type: 'dir',
        children: {
          'starneko': {
            type: 'dir',
            children: {
              'TODO.2026': {
                type: 'file',
                content: `[ ] voice surgery prep
[ ] toefl (no human examiners pls)
[ ] become a qualified bug bounty hunter`
              },
              'interests': {
                type: 'dir',
                children: {
                  'irl': { type: 'file', content: 'shopping archery driving concerts' },
                  'games': { type: 'file', content: 'arpg mmorpg fps sandbox maimaiDX' },
                  'lang': { type: 'file', content: 'python go rust c c++' },
                  'fields': { type: 'file', content: 'security gamedev graphics vr nlp' },
                  'music': { type: 'file', content: 'yorushika' }
                }
              },
              '.status': {
                type: 'file',
                content: `Gender:   non-binary / queer
State:    unstable (with humans)
Memory:   volatile
Uptime:   timeless
Type:     INFJ-ish
Mode:     global-perfectionist`
              }
            }
          }
        }
      },
      'proc': {
        type: 'dir',
        children: {
          'self': {
            type: 'dir',
            children: {
              'status': {
                type: 'file',
                content: `Name:     starneko
State:    R (running)
Pid:      1337
Uid:      1000
Gid:      1000`
              }
            }
          }
        }
      },
      'tmp': { type: 'dir', children: {} }
    }
  }
}

// State
const terminalBody = ref<HTMLElement | null>(null)
const inputEl = ref<HTMLInputElement | null>(null)
const visibleBlocks = ref<OutputBlock[]>([])
const currentCommand = ref('')
const currentTyping = ref(true)
const isTyping = ref(false)
const isInteractive = ref(false)
const userInput = ref('')
const cwd = ref('/home/starneko')
const commandHistory: string[] = []
let historyIndex = -1
let ctfConfig: CTFConfig | null = null

const MAX_BLOCKS = 200

// Intro commands
const introCommands: OutputBlock[] = [
  { command: 'whoami', output: 'starneko <span class="dim">// aka misakabit</span>' },
  { command: 'cat /etc/profile', output: '' },
  { command: 'cat .status', output: '' },
  { command: 'ls interests/', output: '' },
  { command: 'cat TODO.2026', output: '' },
]

// Utils
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

const escapeHtml = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')

const pushBlock = (block: OutputBlock) => {
  visibleBlocks.value.push(block)
  if (visibleBlocks.value.length > MAX_BLOCKS) {
    visibleBlocks.value.splice(0, visibleBlocks.value.length - MAX_BLOCKS)
  }
}

const splitArgs = (input: string): string[] => {
  const out: string[] = []
  let cur = ''
  let quote: '"' | "'" | null = null
  let escaped = false

  for (const ch of input) {
    if (escaped) {
      cur += ch
      escaped = false
      continue
    }
    if (ch === '\\') {
      escaped = true
      continue
    }
    if (quote) {
      if (ch === quote) quote = null
      else cur += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (/\s/.test(ch)) {
      if (cur) {
        out.push(cur)
        cur = ''
      }
      continue
    }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}

const getPrompt = () => {
  const home = '/home/starneko'
  let display = cwd.value
  if (cwd.value === home) display = '~'
  else if (cwd.value.startsWith(home + '/')) display = '~' + cwd.value.slice(home.length)
  return `starneko:${display}$ `
}

const resolvePath = (path: string): string => {
  if (!path) return cwd.value
  
  let resolved: string
  if (path.startsWith('/')) {
    resolved = path
  } else if (path.startsWith('~')) {
    resolved = '/home/starneko' + path.slice(1)
  } else {
    resolved = cwd.value + '/' + path
  }
  
  // Normalize path
  const parts = resolved.split('/').filter(Boolean)
  const stack: string[] = []
  for (const part of parts) {
    if (part === '..') stack.pop()
    else if (part !== '.') stack.push(part)
  }
  return '/' + stack.join('/')
}

const getNode = (path: string): FSNode | null => {
  const resolved = resolvePath(path)
  if (resolved === '/') return fileSystem['/']
  
  const parts = resolved.split('/').filter(Boolean)
  let node = fileSystem['/']
  
  for (const part of parts) {
    if (node.type !== 'dir' || !node.children?.[part]) return null
    node = node.children[part]
  }
  return node
}

const sha256 = async (str: string): Promise<string> => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

const xorDecrypt = (encryptedB64: string, key: string): string => {
  const encrypted = atob(encryptedB64)
  let result = ''
  for (let i = 0; i < encrypted.length; i++) {
    result += String.fromCharCode(encrypted.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return result
}

// Commands
const executeCommand = async (input: string): Promise<string> => {
  const trimmed = input.trim()
  if (!trimmed) return ''

  const parts = splitArgs(trimmed)
  const cmd = parts[0]
  const args = parts.slice(1)
  
  switch (cmd) {
    case 'help':
      return `Available commands:
  help              show this message
  whoami            display current user
  pwd               print working directory
  cd <dir>          change directory
  ls [-la] [path]   list directory contents
  cat <file>        display file contents
  file <path>       determine file type
  ./flag <key>      decrypt /flag (root only)
  clear             clear terminal
  
<span class="dim">Hint: There might be something interesting in /</span>`

    case 'whoami':
      return 'starneko'

    case 'pwd':
      return cwd.value

    case 'cd': {
      const target = args[0] || '/home/starneko'
      const node = getNode(target)
      if (!node) return `cd: ${escapeHtml(target)}: No such file or directory`
      if (node.type !== 'dir') return `cd: ${escapeHtml(target)}: Not a directory`
      cwd.value = resolvePath(target)
      return ''
    }

    case 'ls': {
      let showAll = false
      let showLong = false
      let target = '.'
      
      for (const arg of args) {
        if (arg === '-a') showAll = true
        else if (arg === '-l') showLong = true
        else if (arg === '-la' || arg === '-al') { showAll = true; showLong = true }
        else target = arg
      }
      
      const node = getNode(target)
      if (!node) return `ls: ${escapeHtml(target)}: No such file or directory`
      if (node.type !== 'dir') return target
      
      let entries = Object.keys(node.children || {})
      if (!showAll) entries = entries.filter(e => !e.startsWith('.'))
      entries.sort()
      
      if (showLong) {
        return entries.map(name => {
          const child = node.children![name]
          const type = child.type === 'dir' ? 'drwxr-x---' : '-rw-r--r--'
          const color = child.type === 'dir' ? 'dir' : ''
          const safeName = escapeHtml(name)
          return `${type}  starneko  ${color ? `<span class="${color}">${safeName}</span>` : safeName}${child.type === 'dir' ? '/' : ''}`
        }).join('\n')
      }
      
      return entries.map(name => {
        const child = node.children![name]
        const safeName = escapeHtml(name)
        return child.type === 'dir' ? `<span class="dir">${safeName}/</span>` : safeName
      }).join('  ')
    }

    case 'cat': {
      if (!args[0]) return 'cat: missing operand'
      const resolved = resolvePath(args[0])
      const binaryPath = ctfConfig?.binary || '/ctf/re_checkin'
      if (resolved === binaryPath) {
        return `<span class="dim">This is a downloadable binary.</span>
<span class="dim">URL: ${escapeHtml(binaryPath)}</span>`
      }
      const node = getNode(args[0])
      if (!node) return `cat: ${escapeHtml(args[0])}: No such file or directory`
      if (node.type === 'dir') return `cat: ${escapeHtml(args[0])}: Is a directory`
      if (node.content === '::ENCRYPTED::') {
        return `<span class="error">cat: /flag: Permission denied</span>
<span class="dim">This file is encrypted. Solve the challenge to decrypt it.</span>`
      }
      return node.content || ''
    }

    case 'file': {
      if (!args[0]) return 'file: missing operand'
      const resolved = resolvePath(args[0])
      const binaryPath = ctfConfig?.binary || '/ctf/re_checkin'
      if (resolved === binaryPath) {
        return `${escapeHtml(resolved)}: ${escapeHtml(ctfConfig?.binaryType || 'binary data')}`
      }
      const node = getNode(args[0])
      if (!node) return `${escapeHtml(args[0])}: cannot open (No such file or directory)`
      if (node.type === 'dir') return `${resolved}: directory`
      if (resolved === '/flag') {
        return `${resolved}: encrypted data, requires key to decrypt
<span class="dim">
To decrypt this file, you need to:
1. Download the challenge: ${escapeHtml(ctfConfig?.binary || '/ctf/re_checkin')}
2. Analyze it to get the key
3. Run: ./flag &lt;key&gt;

Tools: ${ctfConfig?.tools || 'https://re.starneko.com/'}
Difficulty: ${ctfConfig?.difficulty || 'Easy'} | Category: ${ctfConfig?.category || 'RE'}
</span>`
      }
      return `${resolved}: ASCII text`
    }

    case './flag': {
      // Check if we're in root directory where flag exists
      if (cwd.value !== '/') {
        return `<span class="dim">zsh: no such file or directory: ./flag</span>`
      }
      
      if (!args[0]) {
        return `Usage: ./flag &lt;key&gt;
<span class="dim">
Analyze the challenge to get the key.
Download: ${escapeHtml(ctfConfig?.binary || '/ctf/re_checkin')}

    Tools: ${escapeHtml(ctfConfig?.tools || 'https://re.starneko.com/')}
    Difficulty: ${ctfConfig?.difficulty || 'Easy'} | Category: ${ctfConfig?.category || 'RE'}
</span>`
      }
      
      if (!ctfConfig) {
        return '<span class="error">Error: CTF config not loaded</span>'
      }
      
      const inputHash = await sha256(args[0])
      if (inputHash === ctfConfig.keyHash) {
        const contact = xorDecrypt(ctfConfig.encryptedFlag, args[0])
        const contactLine = `私人联系方式: ${contact}`
        const contactPadded = contactLine.length > 40 ? contactLine.slice(0, 39) + '…' : contactLine.padEnd(40)
        return `<span class="success">
╔══════════════════════════════════════════╗
║  ${ctfConfig.successMessage.padEnd(40)}║
      ║  ${contactPadded}║
╚══════════════════════════════════════════╝
</span>`
      }
      return '<span class="error">Invalid key. Keep trying!</span>'
    }

    case 'clear':
      visibleBlocks.value = []
      return ''

    default:
      return `<span class="dim">${escapeHtml(cmd)}: command not found</span>`
  }
}

// Input handling
const handleKeydown = async (e: KeyboardEvent) => {
  if (e.key === 'Enter') {
    e.preventDefault()
    const cmd = userInput.value
    userInput.value = ''

    // Snapshot prompt before command execution (so `cd` doesn't retroactively change history)
    const promptSnapshot = getPrompt()
    
    if (cmd.trim()) {
      commandHistory.push(cmd)
      historyIndex = commandHistory.length
    }
    
    const output = await executeCommand(cmd)
    pushBlock({ prompt: promptSnapshot, command: cmd, output })
    
    await nextTick()
    scrollToBottom()
    inputEl.value?.focus()
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    if (historyIndex > 0) {
      historyIndex--
      userInput.value = commandHistory[historyIndex]
    }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    if (historyIndex < commandHistory.length - 1) {
      historyIndex++
      userInput.value = commandHistory[historyIndex]
    } else {
      historyIndex = commandHistory.length
      userInput.value = ''
    }
  } else if (e.key === 'Tab') {
    e.preventDefault()
    // Simple tab completion for commands
    const cmds = ['help', 'whoami', 'pwd', 'cd', 'ls', 'cat', 'file', 'clear', './flag']
    const matches = cmds.filter(c => c.startsWith(userInput.value))
    if (matches.length === 1) userInput.value = matches[0] + ' '
  } else if (e.key === 'l' && e.ctrlKey) {
    e.preventDefault()
    visibleBlocks.value = []
  }
}

const scrollToBottom = () => {
  if (terminalBody.value) {
    terminalBody.value.scrollTop = terminalBody.value.scrollHeight
  }
}

const focusInput = () => {
  if (!isInteractive.value) return
  const el = inputEl.value
  if (!el) return
  el.focus()
  try {
    const len = el.value.length
    el.setSelectionRange(len, len)
  } catch {
    // ignore (some browsers may throw on hidden inputs)
  }
}

const typeCommand = async (cmd: string) => {
  isTyping.value = true
  currentCommand.value = ''
  for (const char of cmd) {
    currentCommand.value += char
    await sleep(30 + Math.random() * 50)
  }
  isTyping.value = false
  await sleep(200)
}

const runIntro = async () => {
  // Load CTF config
  try {
    const res = await fetch('/ctf/config.json')
    ctfConfig = await res.json()
  } catch {
    console.warn('CTF config not loaded')
  }
  
  await sleep(800)
  
  for (const intro of introCommands) {
    const promptSnapshot = getPrompt()
    await typeCommand(intro.command)
    await sleep(150)
    
    // Execute the command to get real output
    const output = intro.output || await executeCommand(intro.command)
    pushBlock({ prompt: promptSnapshot, command: intro.command, output })
    currentCommand.value = ''
    
    await nextTick()
    scrollToBottom()
    await sleep(600)
  }
  
  // Show hint
  visibleBlocks.value.push({
    command: '',
    output: '<span class="dim">Type "help" for available commands</span>'
  })
  
  currentTyping.value = false
  isInteractive.value = true
  
  await nextTick()
  focusInput()
}

onMounted(() => {
  runIntro()
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

.output :deep(.dir) {
  color: #3b82f6;
  font-weight: 600;
}

:root.dark .output :deep(.dir) {
  color: #7dd3fc;
}

.output :deep(.error) {
  color: #ef4444;
}

:root.dark .output :deep(.error) {
  color: #f87171;
}

.output :deep(.success) {
  color: #10b981;
}

:root.dark .output :deep(.success) {
  color: #34d399;
}

/* Interactive input */
.interactive {
  display: flex;
  align-items: center;
}

.input-display {
  flex: 0 1 auto;
  color: #3b82f6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  min-height: 1em;
}

:root.dark .input-display {
  color: #fff;
}

.terminal-input-hidden {
  position: absolute;
  left: -9999px;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
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
