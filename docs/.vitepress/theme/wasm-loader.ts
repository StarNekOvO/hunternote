// Wasm module loader with lazy initialization
import init, * as wasmModule from '../wasm/wasm_tools.js'

let initialized = false
let initPromise: Promise<void> | null = null

export async function ensureWasmLoaded(): Promise<typeof wasmModule> {
  if (initialized) {
    return wasmModule
  }
  
  if (!initPromise) {
    initPromise = (async () => {
      // In browser environment, load the wasm file
      if (typeof window !== 'undefined') {
        // Use public path for wasm file
        await init('/wasm_tools_bg.wasm')
        initialized = true
      }
    })()
  }
  
  await initPromise
  return wasmModule
}

// Re-export all functions with lazy loading wrapper
export const wasm = wasmModule
