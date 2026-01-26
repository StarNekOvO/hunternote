<template>
  <div class="image-tool">
    <!-- 功能标签页 -->
    <div class="tool-tabs">
      <button 
        v-for="tab in tabs" 
        :key="tab.id"
        :class="['tab-btn', { active: activeTab === tab.id }]"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
      </button>
    </div>

    <!-- 裁剪工具 -->
    <div v-show="activeTab === 'crop'" class="tool-panel">
      <div v-if="!cropImage" class="upload-area" @click="triggerCropUpload" @dragover.prevent @drop.prevent="handleCropDrop">
        <input ref="cropFileInput" type="file" accept="image/*" @change="handleCropUpload" hidden />
        <div class="upload-content">
          <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
          </svg>
          <p class="upload-text">点击或拖拽图片到此处</p>
          <p class="upload-hint">支持 JPG、PNG、WebP 等格式</p>
        </div>
      </div>
      
      <template v-else>
        <div class="editor-layout">
          <div class="editor-main">
            <div class="canvas-container" ref="cropContainer">
              <canvas ref="cropCanvas" @mousedown="handleCropMouseDown"></canvas>
            </div>
          </div>
          <div class="editor-sidebar">
            <div class="control-section">
              <div class="control-label">裁剪比例</div>
              <div class="ratio-grid">
                <button 
                  v-for="r in cropRatios" 
                  :key="r.value"
                  :class="['ratio-btn', { active: cropRatio === r.value }]"
                  @click="setCropRatio(r.value)"
                >
                  {{ r.label }}
                </button>
              </div>
            </div>

            <div class="control-section">
              <div class="control-label">旋转角度</div>
              <div class="rotation-controls">
                <button class="icon-btn" @click="rotateImage(-90)" title="逆时针旋转90度">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9m0 0v4m0-4H8"/></svg>
                </button>
                <span class="rotation-value">{{ imageRotation }}deg</span>
                <button class="icon-btn" @click="rotateImage(90)" title="顺时针旋转90度">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 0-9-9m0 0v4m0-4h4"/></svg>
                </button>
              </div>
              <input type="range" v-model.number="imageRotation" min="-180" max="180" step="1" class="slider" @input="renderCropPreview" />
            </div>

            <div class="control-section">
              <div class="control-label">翻转</div>
              <div class="flip-controls">
                <button :class="['flip-btn', { active: flipH }]" @click="flipH = !flipH; renderCropPreview()" title="水平翻转">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v18M16 7l4 5-4 5M8 7l-4 5 4 5"/></svg>
                  <span>水平</span>
                </button>
                <button :class="['flip-btn', { active: flipV }]" @click="flipV = !flipV; renderCropPreview()" title="垂直翻转">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h18M7 8l5-4 5 4M7 16l5 4 5-4"/></svg>
                  <span>垂直</span>
                </button>
              </div>
            </div>

            <div class="control-section">
              <div class="control-label">输出设置</div>
              <div class="output-settings">
                <select v-model="cropOutputFormat" class="select-input">
                  <option value="png">PNG</option>
                  <option value="jpeg">JPEG</option>
                  <option value="webp">WebP</option>
                </select>
                <div v-if="cropOutputFormat === 'jpeg'" class="quality-control">
                  <span class="quality-label">质量 {{ cropQuality }}%</span>
                  <input type="range" v-model.number="cropQuality" min="10" max="100" step="5" class="slider" />
                </div>
              </div>
            </div>

            <div class="action-buttons">
              <button class="btn-primary" @click="applyCrop">裁剪并下载</button>
              <button class="btn-secondary" @click="resetCropArea">重置选区</button>
              <button class="btn-text" @click="clearCrop">更换图片</button>
            </div>
          </div>
        </div>
      </template>
    </div>

    <!-- 大小调整工具 -->
    <div v-show="activeTab === 'resize'" class="tool-panel">
      <div v-if="!resizeImage" class="upload-area" @click="triggerResizeUpload" @dragover.prevent @drop.prevent="handleResizeDrop">
        <input ref="resizeFileInput" type="file" accept="image/*" @change="handleResizeUpload" hidden />
        <div class="upload-content">
          <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/>
          </svg>
          <p class="upload-text">点击或拖拽图片到此处</p>
          <p class="upload-hint">支持 JPG、PNG、WebP 等格式</p>
        </div>
      </div>

      <template v-else>
        <div class="editor-layout">
          <div class="editor-main">
            <div class="canvas-container">
              <canvas ref="resizeCanvas"></canvas>
            </div>
          </div>
          <div class="editor-sidebar">
            <div class="file-info">
              <div class="info-row">
                <span class="info-label">文件名</span>
                <span class="info-value text-truncate">{{ resizeFileName }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">原始大小</span>
                <span class="info-value">{{ formatFileSize(resizeOriginalSize) }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">原始尺寸</span>
                <span class="info-value">{{ resizeOriginalWidth }} x {{ resizeOriginalHeight }} px</span>
              </div>
            </div>

            <div class="control-section">
              <div class="control-label">调整模式</div>
              <div class="mode-toggle compact">
                <button :class="['mode-btn', { active: resizeMode === 'dimension' }]" @click="resizeMode = 'dimension'">按尺寸</button>
                <button :class="['mode-btn', { active: resizeMode === 'filesize' }]" @click="resizeMode = 'filesize'">按文件大小</button>
              </div>
            </div>

            <!-- 按尺寸调整 -->
            <template v-if="resizeMode === 'dimension'">
              <div class="control-section">
                <div class="control-label">快捷尺寸</div>
                <div class="preset-grid">
                  <button 
                    v-for="preset in dimensionPresets" 
                    :key="preset.label"
                    class="preset-btn"
                    @click="applyDimensionPreset(preset)"
                  >
                    {{ preset.label }}
                  </button>
                </div>
              </div>

              <div class="control-section">
                <div class="control-label">自定义尺寸</div>
                <div class="resize-inputs">
                  <div class="size-input-group">
                    <label>宽度</label>
                    <input type="number" v-model.number="resizeWidth" @input="onResizeWidthChange" min="1" max="10000" />
                  </div>
                  <span class="size-separator">x</span>
                  <div class="size-input-group">
                    <label>高度</label>
                    <input type="number" v-model.number="resizeHeight" @input="onResizeHeightChange" min="1" max="10000" />
                  </div>
                </div>
                <label class="checkbox-row" style="margin-top: 0.5rem;">
                  <input type="checkbox" v-model="resizeLockRatio" />
                  <span>锁定比例</span>
                </label>
              </div>

              <div class="result-preview" v-if="resizeWidth !== resizeOriginalWidth || resizeHeight !== resizeOriginalHeight">
                <span class="result-label">调整后</span>
                <span class="result-value">{{ resizeWidth }} x {{ resizeHeight }} px</span>
                <span class="result-ratio" :class="{ shrink: resizeWidth < resizeOriginalWidth }">
                  {{ Math.round(resizeWidth / resizeOriginalWidth * 100) }}%
                </span>
              </div>
            </template>

            <!-- 按文件大小调整 -->
            <template v-else>
              <div class="control-section">
                <div class="control-label">目标文件大小</div>
                <div class="size-limit-input">
                  <input type="number" v-model.number="targetFileSize" min="1" max="10000" />
                  <select v-model="targetFileSizeUnit">
                    <option value="kb">KB</option>
                    <option value="mb">MB</option>
                  </select>
                </div>
                <div class="preset-grid" style="margin-top: 0.5rem;">
                  <button class="preset-btn" @click="targetFileSize = 100; targetFileSizeUnit = 'kb'">100KB</button>
                  <button class="preset-btn" @click="targetFileSize = 200; targetFileSizeUnit = 'kb'">200KB</button>
                  <button class="preset-btn" @click="targetFileSize = 500; targetFileSizeUnit = 'kb'">500KB</button>
                  <button class="preset-btn" @click="targetFileSize = 1; targetFileSizeUnit = 'mb'">1MB</button>
                </div>
              </div>

              <div class="control-section">
                <div class="control-label">最大尺寸限制 (可选)</div>
                <div class="resize-inputs">
                  <div class="size-input-group">
                    <label>最大宽度</label>
                    <input type="number" v-model.number="maxDimensionWidth" min="0" max="10000" placeholder="不限" />
                  </div>
                  <span class="size-separator">x</span>
                  <div class="size-input-group">
                    <label>最大高度</label>
                    <input type="number" v-model.number="maxDimensionHeight" min="0" max="10000" placeholder="不限" />
                  </div>
                </div>
                <p class="hint-text">设为 0 表示不限制该方向</p>
              </div>

              <div class="control-section">
                <div class="control-label">输出格式</div>
                <select v-model="resizeOutputFormat" class="select-input">
                  <option value="jpeg">JPEG (推荐用于压缩)</option>
                  <option value="webp">WebP (更高压缩率)</option>
                  <option value="png">PNG (无损，文件较大)</option>
                </select>
              </div>

              <div class="info-box" v-if="compressResult">
                <div class="compress-result">
                  <div class="result-item">
                    <span class="result-label">调整后尺寸</span>
                    <span class="result-value">{{ compressResult.width }} x {{ compressResult.height }} px</span>
                  </div>
                  <div class="result-item">
                    <span class="result-label">预估大小</span>
                    <span class="result-value">{{ formatFileSize(compressResult.size) }}</span>
                  </div>
                  <div class="result-item">
                    <span class="result-label">压缩率</span>
                    <span class="result-value success">{{ Math.round((1 - compressResult.size / resizeOriginalSize) * 100) }}%</span>
                  </div>
                </div>
              </div>
            </template>

            <div class="action-buttons">
              <button class="btn-primary" @click="applyResize" :disabled="resizeProcessing">
                {{ resizeProcessing ? '处理中...' : (resizeMode === 'dimension' ? '调整并下载' : '压缩并下载') }}
              </button>
              <button class="btn-secondary" @click="previewCompress" v-if="resizeMode === 'filesize'" :disabled="resizeProcessing">预估大小</button>
              <button class="btn-text" @click="clearResize">更换图片</button>
            </div>
          </div>
        </div>
      </template>
    </div>

    <!-- 水印工具 -->
    <div v-show="activeTab === 'watermark'" class="tool-panel">
      <div v-if="!watermarkImage" class="upload-area" @click="triggerWatermarkUpload" @dragover.prevent @drop.prevent="handleWatermarkDrop">
        <input ref="watermarkFileInput" type="file" accept="image/*" @change="handleWatermarkUpload" hidden />
        <div class="upload-content">
          <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
          </svg>
          <p class="upload-text">点击或拖拽图片到此处</p>
          <p class="upload-hint">支持 JPG、PNG、WebP 等格式</p>
        </div>
      </div>

      <template v-else>
        <div class="editor-layout">
          <div class="editor-main">
            <div class="canvas-container">
              <canvas ref="watermarkCanvas"></canvas>
            </div>
          </div>
          <div class="editor-sidebar">
            <div class="control-section">
              <div class="control-label">水印文字</div>
              <input type="text" v-model="watermarkText" class="text-input" placeholder="输入水印文字" @input="renderWatermarkPreview" />
            </div>

            <div class="control-section">
              <div class="control-label">字体大小 <span class="value-badge">{{ watermarkSize }}px</span></div>
              <input type="range" v-model.number="watermarkSize" min="12" max="200" class="slider" @input="renderWatermarkPreview" />
            </div>

            <div class="control-section">
              <div class="control-label">颜色与透明度</div>
              <div class="color-opacity-row">
                <input type="color" v-model="watermarkColor" class="color-picker" @input="renderWatermarkPreview" />
                <div class="opacity-control">
                  <span>{{ Math.round(watermarkOpacity * 100) }}%</span>
                  <input type="range" v-model.number="watermarkOpacity" min="0.05" max="1" step="0.05" class="slider" @input="renderWatermarkPreview" />
                </div>
              </div>
            </div>

            <div class="control-section">
              <div class="control-label">旋转角度 <span class="value-badge">{{ watermarkRotation }}deg</span></div>
              <input type="range" v-model.number="watermarkRotation" min="-90" max="90" class="slider" @input="renderWatermarkPreview" />
            </div>

            <div class="control-section">
              <label class="checkbox-row">
                <input type="checkbox" v-model="watermarkTile" @change="renderWatermarkPreview" />
                <span>平铺水印</span>
              </label>
              <div v-if="watermarkTile" class="sub-control">
                <span class="control-label">间距 <span class="value-badge">{{ watermarkGap }}px</span></span>
                <input type="range" v-model.number="watermarkGap" min="50" max="500" class="slider" @input="renderWatermarkPreview" />
              </div>
            </div>

            <div class="action-buttons">
              <button class="btn-primary" @click="downloadWatermark">下载图片</button>
              <button class="btn-text" @click="clearWatermark">更换图片</button>
            </div>
          </div>
        </div>
      </template>
    </div>

    <!-- 盲水印工具 -->
    <div v-show="activeTab === 'blind'" class="tool-panel">
      <div class="mode-toggle">
        <button :class="['mode-btn', { active: blindMode === 'encode' }]" @click="blindMode = 'encode'">添加盲水印</button>
        <button :class="['mode-btn', { active: blindMode === 'decode' }]" @click="blindMode = 'decode'">解码盲水印</button>
      </div>

      <!-- 添加盲水印 -->
      <template v-if="blindMode === 'encode'">
        <div v-if="!blindEncodeImage" class="upload-area" @click="triggerBlindEncodeUpload" @dragover.prevent @drop.prevent="handleBlindEncodeDrop">
          <input ref="blindEncodeFileInput" type="file" accept="image/*" @change="handleBlindEncodeUpload" hidden />
          <div class="upload-content">
            <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
            </svg>
            <p class="upload-text">点击或拖拽图片到此处</p>
            <p class="upload-hint">支持 JPG、PNG、WebP 等格式</p>
          </div>
        </div>

        <template v-else>
          <div class="editor-layout">
            <div class="editor-main">
              <div class="compare-view">
                <div class="compare-item">
                  <div class="compare-label">原图预览</div>
                  <div class="compare-canvas">
                    <img :src="blindEncodeImage" />
                  </div>
                </div>
                <div class="compare-item">
                  <div class="compare-label">盲水印预览</div>
                  <div class="compare-canvas">
                    <canvas ref="blindEncodeCanvas"></canvas>
                  </div>
                </div>
              </div>
            </div>
            <div class="editor-sidebar">
              <div class="control-section">
                <div class="control-label">隐藏文字</div>
                <input type="text" v-model="blindText" class="text-input" placeholder="输入要隐藏的文字" @input="renderBlindEncodePreview" />
              </div>

              <div class="control-section">
                <div class="control-label">字体大小 <span class="value-badge">{{ blindFontSize }}px</span></div>
                <input type="range" v-model.number="blindFontSize" min="20" max="120" class="slider" @input="renderBlindEncodePreview" />
              </div>

              <div class="info-box">
                盲水印通过修改像素最低有效位嵌入信息，肉眼不可见，可用于版权保护和来源追踪。
              </div>

              <div class="action-buttons">
                <button class="btn-primary" @click="applyBlindWatermark">添加并下载</button>
                <button class="btn-text" @click="clearBlindEncode">更换图片</button>
              </div>
            </div>
          </div>
        </template>
      </template>

      <!-- 解码盲水印 -->
      <template v-else>
        <div v-if="!blindDecodeImage" class="upload-area" @click="triggerBlindDecodeUpload" @dragover.prevent @drop.prevent="handleBlindDecodeDrop">
          <input ref="blindDecodeFileInput" type="file" accept="image/*" @change="handleBlindDecodeUpload" hidden />
          <div class="upload-content">
            <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            <p class="upload-text">上传含盲水印的图片</p>
            <p class="upload-hint">将尝试提取隐藏的水印信息</p>
          </div>
        </div>

        <template v-else>
          <div class="editor-layout">
            <div class="editor-main">
              <div class="compare-view">
                <div class="compare-item">
                  <div class="compare-label">原图</div>
                  <div class="compare-canvas">
                    <img :src="blindDecodeImage" />
                  </div>
                </div>
                <div class="compare-item">
                  <div class="compare-label">解码结果</div>
                  <div class="compare-canvas decode-result">
                    <canvas ref="blindDecodeCanvas"></canvas>
                  </div>
                </div>
              </div>
            </div>
            <div class="editor-sidebar">
              <div class="info-box">
                解码将提取图片中的盲水印信息。如果图片未添加盲水印或经过压缩处理，可能无法正确解码。
              </div>

              <div class="action-buttons">
                <button class="btn-primary" @click="decodeBlindWatermark">解码水印</button>
                <button class="btn-text" @click="clearBlindDecode">更换图片</button>
              </div>
            </div>
          </div>
        </template>
      </template>
    </div>

    <!-- 格式转换 -->
    <div v-show="activeTab === 'convert'" class="tool-panel">
      <div v-if="!convertImage" class="upload-area" @click="triggerConvertUpload" @dragover.prevent @drop.prevent="handleConvertDrop">
        <input ref="convertFileInput" type="file" accept="image/*" @change="handleConvertUpload" hidden />
        <div class="upload-content">
          <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
          </svg>
          <p class="upload-text">点击或拖拽图片到此处</p>
          <p class="upload-hint">支持 JPG、PNG、WebP、GIF、BMP 等格式</p>
        </div>
      </div>

      <template v-else>
        <div class="editor-layout">
          <div class="editor-main">
            <div class="canvas-container">
              <img :src="convertImage" class="preview-image" />
            </div>
          </div>
          <div class="editor-sidebar">
            <div class="file-info">
              <div class="info-row">
                <span class="info-label">文件名</span>
                <span class="info-value">{{ convertFileName }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">原始大小</span>
                <span class="info-value">{{ formatFileSize(convertOriginalSize) }}</span>
              </div>
              <div class="info-row">
                <span class="info-label">尺寸</span>
                <span class="info-value">{{ convertWidth }} x {{ convertHeight }} px</span>
              </div>
            </div>

            <div class="control-section">
              <div class="control-label">输出格式</div>
              <select v-model="convertFormat" class="select-input">
                <option value="png">PNG (无损)</option>
                <option value="jpeg">JPEG (有损)</option>
                <option value="webp">WebP (推荐)</option>
                <option value="gif">GIF</option>
                <option value="bmp">BMP</option>
              </select>
            </div>

            <div v-if="['jpeg', 'webp'].includes(convertFormat)" class="control-section">
              <div class="control-label">输出质量 <span class="value-badge">{{ convertQuality }}%</span></div>
              <input type="range" v-model.number="convertQuality" min="10" max="100" step="5" class="slider" />
            </div>

            <div class="control-section">
              <label class="checkbox-row">
                <input type="checkbox" v-model="convertResize" />
                <span>调整尺寸</span>
              </label>
              <div v-if="convertResize" class="resize-inputs">
                <div class="size-input-group">
                  <label>宽度</label>
                  <input type="number" v-model.number="convertNewWidth" @input="onWidthChange" />
                </div>
                <span class="size-separator">x</span>
                <div class="size-input-group">
                  <label>高度</label>
                  <input type="number" v-model.number="convertNewHeight" @input="onHeightChange" />
                </div>
                <label class="checkbox-row lock-ratio">
                  <input type="checkbox" v-model="convertLockRatio" />
                  <span>锁定比例</span>
                </label>
              </div>
            </div>

            <div class="action-buttons">
              <button class="btn-primary" @click="applyConvert">转换并下载</button>
              <button class="btn-text" @click="clearConvert">更换图片</button>
            </div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onUnmounted } from 'vue'

const tabs = [
  { id: 'crop', label: '裁剪' },
  { id: 'resize', label: '大小调整' },
  { id: 'watermark', label: '水印' },
  { id: 'blind', label: '盲水印' },
  { id: 'convert', label: '格式转换' },
]

const activeTab = ref('crop')

// ========== 裁剪功能 ==========
const cropFileInput = ref<HTMLInputElement | null>(null)
const cropContainer = ref<HTMLDivElement | null>(null)
const cropCanvas = ref<HTMLCanvasElement | null>(null)
const cropImage = ref<string | null>(null)
const cropImageObj = ref<HTMLImageElement | null>(null)

const cropRatios = [
  { label: '自由', value: 'free' },
  { label: '1:1', value: '1:1' },
  { label: '4:3', value: '4:3' },
  { label: '16:9', value: '16:9' },
  { label: '3:2', value: '3:2' },
  { label: '9:16', value: '9:16' },
]
const cropRatio = ref('free')
const cropOutputFormat = ref('png')
const cropQuality = ref(90)
const imageRotation = ref(0)
const flipH = ref(false)
const flipV = ref(false)

// 裁剪框状态
const cropBox = ref({ x: 0, y: 0, w: 100, h: 100 })
const canvasScale = ref(1)
let isDragging = false
let isResizing = false
let resizeHandle = ''
let dragStartX = 0, dragStartY = 0
let cropStartX = 0, cropStartY = 0, cropStartW = 0, cropStartH = 0

function triggerCropUpload() {
  cropFileInput.value?.click()
}

function handleCropUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadCropImage(file)
}

function handleCropDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadCropImage(file)
}

function loadCropImage(file: File) {
  const url = URL.createObjectURL(file)
  cropImage.value = url
  imageRotation.value = 0
  flipH.value = false
  flipV.value = false
  cropRatio.value = 'free'
  
  const img = new Image()
  img.onload = () => {
    cropImageObj.value = img
    setTimeout(() => initCropCanvas(), 50)
  }
  img.src = url
}

function initCropCanvas() {
  if (!cropCanvas.value || !cropContainer.value || !cropImageObj.value) return
  
  const canvas = cropCanvas.value
  const container = cropContainer.value
  const img = cropImageObj.value
  
  const maxW = container.clientWidth - 32
  const maxH = 500
  canvasScale.value = Math.min(1, maxW / img.width, maxH / img.height)
  
  canvas.width = img.width * canvasScale.value
  canvas.height = img.height * canvasScale.value
  
  // 初始化裁剪框
  const initSize = Math.min(canvas.width, canvas.height) * 0.7
  cropBox.value = {
    x: (canvas.width - initSize) / 2,
    y: (canvas.height - initSize) / 2,
    w: initSize,
    h: initSize
  }
  
  renderCropPreview()
}

function renderCropPreview() {
  if (!cropCanvas.value || !cropImageObj.value) return
  
  const canvas = cropCanvas.value
  const ctx = canvas.getContext('2d')!
  const img = cropImageObj.value
  
  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.save()
  
  // 应用变换
  ctx.translate(canvas.width / 2, canvas.height / 2)
  ctx.rotate((imageRotation.value * Math.PI) / 180)
  ctx.scale(flipH.value ? -1 : 1, flipV.value ? -1 : 1)
  ctx.translate(-canvas.width / 2, -canvas.height / 2)
  
  // 绘制图片
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  ctx.restore()
  
  // 绘制遮罩
  ctx.fillStyle = 'rgba(0, 0, 0, 0.5)'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  
  // 清除裁剪区域的遮罩
  const box = cropBox.value
  ctx.clearRect(box.x, box.y, box.w, box.h)
  
  // 重新绘制裁剪区域的图片
  ctx.save()
  ctx.beginPath()
  ctx.rect(box.x, box.y, box.w, box.h)
  ctx.clip()
  ctx.translate(canvas.width / 2, canvas.height / 2)
  ctx.rotate((imageRotation.value * Math.PI) / 180)
  ctx.scale(flipH.value ? -1 : 1, flipV.value ? -1 : 1)
  ctx.translate(-canvas.width / 2, -canvas.height / 2)
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  ctx.restore()
  
  // 绘制裁剪框边框
  ctx.strokeStyle = '#fff'
  ctx.lineWidth = 2
  ctx.strokeRect(box.x, box.y, box.w, box.h)
  
  // 绘制三分线
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)'
  ctx.lineWidth = 1
  const thirdW = box.w / 3
  const thirdH = box.h / 3
  ctx.beginPath()
  ctx.moveTo(box.x + thirdW, box.y)
  ctx.lineTo(box.x + thirdW, box.y + box.h)
  ctx.moveTo(box.x + thirdW * 2, box.y)
  ctx.lineTo(box.x + thirdW * 2, box.y + box.h)
  ctx.moveTo(box.x, box.y + thirdH)
  ctx.lineTo(box.x + box.w, box.y + thirdH)
  ctx.moveTo(box.x, box.y + thirdH * 2)
  ctx.lineTo(box.x + box.w, box.y + thirdH * 2)
  ctx.stroke()
  
  // 绘制角落控制点
  const cornerSize = 12
  ctx.fillStyle = '#fff'
  const corners = [
    { x: box.x, y: box.y },
    { x: box.x + box.w, y: box.y },
    { x: box.x, y: box.y + box.h },
    { x: box.x + box.w, y: box.y + box.h },
  ]
  corners.forEach(c => {
    ctx.beginPath()
    ctx.arc(c.x, c.y, cornerSize / 2, 0, Math.PI * 2)
    ctx.fill()
  })
}

function handleCropMouseDown(e: MouseEvent) {
  if (!cropCanvas.value) return
  
  const rect = cropCanvas.value.getBoundingClientRect()
  const x = e.clientX - rect.left
  const y = e.clientY - rect.top
  const box = cropBox.value
  const cornerRadius = 12
  
  // 检查是否点击了角落
  const corners = [
    { name: 'nw', x: box.x, y: box.y },
    { name: 'ne', x: box.x + box.w, y: box.y },
    { name: 'sw', x: box.x, y: box.y + box.h },
    { name: 'se', x: box.x + box.w, y: box.y + box.h },
  ]
  
  for (const corner of corners) {
    if (Math.hypot(x - corner.x, y - corner.y) < cornerRadius) {
      isResizing = true
      resizeHandle = corner.name
      dragStartX = e.clientX
      dragStartY = e.clientY
      cropStartX = box.x
      cropStartY = box.y
      cropStartW = box.w
      cropStartH = box.h
      document.addEventListener('mousemove', handleCropMouseMove)
      document.addEventListener('mouseup', handleCropMouseUp)
      return
    }
  }
  
  // 检查是否点击了裁剪框内部
  if (x >= box.x && x <= box.x + box.w && y >= box.y && y <= box.y + box.h) {
    isDragging = true
    dragStartX = e.clientX
    dragStartY = e.clientY
    cropStartX = box.x
    cropStartY = box.y
    document.addEventListener('mousemove', handleCropMouseMove)
    document.addEventListener('mouseup', handleCropMouseUp)
  }
}

function handleCropMouseMove(e: MouseEvent) {
  if (!cropCanvas.value) return
  
  const dx = e.clientX - dragStartX
  const dy = e.clientY - dragStartY
  const canvas = cropCanvas.value
  
  if (isDragging) {
    let newX = cropStartX + dx
    let newY = cropStartY + dy
    newX = Math.max(0, Math.min(newX, canvas.width - cropBox.value.w))
    newY = Math.max(0, Math.min(newY, canvas.height - cropBox.value.h))
    cropBox.value.x = newX
    cropBox.value.y = newY
    renderCropPreview()
  } else if (isResizing) {
    const ratio = getRatioValue()
    let newX = cropStartX
    let newY = cropStartY
    let newW = cropStartW
    let newH = cropStartH
    
    const minSize = 50
    
    // 根据不同角落计算新尺寸
    if (resizeHandle === 'se') {
      newW = Math.max(minSize, cropStartW + dx)
      newW = Math.min(newW, canvas.width - cropStartX)
      if (ratio > 0) {
        newH = newW / ratio
        if (cropStartY + newH > canvas.height) {
          newH = canvas.height - cropStartY
          newW = newH * ratio
        }
      } else {
        newH = Math.max(minSize, cropStartH + dy)
        newH = Math.min(newH, canvas.height - cropStartY)
      }
    } else if (resizeHandle === 'sw') {
      newW = Math.max(minSize, cropStartW - dx)
      newX = cropStartX + cropStartW - newW
      if (newX < 0) {
        newX = 0
        newW = cropStartX + cropStartW
      }
      if (ratio > 0) {
        newH = newW / ratio
        if (cropStartY + newH > canvas.height) {
          newH = canvas.height - cropStartY
          newW = newH * ratio
          newX = cropStartX + cropStartW - newW
        }
      } else {
        newH = Math.max(minSize, cropStartH + dy)
        newH = Math.min(newH, canvas.height - cropStartY)
      }
    } else if (resizeHandle === 'ne') {
      newW = Math.max(minSize, cropStartW + dx)
      newW = Math.min(newW, canvas.width - cropStartX)
      if (ratio > 0) {
        newH = newW / ratio
        newY = cropStartY + cropStartH - newH
        if (newY < 0) {
          newY = 0
          newH = cropStartY + cropStartH
          newW = newH * ratio
        }
      } else {
        newH = Math.max(minSize, cropStartH - dy)
        newY = cropStartY + cropStartH - newH
        if (newY < 0) {
          newY = 0
          newH = cropStartY + cropStartH
        }
      }
    } else if (resizeHandle === 'nw') {
      newW = Math.max(minSize, cropStartW - dx)
      newX = cropStartX + cropStartW - newW
      if (newX < 0) {
        newX = 0
        newW = cropStartX + cropStartW
      }
      if (ratio > 0) {
        newH = newW / ratio
        newY = cropStartY + cropStartH - newH
        if (newY < 0) {
          newY = 0
          newH = cropStartY + cropStartH
          newW = newH * ratio
          newX = cropStartX + cropStartW - newW
        }
      } else {
        newH = Math.max(minSize, cropStartH - dy)
        newY = cropStartY + cropStartH - newH
        if (newY < 0) {
          newY = 0
          newH = cropStartY + cropStartH
        }
      }
    }
    
    cropBox.value = { x: newX, y: newY, w: newW, h: newH }
    renderCropPreview()
  }
}

function handleCropMouseUp() {
  isDragging = false
  isResizing = false
  document.removeEventListener('mousemove', handleCropMouseMove)
  document.removeEventListener('mouseup', handleCropMouseUp)
}

function getRatioValue(): number {
  if (cropRatio.value === 'free') return 0
  const [w, h] = cropRatio.value.split(':').map(Number)
  return w / h
}

function setCropRatio(value: string) {
  cropRatio.value = value
  if (value !== 'free' && cropCanvas.value) {
    const ratio = getRatioValue()
    const canvas = cropCanvas.value
    const box = cropBox.value
    
    // 根据当前框的较小边计算新尺寸
    let newW = box.w
    let newH = box.w / ratio
    
    if (newH > canvas.height - box.y) {
      newH = canvas.height - box.y
      newW = newH * ratio
    }
    if (newW > canvas.width - box.x) {
      newW = canvas.width - box.x
      newH = newW / ratio
    }
    
    cropBox.value.w = newW
    cropBox.value.h = newH
    renderCropPreview()
  }
}

function rotateImage(deg: number) {
  imageRotation.value = ((imageRotation.value + deg + 180) % 360) - 180
  renderCropPreview()
}

function resetCropArea() {
  if (!cropCanvas.value) return
  const canvas = cropCanvas.value
  const initSize = Math.min(canvas.width, canvas.height) * 0.7
  cropBox.value = {
    x: (canvas.width - initSize) / 2,
    y: (canvas.height - initSize) / 2,
    w: initSize,
    h: initSize
  }
  imageRotation.value = 0
  flipH.value = false
  flipV.value = false
  cropRatio.value = 'free'
  renderCropPreview()
}

function applyCrop() {
  if (!cropImageObj.value || !cropCanvas.value) return
  
  const img = cropImageObj.value
  const box = cropBox.value
  const scale = canvasScale.value
  
  // 计算原图上的裁剪区域
  const sx = box.x / scale
  const sy = box.y / scale
  const sw = box.w / scale
  const sh = box.h / scale
  
  const outputCanvas = document.createElement('canvas')
  outputCanvas.width = sw
  outputCanvas.height = sh
  const ctx = outputCanvas.getContext('2d')!
  
  // 应用变换
  ctx.translate(sw / 2, sh / 2)
  ctx.rotate((imageRotation.value * Math.PI) / 180)
  ctx.scale(flipH.value ? -1 : 1, flipV.value ? -1 : 1)
  ctx.translate(-sw / 2, -sh / 2)
  
  // 绘制裁剪区域
  ctx.drawImage(img, sx, sy, sw, sh, 0, 0, sw, sh)
  
  // 下载
  const mimeType = cropOutputFormat.value === 'jpeg' ? 'image/jpeg' : cropOutputFormat.value === 'webp' ? 'image/webp' : 'image/png'
  const quality = cropOutputFormat.value === 'jpeg' ? cropQuality.value / 100 : undefined
  const link = document.createElement('a')
  link.download = `cropped.${cropOutputFormat.value}`
  link.href = outputCanvas.toDataURL(mimeType, quality)
  link.click()
}

function clearCrop() {
  if (cropImage.value) URL.revokeObjectURL(cropImage.value)
  cropImage.value = null
  cropImageObj.value = null
  if (cropFileInput.value) cropFileInput.value.value = ''
}

// ========== 大小调整功能 ==========
const resizeFileInput = ref<HTMLInputElement | null>(null)
const resizeCanvas = ref<HTMLCanvasElement | null>(null)
const resizeImage = ref<string | null>(null)
const resizeImageObj = ref<HTMLImageElement | null>(null)
const resizeFileName = ref('')
const resizeOriginalSize = ref(0)
const resizeOriginalWidth = ref(0)
const resizeOriginalHeight = ref(0)

const resizeMode = ref<'dimension' | 'filesize'>('dimension')
const resizeWidth = ref(0)
const resizeHeight = ref(0)
const resizeLockRatio = ref(true)
const resizeProcessing = ref(false)

// 文件大小模式
const targetFileSize = ref(200)
const targetFileSizeUnit = ref<'kb' | 'mb'>('kb')
const maxDimensionWidth = ref(0)
const maxDimensionHeight = ref(0)
const resizeOutputFormat = ref('jpeg')
const compressResult = ref<{ width: number; height: number; size: number } | null>(null)

const dimensionPresets = [
  { label: '200x200', width: 200, height: 200 },
  { label: '500x500', width: 500, height: 500 },
  { label: '800x800', width: 800, height: 800 },
  { label: '1000x1000', width: 1000, height: 1000 },
  { label: '1920x1080', width: 1920, height: 1080 },
  { label: '1080x1920', width: 1080, height: 1920 },
]

function triggerResizeUpload() {
  resizeFileInput.value?.click()
}

function handleResizeUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadResizeImage(file)
}

function handleResizeDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadResizeImage(file)
}

function loadResizeImage(file: File) {
  const url = URL.createObjectURL(file)
  resizeImage.value = url
  resizeFileName.value = file.name
  resizeOriginalSize.value = file.size
  compressResult.value = null
  
  const img = new Image()
  img.onload = () => {
    resizeImageObj.value = img
    resizeOriginalWidth.value = img.width
    resizeOriginalHeight.value = img.height
    resizeWidth.value = img.width
    resizeHeight.value = img.height
    setTimeout(() => renderResizePreview(), 50)
  }
  img.src = url
}

function renderResizePreview() {
  if (!resizeCanvas.value || !resizeImageObj.value) return
  
  const canvas = resizeCanvas.value
  const ctx = canvas.getContext('2d')!
  const img = resizeImageObj.value
  
  const maxSize = 400
  const scale = Math.min(1, maxSize / Math.max(img.width, img.height))
  canvas.width = img.width * scale
  canvas.height = img.height * scale
  
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
}

function onResizeWidthChange() {
  if (resizeLockRatio.value && resizeOriginalWidth.value > 0) {
    const ratio = resizeOriginalHeight.value / resizeOriginalWidth.value
    resizeHeight.value = Math.round(resizeWidth.value * ratio)
  }
}

function onResizeHeightChange() {
  if (resizeLockRatio.value && resizeOriginalHeight.value > 0) {
    const ratio = resizeOriginalWidth.value / resizeOriginalHeight.value
    resizeWidth.value = Math.round(resizeHeight.value * ratio)
  }
}

function applyDimensionPreset(preset: { width: number; height: number }) {
  // 如果锁定比例，按比例缩放到 preset 尺寸内
  if (resizeLockRatio.value) {
    const ratio = resizeOriginalWidth.value / resizeOriginalHeight.value
    if (ratio > preset.width / preset.height) {
      // 宽度限制
      resizeWidth.value = Math.min(preset.width, resizeOriginalWidth.value)
      resizeHeight.value = Math.round(resizeWidth.value / ratio)
    } else {
      // 高度限制
      resizeHeight.value = Math.min(preset.height, resizeOriginalHeight.value)
      resizeWidth.value = Math.round(resizeHeight.value * ratio)
    }
  } else {
    resizeWidth.value = preset.width
    resizeHeight.value = preset.height
  }
}

async function applyResize() {
  if (!resizeImageObj.value) return
  resizeProcessing.value = true
  
  try {
    if (resizeMode.value === 'dimension') {
      await resizeByDimension()
    } else {
      await resizeByFileSize()
    }
  } finally {
    resizeProcessing.value = false
  }
}

async function resizeByDimension() {
  if (!resizeImageObj.value) return
  
  const img = resizeImageObj.value
  const canvas = document.createElement('canvas')
  canvas.width = resizeWidth.value
  canvas.height = resizeHeight.value
  
  const ctx = canvas.getContext('2d')!
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.drawImage(img, 0, 0, resizeWidth.value, resizeHeight.value)
  
  const link = document.createElement('a')
  const baseName = resizeFileName.value.replace(/\.[^.]+$/, '')
  link.download = `${baseName}_${resizeWidth.value}x${resizeHeight.value}.png`
  link.href = canvas.toDataURL('image/png')
  link.click()
}

async function resizeByFileSize() {
  if (!resizeImageObj.value) return
  
  const targetBytes = targetFileSizeUnit.value === 'kb' 
    ? targetFileSize.value * 1024 
    : targetFileSize.value * 1024 * 1024
  
  const result = await compressToTargetSize(resizeImageObj.value, targetBytes, true)
  
  if (result) {
    const link = document.createElement('a')
    const baseName = resizeFileName.value.replace(/\.[^.]+$/, '')
    link.download = `${baseName}_compressed.${resizeOutputFormat.value}`
    link.href = result.dataUrl
    link.click()
  }
}

async function previewCompress() {
  if (!resizeImageObj.value) return
  resizeProcessing.value = true
  
  try {
    const targetBytes = targetFileSizeUnit.value === 'kb' 
      ? targetFileSize.value * 1024 
      : targetFileSize.value * 1024 * 1024
    
    const result = await compressToTargetSize(resizeImageObj.value, targetBytes, false)
    
    if (result) {
      compressResult.value = {
        width: result.width,
        height: result.height,
        size: result.size
      }
    }
  } finally {
    resizeProcessing.value = false
  }
}

async function compressToTargetSize(
  img: HTMLImageElement, 
  targetBytes: number, 
  download: boolean
): Promise<{ dataUrl: string; width: number; height: number; size: number } | null> {
  let width = img.width
  let height = img.height
  const ratio = width / height
  
  // 应用最大尺寸限制
  if (maxDimensionWidth.value > 0 && width > maxDimensionWidth.value) {
    width = maxDimensionWidth.value
    height = Math.round(width / ratio)
  }
  if (maxDimensionHeight.value > 0 && height > maxDimensionHeight.value) {
    height = maxDimensionHeight.value
    width = Math.round(height * ratio)
  }
  
  const mimeType = resizeOutputFormat.value === 'webp' ? 'image/webp' 
    : resizeOutputFormat.value === 'png' ? 'image/png' 
    : 'image/jpeg'
  
  // 二分查找最佳质量和尺寸
  let quality = 0.92
  let minQuality = 0.1
  let scale = 1
  let minScale = 0.1
  let bestResult: { dataUrl: string; width: number; height: number; size: number } | null = null
  
  // 先尝试只调整质量
  for (let i = 0; i < 10; i++) {
    const canvas = document.createElement('canvas')
    canvas.width = Math.round(width * scale)
    canvas.height = Math.round(height * scale)
    
    const ctx = canvas.getContext('2d')!
    ctx.imageSmoothingEnabled = true
    ctx.imageSmoothingQuality = 'high'
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
    
    const dataUrl = canvas.toDataURL(mimeType, quality)
    const size = Math.round((dataUrl.length - `data:${mimeType};base64,`.length) * 0.75)
    
    bestResult = { dataUrl, width: canvas.width, height: canvas.height, size }
    
    if (size <= targetBytes) {
      break
    }
    
    // 如果质量已经很低，尝试缩小尺寸
    if (quality <= minQuality) {
      scale *= 0.85
      quality = 0.85
      if (scale < minScale) break
    } else {
      quality = Math.max(minQuality, quality - 0.1)
    }
  }
  
  return bestResult
}

function clearResize() {
  if (resizeImage.value) URL.revokeObjectURL(resizeImage.value)
  resizeImage.value = null
  resizeImageObj.value = null
  resizeFileName.value = ''
  resizeOriginalSize.value = 0
  resizeOriginalWidth.value = 0
  resizeOriginalHeight.value = 0
  resizeWidth.value = 0
  resizeHeight.value = 0
  compressResult.value = null
  if (resizeFileInput.value) resizeFileInput.value.value = ''
}

// ========== 水印功能 ==========
const watermarkFileInput = ref<HTMLInputElement | null>(null)
const watermarkCanvas = ref<HTMLCanvasElement | null>(null)
const watermarkImage = ref<string | null>(null)
const watermarkImageObj = ref<HTMLImageElement | null>(null)
const watermarkText = ref('starneko.com')
const watermarkSize = ref(48)
const watermarkColor = ref('#000000')
const watermarkOpacity = ref(0.3)
const watermarkRotation = ref(-30)
const watermarkTile = ref(true)
const watermarkGap = ref(200)

function triggerWatermarkUpload() {
  watermarkFileInput.value?.click()
}

function handleWatermarkUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadWatermarkImage(file)
}

function handleWatermarkDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadWatermarkImage(file)
}

function loadWatermarkImage(file: File) {
  const url = URL.createObjectURL(file)
  watermarkImage.value = url
  const img = new Image()
  img.onload = () => {
    watermarkImageObj.value = img
    setTimeout(() => renderWatermarkPreview(), 50)
  }
  img.src = url
}

function renderWatermarkPreview() {
  if (!watermarkCanvas.value || !watermarkImageObj.value) return
  
  const canvas = watermarkCanvas.value
  const ctx = canvas.getContext('2d')!
  const img = watermarkImageObj.value
  
  const maxSize = 600
  const scale = Math.min(1, maxSize / Math.max(img.width, img.height))
  canvas.width = img.width * scale
  canvas.height = img.height * scale
  
  // 绘制图片
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  
  // 绘制水印
  ctx.save()
  ctx.globalAlpha = watermarkOpacity.value
  ctx.fillStyle = watermarkColor.value
  ctx.font = `${watermarkSize.value * scale}px sans-serif`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  
  if (watermarkTile.value) {
    const gap = watermarkGap.value * scale
    for (let y = -gap; y < canvas.height + gap * 2; y += gap) {
      for (let x = -gap; x < canvas.width + gap * 2; x += gap) {
        ctx.save()
        ctx.translate(x, y)
        ctx.rotate((watermarkRotation.value * Math.PI) / 180)
        ctx.fillText(watermarkText.value, 0, 0)
        ctx.restore()
      }
    }
  } else {
    ctx.translate(canvas.width / 2, canvas.height / 2)
    ctx.rotate((watermarkRotation.value * Math.PI) / 180)
    ctx.fillText(watermarkText.value, 0, 0)
  }
  ctx.restore()
}

function downloadWatermark() {
  if (!watermarkImageObj.value) return
  
  const img = watermarkImageObj.value
  const canvas = document.createElement('canvas')
  canvas.width = img.width
  canvas.height = img.height
  const ctx = canvas.getContext('2d')!
  
  ctx.drawImage(img, 0, 0)
  
  ctx.save()
  ctx.globalAlpha = watermarkOpacity.value
  ctx.fillStyle = watermarkColor.value
  ctx.font = `${watermarkSize.value}px sans-serif`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  
  if (watermarkTile.value) {
    for (let y = -watermarkGap.value; y < canvas.height + watermarkGap.value * 2; y += watermarkGap.value) {
      for (let x = -watermarkGap.value; x < canvas.width + watermarkGap.value * 2; x += watermarkGap.value) {
        ctx.save()
        ctx.translate(x, y)
        ctx.rotate((watermarkRotation.value * Math.PI) / 180)
        ctx.fillText(watermarkText.value, 0, 0)
        ctx.restore()
      }
    }
  } else {
    ctx.translate(canvas.width / 2, canvas.height / 2)
    ctx.rotate((watermarkRotation.value * Math.PI) / 180)
    ctx.fillText(watermarkText.value, 0, 0)
  }
  ctx.restore()
  
  const link = document.createElement('a')
  link.download = 'watermarked.png'
  link.href = canvas.toDataURL('image/png')
  link.click()
}

function clearWatermark() {
  if (watermarkImage.value) URL.revokeObjectURL(watermarkImage.value)
  watermarkImage.value = null
  watermarkImageObj.value = null
  if (watermarkFileInput.value) watermarkFileInput.value.value = ''
}

// ========== 盲水印功能 ==========
const blindMode = ref<'encode' | 'decode'>('encode')

// 编码
const blindEncodeFileInput = ref<HTMLInputElement | null>(null)
const blindEncodeCanvas = ref<HTMLCanvasElement | null>(null)
const blindEncodeImage = ref<string | null>(null)
const blindEncodeImageObj = ref<HTMLImageElement | null>(null)
const blindText = ref('starneko.com')
const blindFontSize = ref(40)

function triggerBlindEncodeUpload() {
  blindEncodeFileInput.value?.click()
}

function handleBlindEncodeUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadBlindEncodeImage(file)
}

function handleBlindEncodeDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadBlindEncodeImage(file)
}

function loadBlindEncodeImage(file: File) {
  const url = URL.createObjectURL(file)
  blindEncodeImage.value = url
  const img = new Image()
  img.onload = () => {
    blindEncodeImageObj.value = img
    setTimeout(() => renderBlindEncodePreview(), 50)
  }
  img.src = url
}

function renderBlindEncodePreview() {
  if (!blindEncodeCanvas.value || !blindEncodeImageObj.value) return
  
  const canvas = blindEncodeCanvas.value
  const ctx = canvas.getContext('2d')!
  const img = blindEncodeImageObj.value
  
  const maxSize = 400
  const scale = Math.min(1, maxSize / Math.max(img.width, img.height))
  canvas.width = img.width * scale
  canvas.height = img.height * scale
  
  // 先绘制原图
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  
  // 生成水印层预览（可视化）
  const watermarkCanvas = document.createElement('canvas')
  watermarkCanvas.width = canvas.width
  watermarkCanvas.height = canvas.height
  const wctx = watermarkCanvas.getContext('2d')!
  
  wctx.fillStyle = '#000'
  wctx.fillRect(0, 0, watermarkCanvas.width, watermarkCanvas.height)
  wctx.fillStyle = '#fff'
  wctx.font = `${blindFontSize.value * scale}px sans-serif`
  wctx.textAlign = 'center'
  wctx.textBaseline = 'middle'
  
  const gap = blindFontSize.value * scale * 3
  for (let y = gap / 2; y < watermarkCanvas.height; y += gap) {
    for (let x = gap / 2; x < watermarkCanvas.width; x += gap) {
      wctx.save()
      wctx.translate(x, y)
      wctx.rotate(-30 * Math.PI / 180)
      wctx.fillText(blindText.value, 0, 0)
      wctx.restore()
    }
  }
  
  // 叠加预览（低透明度显示水印效果）
  ctx.globalAlpha = 0.15
  ctx.drawImage(watermarkCanvas, 0, 0)
}

function applyBlindWatermark() {
  if (!blindEncodeImageObj.value) return
  
  const img = blindEncodeImageObj.value
  const canvas = document.createElement('canvas')
  canvas.width = img.width
  canvas.height = img.height
  const ctx = canvas.getContext('2d')!
  
  ctx.drawImage(img, 0, 0)
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
  
  // 生成水印图案
  const watermarkCanvas = document.createElement('canvas')
  watermarkCanvas.width = canvas.width
  watermarkCanvas.height = canvas.height
  const wctx = watermarkCanvas.getContext('2d')!
  
  wctx.fillStyle = '#000'
  wctx.fillRect(0, 0, watermarkCanvas.width, watermarkCanvas.height)
  wctx.fillStyle = '#fff'
  wctx.font = `${blindFontSize.value}px sans-serif`
  wctx.textAlign = 'center'
  wctx.textBaseline = 'middle'
  
  const gap = blindFontSize.value * 3
  for (let y = gap / 2; y < watermarkCanvas.height; y += gap) {
    for (let x = gap / 2; x < watermarkCanvas.width; x += gap) {
      wctx.save()
      wctx.translate(x, y)
      wctx.rotate(-30 * Math.PI / 180)
      wctx.fillText(blindText.value, 0, 0)
      wctx.restore()
    }
  }
  
  const watermarkData = wctx.getImageData(0, 0, watermarkCanvas.width, watermarkCanvas.height)
  
  // LSB 编码
  for (let i = 0; i < imageData.data.length; i += 4) {
    const wmPixel = watermarkData.data[i] > 128 ? 1 : 0
    imageData.data[i] = (imageData.data[i] & 0xFE) | wmPixel // R通道
  }
  
  ctx.putImageData(imageData, 0, 0)
  
  const link = document.createElement('a')
  link.download = 'blind-watermarked.png'
  link.href = canvas.toDataURL('image/png')
  link.click()
}

function clearBlindEncode() {
  if (blindEncodeImage.value) URL.revokeObjectURL(blindEncodeImage.value)
  blindEncodeImage.value = null
  blindEncodeImageObj.value = null
  if (blindEncodeFileInput.value) blindEncodeFileInput.value.value = ''
}

// 解码
const blindDecodeFileInput = ref<HTMLInputElement | null>(null)
const blindDecodeCanvas = ref<HTMLCanvasElement | null>(null)
const blindDecodeImage = ref<string | null>(null)
const blindDecodeImageObj = ref<HTMLImageElement | null>(null)

function triggerBlindDecodeUpload() {
  blindDecodeFileInput.value?.click()
}

function handleBlindDecodeUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadBlindDecodeImage(file)
}

function handleBlindDecodeDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadBlindDecodeImage(file)
}

function loadBlindDecodeImage(file: File) {
  const url = URL.createObjectURL(file)
  blindDecodeImage.value = url
  const img = new Image()
  img.onload = () => {
    blindDecodeImageObj.value = img
  }
  img.src = url
}

function decodeBlindWatermark() {
  if (!blindDecodeCanvas.value || !blindDecodeImageObj.value) return
  
  const img = blindDecodeImageObj.value
  const tempCanvas = document.createElement('canvas')
  tempCanvas.width = img.width
  tempCanvas.height = img.height
  const tempCtx = tempCanvas.getContext('2d')!
  tempCtx.drawImage(img, 0, 0)
  const imageData = tempCtx.getImageData(0, 0, tempCanvas.width, tempCanvas.height)
  
  // 提取 LSB
  const canvas = blindDecodeCanvas.value
  const maxSize = 400
  const scale = Math.min(1, maxSize / Math.max(img.width, img.height))
  canvas.width = img.width * scale
  canvas.height = img.height * scale
  const ctx = canvas.getContext('2d')!
  
  const outputData = ctx.createImageData(canvas.width, canvas.height)
  
  for (let y = 0; y < canvas.height; y++) {
    for (let x = 0; x < canvas.width; x++) {
      const srcX = Math.floor(x / scale)
      const srcY = Math.floor(y / scale)
      const srcIdx = (srcY * img.width + srcX) * 4
      const dstIdx = (y * canvas.width + x) * 4
      
      const bit = imageData.data[srcIdx] & 1
      const color = bit ? 255 : 0
      outputData.data[dstIdx] = color
      outputData.data[dstIdx + 1] = color
      outputData.data[dstIdx + 2] = color
      outputData.data[dstIdx + 3] = 255
    }
  }
  
  ctx.putImageData(outputData, 0, 0)
}

function clearBlindDecode() {
  if (blindDecodeImage.value) URL.revokeObjectURL(blindDecodeImage.value)
  blindDecodeImage.value = null
  blindDecodeImageObj.value = null
  if (blindDecodeFileInput.value) blindDecodeFileInput.value.value = ''
  if (blindDecodeCanvas.value) {
    const ctx = blindDecodeCanvas.value.getContext('2d')
    ctx?.clearRect(0, 0, blindDecodeCanvas.value.width, blindDecodeCanvas.value.height)
  }
}

// ========== 格式转换功能 ==========
const convertFileInput = ref<HTMLInputElement | null>(null)
const convertImage = ref<string | null>(null)
const convertImageObj = ref<HTMLImageElement | null>(null)
const convertFileName = ref('')
const convertOriginalSize = ref(0)
const convertWidth = ref(0)
const convertHeight = ref(0)
const convertFormat = ref('webp')
const convertQuality = ref(85)
const convertResize = ref(false)
const convertNewWidth = ref(0)
const convertNewHeight = ref(0)
const convertLockRatio = ref(true)

function triggerConvertUpload() {
  convertFileInput.value?.click()
}

function handleConvertUpload(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (file) loadConvertImage(file)
}

function handleConvertDrop(e: DragEvent) {
  const file = e.dataTransfer?.files[0]
  if (file && file.type.startsWith('image/')) loadConvertImage(file)
}

function loadConvertImage(file: File) {
  const url = URL.createObjectURL(file)
  convertImage.value = url
  convertFileName.value = file.name
  convertOriginalSize.value = file.size
  
  const img = new Image()
  img.onload = () => {
    convertImageObj.value = img
    convertWidth.value = img.width
    convertHeight.value = img.height
    convertNewWidth.value = img.width
    convertNewHeight.value = img.height
  }
  img.src = url
}

function onWidthChange() {
  if (convertLockRatio.value && convertWidth.value > 0) {
    const ratio = convertHeight.value / convertWidth.value
    convertNewHeight.value = Math.round(convertNewWidth.value * ratio)
  }
}

function onHeightChange() {
  if (convertLockRatio.value && convertHeight.value > 0) {
    const ratio = convertWidth.value / convertHeight.value
    convertNewWidth.value = Math.round(convertNewHeight.value * ratio)
  }
}

function applyConvert() {
  if (!convertImageObj.value) return
  
  const img = convertImageObj.value
  const canvas = document.createElement('canvas')
  const w = convertResize.value ? convertNewWidth.value : img.width
  const h = convertResize.value ? convertNewHeight.value : img.height
  canvas.width = w
  canvas.height = h
  
  const ctx = canvas.getContext('2d')!
  ctx.drawImage(img, 0, 0, w, h)
  
  const mimeTypes: Record<string, string> = {
    png: 'image/png',
    jpeg: 'image/jpeg',
    webp: 'image/webp',
    gif: 'image/gif',
    bmp: 'image/bmp',
  }
  const mimeType = mimeTypes[convertFormat.value] || 'image/png'
  const quality = ['jpeg', 'webp'].includes(convertFormat.value) ? convertQuality.value / 100 : undefined
  
  const link = document.createElement('a')
  const baseName = convertFileName.value.replace(/\.[^.]+$/, '')
  link.download = `${baseName}.${convertFormat.value}`
  link.href = canvas.toDataURL(mimeType, quality)
  link.click()
}

function clearConvert() {
  if (convertImage.value) URL.revokeObjectURL(convertImage.value)
  convertImage.value = null
  convertImageObj.value = null
  convertFileName.value = ''
  convertOriginalSize.value = 0
  convertWidth.value = 0
  convertHeight.value = 0
  convertResize.value = false
  if (convertFileInput.value) convertFileInput.value.value = ''
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}

// 清理
onUnmounted(() => {
  clearCrop()
  clearResize()
  clearWatermark()
  clearBlindEncode()
  clearBlindDecode()
  clearConvert()
})
</script>

<style scoped>
.image-tool {
  margin-top: 1rem;
}

/* 标签页 */
.tool-tabs {
  display: flex;
  gap: 0.5rem;
  border-bottom: 1px solid var(--vp-c-divider);
  padding-bottom: 0.75rem;
  margin-bottom: 1.5rem;
}

.tab-btn {
  padding: 0.5rem 1rem;
  border: none;
  background: none;
  color: var(--vp-c-text-2);
  font-size: 0.95rem;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
}

.tab-btn:hover {
  color: var(--vp-c-text-1);
  background: var(--vp-c-bg-soft);
}

.tab-btn.active {
  color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  font-weight: 500;
}

/* 上传区域 */
.upload-area {
  border: 2px dashed var(--vp-c-divider);
  border-radius: 12px;
  padding: 3rem 2rem;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}

.upload-area:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-bg-soft);
}

.upload-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.upload-icon {
  width: 48px;
  height: 48px;
  color: var(--vp-c-text-3);
}

.upload-text {
  font-size: 1rem;
  color: var(--vp-c-text-1);
  margin: 0;
}

.upload-hint {
  font-size: 0.85rem;
  color: var(--vp-c-text-3);
  margin: 0;
}

/* 编辑器布局 */
.editor-layout {
  display: grid;
  grid-template-columns: 1fr 280px;
  gap: 1.5rem;
}

@media (max-width: 768px) {
  .editor-layout {
    grid-template-columns: 1fr;
  }
}

.editor-main {
  min-width: 0;
}

.editor-sidebar {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

/* Canvas 容器 */
.canvas-container {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 300px;
}

.canvas-container canvas {
  max-width: 100%;
  border-radius: 4px;
  cursor: crosshair;
}

.preview-image {
  max-width: 100%;
  max-height: 400px;
  object-fit: contain;
  border-radius: 4px;
}

/* 控制区域 */
.control-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.control-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.value-badge {
  font-size: 0.75rem;
  font-weight: 400;
  color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
}

/* 比例选择网格 */
.ratio-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.5rem;
}

.ratio-btn {
  padding: 0.4rem 0.5rem;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
  border-radius: 6px;
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.2s;
}

.ratio-btn:hover {
  border-color: var(--vp-c-brand);
}

.ratio-btn.active {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
}

/* 旋转控制 */
.rotation-controls {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1rem;
}

.rotation-value {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--vp-c-text-1);
  min-width: 4rem;
  text-align: center;
}

.icon-btn {
  width: 36px;
  height: 36px;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.icon-btn:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
}

.icon-btn svg {
  width: 18px;
  height: 18px;
  color: var(--vp-c-text-2);
}

/* 翻转控制 */
.flip-controls {
  display: flex;
  gap: 0.5rem;
}

.flip-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  padding: 0.5rem;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
  border-radius: 6px;
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.2s;
}

.flip-btn:hover {
  border-color: var(--vp-c-brand);
}

.flip-btn.active {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
}

.flip-btn svg {
  width: 16px;
  height: 16px;
}

/* 输入控件 */
.text-input {
  width: 100%;
  padding: 0.6rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-size: 0.9rem;
}

.text-input:focus {
  outline: none;
  border-color: var(--vp-c-brand);
}

.select-input {
  width: 100%;
  padding: 0.6rem 0.75rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-size: 0.9rem;
  cursor: pointer;
}

.slider {
  width: 100%;
  height: 4px;
  border-radius: 2px;
  background: var(--vp-c-divider);
  appearance: none;
  cursor: pointer;
}

.slider::-webkit-slider-thumb {
  appearance: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: var(--vp-c-brand);
  cursor: pointer;
}

/* 颜色和透明度 */
.color-opacity-row {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

.color-picker {
  width: 40px;
  height: 32px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  cursor: pointer;
  padding: 2px;
}

.opacity-control {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.opacity-control span {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
}

/* 复选框 */
.checkbox-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  font-size: 0.9rem;
  color: var(--vp-c-text-1);
}

.checkbox-row input[type="checkbox"] {
  width: 16px;
  height: 16px;
  cursor: pointer;
}

.sub-control {
  margin-top: 0.5rem;
  padding-left: 1.5rem;
}

/* 输出设置 */
.output-settings {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.quality-control {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.quality-label {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
}

/* 按钮组 */
.action-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: auto;
  padding-top: 1rem;
}

.btn-primary {
  width: 100%;
  padding: 0.7rem 1rem;
  border: none;
  border-radius: 6px;
  background: var(--vp-c-brand);
  color: white;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  background: var(--vp-c-brand-dark);
}

.btn-secondary {
  width: 100%;
  padding: 0.6rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-bg-soft);
}

.btn-text {
  width: 100%;
  padding: 0.5rem;
  border: none;
  background: none;
  color: var(--vp-c-text-2);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-text:hover {
  color: var(--vp-c-brand);
}

/* 模式切换 */
.mode-toggle {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}

.mode-btn {
  flex: 1;
  padding: 0.6rem 1rem;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
  border-radius: 6px;
  font-size: 0.9rem;
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: all 0.2s;
}

.mode-btn:hover {
  border-color: var(--vp-c-brand);
}

.mode-btn.active {
  border-color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
  font-weight: 500;
}

/* 对比视图 */
.compare-view {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

@media (max-width: 640px) {
  .compare-view {
    grid-template-columns: 1fr;
  }
}

.compare-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.compare-label {
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.compare-canvas {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 0.75rem;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 200px;
}

.compare-canvas img,
.compare-canvas canvas {
  max-width: 100%;
  max-height: 250px;
  object-fit: contain;
  border-radius: 4px;
}

.decode-result {
  background: #000;
}

/* 信息框 */
.info-box {
  padding: 0.75rem;
  background: var(--vp-c-bg-soft);
  border-radius: 6px;
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
  line-height: 1.5;
}

/* 文件信息 */
.file-info {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 0.75rem;
}

.info-row {
  display: flex;
  justify-content: space-between;
  padding: 0.35rem 0;
  font-size: 0.85rem;
}

.info-row:not(:last-child) {
  border-bottom: 1px solid var(--vp-c-divider);
}

.info-label {
  color: var(--vp-c-text-2);
}

.info-value {
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
}

/* 尺寸调整 */
.resize-inputs {
  display: flex;
  align-items: flex-end;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
}

.size-input-group {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.size-input-group label {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
}

.size-input-group input {
  width: 80px;
  padding: 0.4rem 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  font-size: 0.85rem;
  font-family: var(--vp-font-family-mono);
}

.size-separator {
  color: var(--vp-c-text-3);
  padding-bottom: 0.4rem;
}

.lock-ratio {
  padding-bottom: 0.4rem;
  font-size: 0.8rem;
}

/* 预设按钮网格 */
.preset-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.5rem;
}

.preset-btn {
  padding: 0.4rem 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-2);
  font-size: 0.8rem;
  cursor: pointer;
  transition: all 0.2s;
}

.preset-btn:hover {
  border-color: var(--vp-c-brand);
  color: var(--vp-c-brand);
  background: var(--vp-c-brand-soft);
}

/* 文件大小输入 */
.size-limit-input {
  display: flex;
  gap: 0.5rem;
}

.size-limit-input input {
  flex: 1;
  padding: 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  font-size: 0.9rem;
  font-family: var(--vp-font-family-mono);
}

.size-limit-input select {
  padding: 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-size: 0.9rem;
}

/* 结果预览 */
.result-preview {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: var(--vp-c-bg-soft);
  border-radius: 6px;
  font-size: 0.85rem;
}

.result-preview .result-label {
  color: var(--vp-c-text-2);
}

.result-preview .result-value {
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
}

.result-preview .result-ratio {
  margin-left: auto;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand);
  font-size: 0.75rem;
  font-weight: 500;
}

.result-preview .result-ratio.shrink {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

/* 压缩结果 */
.compress-result {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.compress-result .result-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.compress-result .result-label {
  color: var(--vp-c-text-2);
}

.compress-result .result-value {
  font-family: var(--vp-font-family-mono);
  font-weight: 500;
}

.compress-result .result-value.success {
  color: #22c55e;
}

/* 提示文字 */
.hint-text {
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
}

/* 紧凑模式切换 */
.mode-toggle.compact {
  margin-bottom: 0;
}

.mode-toggle.compact .mode-btn {
  padding: 0.4rem 0.75rem;
  font-size: 0.85rem;
}

/* 文本截断 */
.text-truncate {
  max-width: 150px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
