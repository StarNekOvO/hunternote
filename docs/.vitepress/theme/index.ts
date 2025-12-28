import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'

import EncoderTool from './components/EncoderTool.vue'
import BaseConverter from './components/BaseConverter.vue'
import HashTool from './components/HashTool.vue'
import TimestampTool from './components/TimestampTool.vue'
import PwnHelper from './components/PwnHelper.vue'
import RegexTool from './components/RegexTool.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('EncoderTool', EncoderTool)
    app.component('BaseConverter', BaseConverter)
    app.component('HashTool', HashTool)
    app.component('TimestampTool', TimestampTool)
    app.component('PwnHelper', PwnHelper)
    app.component('RegexTool', RegexTool)
  }
} satisfies Theme
