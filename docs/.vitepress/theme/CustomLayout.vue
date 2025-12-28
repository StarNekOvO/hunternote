<template>
  <Layout>
    <template #doc-before>
      <ReadingTime />
    </template>
  </Layout>
</template>

<script setup lang="ts">
import DefaultTheme from 'vitepress/theme'
import ReadingTime from './components/ReadingTime.vue'

const { Layout } = DefaultTheme
</script>
