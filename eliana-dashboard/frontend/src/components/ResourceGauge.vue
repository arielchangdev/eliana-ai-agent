<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  label: string
  percent: number
  stale?: boolean
}>()

const clamped = computed(() => Math.max(0, Math.min(100, props.percent)))
const level = computed(() => {
  if (props.stale) return 'stale'
  if (clamped.value >= 90) return 'critical'
  if (clamped.value >= 70) return 'warning'
  return 'normal'
})
</script>

<template>
  <div class="gauge" :class="`gauge--${level}`" data-testid="resource-gauge">
    <div class="gauge__header">
      <span class="gauge__label">{{ label }}</span>
      <span class="gauge__value" data-testid="gauge-value">
        {{ stale ? '資料過期' : Math.round(clamped) + '%' }}
      </span>
    </div>
    <div class="gauge__track">
      <div
        class="gauge__fill"
        :style="{ width: (stale ? 0 : clamped) + '%' }"
        data-testid="gauge-fill"
      />
    </div>
  </div>
</template>

<style scoped>
.gauge { margin: 8px 0; }
.gauge__header { display: flex; justify-content: space-between; font-size: 13px; }
.gauge__track { height: 12px; background: #e0e0e0; border-radius: 6px; overflow: hidden; }
.gauge__fill { height: 100%; transition: width 0.3s; }
.gauge--normal .gauge__fill { background: #4caf50; }
.gauge--warning .gauge__fill { background: #ff9800; }
.gauge--critical .gauge__fill { background: #d32f2f; }
.gauge--stale { opacity: 0.5; }
</style>
