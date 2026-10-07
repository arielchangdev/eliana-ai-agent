<script setup lang="ts">
import type { ResourceAlert } from '../types/dashboard'

defineProps<{ alerts: ResourceAlert[] }>()
</script>

<template>
  <div v-if="alerts.length > 0" class="alert-banner" data-testid="alert-banner">
    <div v-for="(alert, i) in alerts" :key="i" class="alert-banner__item">
      ⚠️ {{ alert.host }} {{ alert.metricName }} 達 {{ Math.round(alert.currentValue) }}%
      (閾值 {{ Math.round(alert.thresholdValue) }}%)
    </div>
  </div>
</template>

<style scoped>
.alert-banner { background: #d32f2f; color: white; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; }
.alert-banner__item { margin: 2px 0; }
</style>
