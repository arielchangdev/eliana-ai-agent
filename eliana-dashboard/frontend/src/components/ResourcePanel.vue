<script setup lang="ts">
import { computed } from 'vue'
import ResourceGauge from './ResourceGauge.vue'
import type { ResourceMetrics } from '../types/dashboard'

const props = defineProps<{
  resources: Record<string, ResourceMetrics>
}>()

// 雙機顯示順序：RHEL 10 優先，其次 Kali
const hosts = computed(() => {
  const keys = Object.keys(props.resources)
  return keys.sort((a, b) => {
    if (a.toLowerCase().includes('rhel')) return -1
    if (b.toLowerCase().includes('rhel')) return 1
    return a.localeCompare(b)
  })
})
</script>

<template>
  <div class="resource-panel" data-testid="resource-panel">
    <div v-for="host in hosts" :key="host" class="resource-panel__host" data-testid="host-panel">
      <h3>{{ host }}</h3>
      <ResourceGauge
        label="CPU"
        :percent="resources[host].cpuPercent"
        :stale="resources[host].stale"
      />
      <ResourceGauge
        label="記憶體"
        :percent="resources[host].memoryPercent"
        :stale="resources[host].stale"
      />
      <ResourceGauge
        label="磁碟"
        :percent="resources[host].diskPercent"
        :stale="resources[host].stale"
      />
    </div>
    <p v-if="hosts.length === 0" data-testid="no-hosts">尚無資源資料</p>
  </div>
</template>

<style scoped>
.resource-panel { display: flex; gap: 16px; flex-wrap: wrap; }
.resource-panel__host { flex: 1; min-width: 220px; padding: 12px; border: 1px solid #ddd; border-radius: 8px; }
</style>
