<script setup lang="ts">
import { computed } from 'vue'
import type { ConnectionStatus } from '../types/dashboard'

const props = defineProps<{ status: ConnectionStatus }>()

const label = computed(() => {
  const map: Record<ConnectionStatus, string> = {
    connected: '已連線',
    disconnected: '連線中斷',
    reconnecting: '重新連線中…',
  }
  return map[props.status]
})

const isWarning = computed(() => props.status !== 'connected')
</script>

<template>
  <div
    class="connection-status"
    :class="{ 'connection-status--warning': isWarning }"
    data-testid="connection-status"
  >
    <span class="connection-status__dot" :class="`connection-status__dot--${status}`" />
    <span>{{ label }}</span>
  </div>
</template>

<style scoped>
.connection-status { display: flex; align-items: center; gap: 6px; }
.connection-status--warning { color: #d32f2f; font-weight: bold; }
.connection-status__dot { width: 10px; height: 10px; border-radius: 50%; }
.connection-status__dot--connected { background: #4caf50; }
.connection-status__dot--disconnected { background: #d32f2f; }
.connection-status__dot--reconnecting { background: #ff9800; }
</style>
