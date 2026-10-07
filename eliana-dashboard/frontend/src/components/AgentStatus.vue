<script setup lang="ts">
import { computed } from 'vue'
import type { AgentState } from '../types/dashboard'

const props = defineProps<{
  state: AgentState
  taskName: string | null
  progress: number
}>()

const stateLabel = computed(() => {
  const map: Record<AgentState, string> = {
    idle: '閒置',
    running: '執行中',
    paused: '暫停',
    error: '錯誤',
  }
  return map[props.state]
})

const stateClass = computed(() => `agent-status--${props.state}`)
const progressPercent = computed(() => Math.round(props.progress * 100))
</script>

<template>
  <div class="agent-status" :class="stateClass" data-testid="agent-status">
    <span class="agent-status__label">{{ stateLabel }}</span>
    <template v-if="taskName">
      <span class="agent-status__task" data-testid="task-name">{{ taskName }}</span>
      <div class="agent-status__progress">
        <div class="agent-status__bar" :style="{ width: progressPercent + '%' }" />
        <span data-testid="progress">{{ progressPercent }}%</span>
      </div>
    </template>
    <span v-else class="agent-status__task">無執行中任務</span>
  </div>
</template>

<style scoped>
.agent-status { padding: 12px; border-radius: 8px; }
.agent-status--idle { background: #eef; }
.agent-status--running { background: #efe; }
.agent-status--paused { background: #ffe; }
.agent-status--error { background: #fee; }
.agent-status__progress { position: relative; height: 16px; background: #ddd; border-radius: 4px; }
.agent-status__bar { height: 100%; background: #4caf50; border-radius: 4px; }
</style>
