<script setup lang="ts">
import { onMounted, onUnmounted, computed } from 'vue'
import { useDashboardStore } from '../composables/useDashboardStore'
import { useWebSocket } from '../composables/useWebSocket'
import AgentStatus from '../components/AgentStatus.vue'
import ConnectionStatus from '../components/ConnectionStatus.vue'
import ResourcePanel from '../components/ResourcePanel.vue'
import TaskTimeline from '../components/TaskTimeline.vue'
import KnowledgeStats from '../components/KnowledgeStats.vue'
import AlertBanner from '../components/AlertBanner.vue'

const store = useDashboardStore()

const ws = useWebSocket({
  url: `ws://${window.location.host}/ws/dashboard`,
  onMessage: (msg) => store.handleMessage(msg),
})

// 同步連線狀態至 store
const connectionStatus = computed(() => ws.status.value)

onMounted(() => {
  ws.connect()
})

onUnmounted(() => {
  ws.disconnect()
})
</script>

<template>
  <div class="dashboard">
    <header class="dashboard__header">
      <h1>Eliana 監控面板</h1>
      <ConnectionStatus :status="connectionStatus" />
    </header>

    <AlertBanner :alerts="store.activeAlerts" />

    <section class="dashboard__section">
      <AgentStatus
        :state="store.agentState"
        :task-name="store.currentTaskName"
        :progress="store.currentTaskProgress"
      />
    </section>

    <section class="dashboard__section">
      <h2>系統資源</h2>
      <ResourcePanel :resources="store.resources" />
    </section>

    <section class="dashboard__section">
      <h2>任務時間線</h2>
      <TaskTimeline :tasks="store.recentTasks" />
    </section>

    <section class="dashboard__section">
      <h2>成長狀態</h2>
      <KnowledgeStats :stats="store.knowledgeStats" />
    </section>
  </div>
</template>

<style scoped>
.dashboard { max-width: 1100px; margin: 0 auto; padding: 16px; font-family: system-ui, sans-serif; }
.dashboard__header { display: flex; justify-content: space-between; align-items: center; }
.dashboard__section { margin: 20px 0; }
</style>
