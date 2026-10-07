<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TaskResultStatus, TaskTimelineItem } from '../types/dashboard'

const props = defineProps<{
  tasks: TaskTimelineItem[]
  successRate24h?: number
  successRate7d?: number
}>()

const statusFilter = ref<TaskResultStatus | ''>('')
const keyword = ref('')
const expandedId = ref<string | null>(null)

const filteredTasks = computed(() => {
  return props.tasks.filter((t) => {
    if (statusFilter.value && t.status !== statusFilter.value) return false
    if (keyword.value && !t.name.toLowerCase().includes(keyword.value.toLowerCase())) return false
    return true
  })
})

function toggle(taskId: string) {
  expandedId.value = expandedId.value === taskId ? null : taskId
}

const statusLabel: Record<TaskResultStatus, string> = {
  success: '成功', failed: '失敗', timeout: '逾時',
  cancelled: '取消', running: '進行中',
}
</script>

<template>
  <div class="task-timeline" data-testid="task-timeline">
    <div class="task-timeline__summary" data-testid="success-summary">
      <span>24h 成功率: {{ Math.round((successRate24h ?? 0) * 100) }}%</span>
      <span>7d 成功率: {{ Math.round((successRate7d ?? 0) * 100) }}%</span>
    </div>
    <div class="task-timeline__filters">
      <select v-model="statusFilter" data-testid="status-filter">
        <option value="">全部狀態</option>
        <option value="success">成功</option>
        <option value="failed">失敗</option>
        <option value="timeout">逾時</option>
        <option value="cancelled">取消</option>
        <option value="running">進行中</option>
      </select>
      <input v-model="keyword" placeholder="搜尋任務名稱" data-testid="keyword-search" />
    </div>
    <ul class="task-timeline__list">
      <li
        v-for="task in filteredTasks"
        :key="task.taskId"
        class="task-timeline__item"
        :class="`task-timeline__item--${task.status}`"
        data-testid="task-item"
        @click="toggle(task.taskId)"
      >
        <div class="task-timeline__row">
          <span class="task-timeline__name">{{ task.name }}</span>
          <span class="task-timeline__status">{{ statusLabel[task.status] }}</span>
        </div>
        <div v-if="expandedId === task.taskId" class="task-timeline__detail" data-testid="task-detail">
          <p v-if="task.target">目標: {{ task.target }}</p>
          <p v-if="task.strategy">策略: {{ task.strategy }}</p>
          <p v-if="task.errorMessage">錯誤: {{ task.errorMessage }}</p>
          <p v-if="task.outputSummary">摘要: {{ task.outputSummary }}</p>
        </div>
      </li>
    </ul>
    <p v-if="filteredTasks.length === 0" data-testid="no-tasks">無符合條件的任務</p>
  </div>
</template>

<style scoped>
.task-timeline__summary { display: flex; gap: 16px; font-weight: bold; margin-bottom: 8px; }
.task-timeline__filters { display: flex; gap: 8px; margin-bottom: 8px; }
.task-timeline__list { list-style: none; padding: 0; }
.task-timeline__item { padding: 8px; border-left: 4px solid #ccc; cursor: pointer; margin: 4px 0; }
.task-timeline__item--success { border-color: #4caf50; }
.task-timeline__item--failed { border-color: #d32f2f; }
.task-timeline__item--running { border-color: #2196f3; }
.task-timeline__row { display: flex; justify-content: space-between; }
</style>
