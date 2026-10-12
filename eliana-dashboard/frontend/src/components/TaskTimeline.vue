<script setup lang="ts">
import { computed, ref } from 'vue'
import type {
  TaskResultStatus, TaskTimelineItem, TaskFinding, StageState,
} from '../types/dashboard'

const props = defineProps<{
  tasks: TaskTimelineItem[]
  successRate24h?: number
  successRate7d?: number
}>()

const statusFilter = ref<TaskResultStatus | ''>('')
const keyword = ref('')
const expandedId = ref<string | null>(null)

const filteredTasks = computed(() =>
  props.tasks.filter((t) => {
    if (statusFilter.value && t.status !== statusFilter.value) return false
    if (keyword.value && !t.name.toLowerCase().includes(keyword.value.toLowerCase())) return false
    return true
  }),
)

function toggle(taskId: string) {
  expandedId.value = expandedId.value === taskId ? null : taskId
}

const statusLabel: Record<TaskResultStatus, string> = {
  success: '完成', failed: '失敗', timeout: '逾時',
  cancelled: '取消', running: '進行中',
}

// severity -> 顏色 + 中文標籤
const SEV: Record<string, { color: string; label: string }> = {
  info: { color: '#9e9e9e', label: 'INFO' },
  low: { color: '#2196f3', label: 'LOW' },
  medium: { color: '#f5b301', label: 'MEDIUM' },
  high: { color: '#fb8c00', label: 'HIGH' },
  critical: { color: '#e53935', label: 'CRITICAL' },
}
function sevStyle(sev: string) {
  const s = SEV[(sev || '').toLowerCase()] ?? SEV.info
  return { background: s.color }
}
function sevLabel(sev: string) {
  return (SEV[(sev || '').toLowerCase()] ?? SEV.info).label
}

// 階段狀態 -> class
function stageClass(state: StageState) {
  return `stage--${state}`
}

function fmtTime(iso: string | null) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString()
}
function fmtDur(sec: number | null) {
  if (sec == null) return ''
  return sec < 60 ? `${sec.toFixed(1)}s` : `${(sec / 60).toFixed(1)}m`
}

function hasReport(f: TaskFinding): boolean {
  return f.report != null
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
        <option value="success">完成</option>
        <option value="failed">失敗</option>
        <option value="timeout">逾時</option>
        <option value="cancelled">取消</option>
        <option value="running">進行中</option>
      </select>
      <input v-model="keyword" placeholder="搜尋任務名稱" data-testid="keyword-search" />
    </div>

    <ul class="cards">
      <li
        v-for="task in filteredTasks"
        :key="task.taskId"
        class="card"
        data-testid="task-item"
      >
        <!-- 標題列 -->
        <div class="card__head" @click="toggle(task.taskId)">
          <span class="card__name">{{ task.name }}</span>
          <span class="card__badge" :class="`badge--${task.status}`">
            {{ statusLabel[task.status] }}
          </span>
        </div>
        <div class="card__meta">
          {{ fmtTime(task.startTime) }}
          <template v-if="task.durationSeconds != null"> · 耗時 {{ fmtDur(task.durationSeconds) }}</template>
        </div>

        <!-- 橫向階段步驟條 -->
        <div class="stages" data-testid="stage-bar">
          <template v-for="(s, i) in task.stages" :key="s.key">
            <div class="stage" :class="stageClass(s.state)" :title="s.state">
              <span class="stage__dot" />
              <span class="stage__label">{{ s.label }}</span>
            </div>
            <span v-if="i < task.stages.length - 1" class="stage__sep"
                  :class="stageClass(s.state)" />
          </template>
        </div>

        <!-- 發現摘要 -->
        <div class="findings">
          <span
            v-for="(f, i) in task.findings"
            :key="i"
            class="sev-tag"
            :style="sevStyle(f.severity)"
          >{{ sevLabel(f.severity) }}</span>
          <span v-if="task.findings.length === 0" class="findings__none">無發現</span>
        </div>

        <!-- 展開：發現細節 + 報告 -->
        <div v-if="expandedId === task.taskId" class="detail" data-testid="task-detail">
          <div v-for="(f, i) in task.findings" :key="i" class="finding">
            <div class="finding__title">
              <span class="sev-tag" :style="sevStyle(f.severity)">{{ sevLabel(f.severity) }}</span>
              {{ f.title }}
              <span v-if="f.cve_id" class="finding__cve">{{ f.cve_id }}</span>
            </div>

            <!-- 有報告：Eliana 敘述分欄 + CVSS -->
            <div v-if="hasReport(f)" class="report">
              <div class="report__cvss">
                CVSS {{ f.report!.cvss_score }}
                <code v-if="f.report!.cvss_vector">{{ f.report!.cvss_vector }}</code>
              </div>
              <div v-if="f.report!.description" class="report__sec">
                <h5>描述</h5><p>{{ f.report!.description }}</p>
              </div>
              <div v-if="f.report!.reproduction_steps" class="report__sec">
                <h5>重現步驟</h5><p>{{ f.report!.reproduction_steps }}</p>
              </div>
              <div v-if="f.report!.impact_assessment" class="report__sec">
                <h5>影響評估</h5><p>{{ f.report!.impact_assessment }}</p>
              </div>
              <div v-if="f.report!.remediation" class="report__sec">
                <h5>修補建議</h5><p>{{ f.report!.remediation }}</p>
              </div>
            </div>
            <!-- 無報告：誠實顯示無需報告 -->
            <div v-else class="report report--none">
              無需報告（{{ sevLabel(f.severity) }} 等級，未達報告門檻）
            </div>
          </div>
          <p v-if="task.findings.length === 0" class="detail__empty">此次掃描無任何發現</p>
        </div>
      </li>
    </ul>
    <p v-if="filteredTasks.length === 0" data-testid="no-tasks">尚無掃描任務</p>
  </div>
</template>

<style scoped>
.task-timeline__summary { display: flex; gap: 16px; font-weight: bold; margin-bottom: 8px; }
.task-timeline__filters { display: flex; gap: 8px; margin-bottom: 12px; }
.cards { list-style: none; padding: 0; margin: 0; }
.card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 12px; margin: 10px 0; background: #fff; }
.card__head { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
.card__name { font-weight: 600; }
.card__badge { font-size: 12px; padding: 2px 8px; border-radius: 10px; background: #eee; }
.badge--success { background: #e8f5e9; color: #2e7d32; }
.badge--failed { background: #ffebee; color: #c62828; }
.badge--running { background: #e3f2fd; color: #1565c0; }
.card__meta { font-size: 12px; color: #777; margin: 4px 0 10px; }

/* 橫向階段步驟條 */
.stages { display: flex; align-items: center; flex-wrap: wrap; gap: 2px; margin-bottom: 10px; }
.stage { display: flex; flex-direction: column; align-items: center; min-width: 56px; }
.stage__dot { width: 14px; height: 14px; border-radius: 50%; background: #d0d0d0; }
.stage__label { font-size: 11px; color: #999; margin-top: 3px; }
.stage__sep { flex: 1; height: 2px; min-width: 14px; background: #d0d0d0; margin-bottom: 16px; }
.stage--done .stage__dot, .stage__sep.stage--done { background: #4caf50; }
.stage--done .stage__label { color: #4caf50; }
.stage--active .stage__dot { background: #2196f3; }
.stage--active .stage__label { color: #2196f3; }
.stage--skipped .stage__dot { background: #e0e0e0; border: 1px dashed #bbb; }
.stage--skipped .stage__label { color: #bbb; }
.stage--pending .stage__dot { background: #d0d0d0; }

/* severity 標籤 */
.sev-tag { color: #fff; font-size: 11px; font-weight: 600; padding: 1px 6px; border-radius: 4px; }
.findings { display: flex; gap: 6px; flex-wrap: wrap; }
.findings__none { font-size: 12px; color: #999; }

/* 展開細節 */
.detail { margin-top: 10px; border-top: 1px solid #eee; padding-top: 10px; }
.finding { margin-bottom: 12px; }
.finding__title { font-size: 14px; margin-bottom: 4px; }
.finding__cve { font-size: 11px; color: #888; margin-left: 6px; }
.report { background: #fafafa; border-radius: 6px; padding: 8px; }
.report--none { color: #999; font-size: 13px; font-style: italic; }
.report__cvss { font-weight: 600; margin-bottom: 6px; }
.report__cvss code { font-size: 11px; color: #555; background: #eee; padding: 1px 4px; border-radius: 3px; }
.report__sec { margin: 6px 0; }
.report__sec h5 { margin: 0 0 2px; font-size: 12px; color: #555; }
.report__sec p { margin: 0; font-size: 13px; white-space: pre-wrap; }
.detail__empty { color: #999; font-size: 13px; }
</style>
