// Pinia Dashboard Store：集中管理面板狀態
import { defineStore } from 'pinia'
import type {
  AgentState,
  ConnectionStatus,
  DashboardMessage,
  DashboardSnapshot,
  KnowledgeStats,
  ResourceAlert,
  ResourceMetrics,
  TaskTimelineItem,
} from '../types/dashboard'

interface DashboardState {
  agentState: AgentState
  currentTaskName: string | null
  currentTaskProgress: number
  resources: Record<string, ResourceMetrics>
  recentTasks: TaskTimelineItem[]
  knowledgeStats: KnowledgeStats | null
  activeAlerts: ResourceAlert[]
  connectionStatus: ConnectionStatus
}

export const useDashboardStore = defineStore('dashboard', {
  state: (): DashboardState => ({
    agentState: 'idle',
    currentTaskName: null,
    currentTaskProgress: 0,
    resources: {},
    recentTasks: [],
    knowledgeStats: null,
    activeAlerts: [],
    connectionStatus: 'disconnected',
  }),

  getters: {
    isRunning: (state) => state.agentState === 'running',
    hasAlerts: (state) => state.activeAlerts.length > 0,
    hostCount: (state) => Object.keys(state.resources).length,
  },

  actions: {
    setConnectionStatus(status: ConnectionStatus) {
      this.connectionStatus = status
    },

    applySnapshot(snapshot: DashboardSnapshot) {
      this.agentState = snapshot.agentState
      this.currentTaskName = snapshot.currentTaskName
      this.currentTaskProgress = snapshot.currentTaskProgress
      this.resources = snapshot.resources ?? {}
      this.recentTasks = snapshot.recentTasks ?? []
      this.knowledgeStats = snapshot.knowledgeStats
      this.activeAlerts = snapshot.activeAlerts ?? []
    },

    handleMessage(msg: DashboardMessage) {
      switch (msg.type) {
        case 'snapshot':
          this.applySnapshot(_snakeToCamelSnapshot(msg.payload))
          break
        case 'agent_status':
          if (typeof msg.payload.state === 'string') {
            this.agentState = msg.payload.state as AgentState
          }
          if ('taskName' in msg.payload) {
            this.currentTaskName = (msg.payload.taskName as string) ?? null
          }
          if (typeof msg.payload.progress === 'number') {
            this.currentTaskProgress = msg.payload.progress
          }
          break
        case 'resource_update': {
          const m = msg.payload as unknown as ResourceMetrics
          if (m.host) this.resources[m.host] = m
          break
        }
        case 'task_update': {
          const t = msg.payload as unknown as TaskTimelineItem
          if (t.taskId) {
            const idx = this.recentTasks.findIndex((x) => x.taskId === t.taskId)
            if (idx >= 0) this.recentTasks[idx] = t
            else this.recentTasks.unshift(t)
          }
          break
        }
        case 'knowledge_update':
          this.knowledgeStats = msg.payload as unknown as KnowledgeStats
          break
        case 'alert': {
          const a = msg.payload as unknown as ResourceAlert
          this.activeAlerts.push(a)
          break
        }
      }
    },
  },
})

// 後端 snapshot payload 使用 snake_case（來自 dataclass），前端統一 camelCase
function _snakeToCamelSnapshot(payload: Record<string, unknown>): DashboardSnapshot {
  return {
    agentState: (payload.agent_state ?? payload.agentState ?? 'idle') as AgentState,
    currentTaskName: (payload.current_task_name ?? payload.currentTaskName ?? null) as string | null,
    currentTaskProgress: (payload.current_task_progress ?? payload.currentTaskProgress ?? 0) as number,
    resources: (payload.resources ?? {}) as Record<string, ResourceMetrics>,
    recentTasks: (payload.recent_tasks ?? payload.recentTasks ?? []) as TaskTimelineItem[],
    knowledgeStats: (payload.knowledge_stats ?? payload.knowledgeStats ?? null) as KnowledgeStats | null,
    activeAlerts: (payload.active_alerts ?? payload.activeAlerts ?? []) as ResourceAlert[],
    timestamp: (payload.timestamp ?? '') as string,
  }
}
