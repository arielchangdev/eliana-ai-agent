// Dashboard 前端型別定義（對應後端 models.py）

export type AgentState = 'idle' | 'running' | 'paused' | 'error'
export type TaskResultStatus = 'success' | 'failed' | 'timeout' | 'cancelled' | 'running'
export type NotificationPriority = 'urgent' | 'normal' | 'low'

export interface ResourceMetrics {
  host: string
  cpuPercent: number
  memoryPercent: number
  memoryUsedGb: number
  memoryTotalGb: number
  diskPercent: number
  diskUsedGb: number
  diskTotalGb: number
  timestamp: string
  stale: boolean
}

export type StageState = 'done' | 'active' | 'skipped' | 'pending'

export interface TaskStage {
  key: string
  label: string
  state: StageState
}

export interface FindingReport {
  cvss_score: number | null
  cvss_vector: string | null
  description: string | null
  reproduction_steps: string | null
  impact_assessment: string | null
  remediation: string | null
  status: string | null
}

export interface TaskFinding {
  severity: string
  title: string
  cve_id: string | null
  report: FindingReport | null
}

export interface TaskTimelineItem {
  taskId: string
  name: string
  status: TaskResultStatus
  startTime: string
  endTime: string | null
  durationSeconds: number | null
  target: string | null
  strategy: string | null
  errorMessage: string | null
  outputSummary: string | null
  stages: TaskStage[]
  findings: TaskFinding[]
}

export interface KnowledgeStats {
  totalFragments: number
  categoryDistribution: Record<string, number>
  dailyGrowth: Array<{ date: string; count: number }>
  lastCrawlTime: string | null
  lastCrawlStatus: string | null
  nextCrawlTime: string | null
  strategySummary: Record<string, number | string | null>
}

export interface ResourceAlert {
  host: string
  metricName: string
  currentValue: number
  thresholdValue: number
  durationSeconds: number
  triggeredAt: string
}

export interface DashboardSnapshot {
  agentState: AgentState
  currentTaskName: string | null
  currentTaskProgress: number
  resources: Record<string, ResourceMetrics>
  recentTasks: TaskTimelineItem[]
  knowledgeStats: KnowledgeStats | null
  activeAlerts: ResourceAlert[]
  timestamp: string
}

export interface DashboardMessage {
  type: 'agent_status' | 'resource_update' | 'task_update' | 'knowledge_update' | 'alert' | 'snapshot'
  payload: Record<string, unknown>
  timestamp: string
}

export type ConnectionStatus = 'connected' | 'disconnected' | 'reconnecting'
