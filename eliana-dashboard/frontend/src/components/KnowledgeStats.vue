<script setup lang="ts">
import { computed } from 'vue'
import type { KnowledgeStats } from '../types/dashboard'

const props = defineProps<{ stats: KnowledgeStats | null }>()

// 知識累積：人話分類（後端已轉成「對話中學到 / 你教的」）
const categories = computed(() => {
  if (!props.stats) return []
  return Object.entries(props.stats.categoryDistribution).map(([name, count]) => ({
    name,
    count: Number(count),
  }))
})

const maxCount = computed(() =>
  Math.max(1, ...categories.value.map((c) => c.count)),
)

// 成長摘要（長期記憶、人格版本、演化、參數）
const s = computed(() => props.stats?.strategySummary ?? {})

const memorySegments = computed(() => Number(s.value['長期記憶段數'] ?? 0))
const assessmentCount = computed(() => Number(s.value['評估經驗次數'] ?? 0))
const personaVersion = computed(() => Number(s.value['人格版本'] ?? 0))
const evolveCount = computed(() => Number(s.value['已演化次數'] ?? 0))

// 評估經驗成長趨勢：每日累積筆數序列（由後端提供；沒資料就空）
type TrendPoint = { date: string; cumulative: number }
const assessmentTrend = computed<TrendPoint[]>(() => {
  const raw = s.value['評估經驗趨勢']
  return Array.isArray(raw) ? (raw as TrendPoint[]) : []
})

// 畫一條簡易 sparkline（SVG polyline）。只在趨勢有實際成長時才顯示，
// 全 0（還沒累積）就不畫，誠實不假裝有曲線。
const hasTrend = computed(() =>
  assessmentTrend.value.some((p) => Number(p.cumulative) > 0),
)
const SPARK_W = 160
const SPARK_H = 32
const sparkPoints = computed(() => {
  const pts = assessmentTrend.value
  if (pts.length === 0) return ''
  const maxCum = Math.max(1, ...pts.map((p) => Number(p.cumulative)))
  const stepX = pts.length > 1 ? SPARK_W / (pts.length - 1) : 0
  return pts
    .map((p, i) => {
      const x = i * stepX
      const y = SPARK_H - (Number(p.cumulative) / maxCum) * SPARK_H
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
})

// 參數值轉人話百分比；null -> 尚未設定
function pct(v: number | string | null | undefined): string {
  if (v === null || v === undefined || v === '') return '—'
  const n = Number(v)
  if (Number.isNaN(n)) return String(v)
  return Math.round(n * 100) + '%'
}

const traits = computed(() => [
  { label: '主動性', value: pct(s.value['主動性']) },
  { label: '幽默感', value: pct(s.value['幽默感']) },
  { label: '表情頻率', value: pct(s.value['表情頻率']) },
])

const evolveLabel = computed(() =>
  evolveCount.value > 0
    ? `已演化 ${evolveCount.value} 次`
    : '尚未演化（初始人格）',
)
</script>

<template>
  <div class="growth" data-testid="knowledge-stats">
    <template v-if="stats">
      <!-- 知識累積 -->
      <section class="growth__block">
        <h4 class="growth__title">知識累積</h4>
        <div class="growth__total" data-testid="total-fragments">
          總計 {{ stats.totalFragments }} 筆
        </div>
        <div
          v-for="cat in categories"
          :key="cat.name"
          class="growth__bar-row"
          data-testid="category-bar"
        >
          <span class="growth__cat-name">{{ cat.name }}</span>
          <div class="growth__bar-track">
            <div class="growth__bar" :style="{ width: (cat.count / maxCount * 100) + '%' }" />
          </div>
          <span class="growth__count">{{ cat.count }}</span>
        </div>
      </section>

      <!-- 長期記憶 -->
      <section class="growth__block">
        <h4 class="growth__title">長期記憶</h4>
        <p class="growth__line" data-testid="memory-segments">
          {{ memorySegments }} 段對話
        </p>
      </section>

      <!-- 評估經驗（成長閉環：越評估越懂）-->
      <section class="growth__block">
        <h4 class="growth__title">評估經驗</h4>
        <p class="growth__line" data-testid="assessment-count">
          <template v-if="assessmentCount > 0">
            從 {{ assessmentCount }} 次評估累積經驗（下次評估會回想參考）
          </template>
          <template v-else>尚未累積評估經驗</template>
        </p>
        <!-- 成長趨勢 sparkline：有實際累積才畫 -->
        <div
          v-if="hasTrend"
          class="growth__trend"
          data-testid="assessment-trend"
        >
          <svg
            class="growth__spark"
            :viewBox="`0 0 ${SPARK_W} ${SPARK_H}`"
            preserveAspectRatio="none"
          >
            <polyline :points="sparkPoints" />
          </svg>
          <span class="growth__trend-label">近 {{ assessmentTrend.length }} 天累積趨勢</span>
        </div>
      </section>

      <!-- 人格演化 -->
      <section class="growth__block">
        <h4 class="growth__title">人格演化</h4>
        <p class="growth__line" data-testid="persona-evolution">
          目前版本 v{{ personaVersion }} · {{ evolveLabel }}
        </p>
        <div class="growth__traits">
          <span v-for="t in traits" :key="t.label" class="growth__trait">
            {{ t.label }} <strong>{{ t.value }}</strong>
          </span>
        </div>
      </section>
    </template>
    <p v-else data-testid="no-knowledge">尚無資料</p>
  </div>
</template>

<style scoped>
.growth__block { margin-bottom: 14px; }
.growth__title { margin: 0 0 6px; font-size: 13px; color: #555; font-weight: 600; }
.growth__total { font-weight: bold; margin-bottom: 6px; }
.growth__bar-row { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
.growth__cat-name { width: 96px; font-size: 13px; }
.growth__bar-track { flex: 1; height: 14px; background: #e0e0e0; border-radius: 4px; }
.growth__bar { height: 100%; background: #3f51b5; border-radius: 4px; }
.growth__count { width: 28px; text-align: right; font-size: 13px; }
.growth__line { margin: 2px 0; }
.growth__traits { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 4px; }
.growth__trait { font-size: 13px; color: #444; }
.growth__trend { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.growth__spark { width: 160px; height: 32px; }
.growth__spark polyline {
  fill: none; stroke: #3f51b5; stroke-width: 1.5;
  stroke-linejoin: round; stroke-linecap: round;
}
.growth__trend-label { font-size: 12px; color: #777; }
</style>
