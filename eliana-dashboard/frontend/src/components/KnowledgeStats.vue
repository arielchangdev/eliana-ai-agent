<script setup lang="ts">
import { computed } from 'vue'
import type { KnowledgeStats } from '../types/dashboard'

const props = defineProps<{ stats: KnowledgeStats | null }>()

const categories = computed(() => {
  if (!props.stats) return []
  return Object.entries(props.stats.categoryDistribution).map(([name, count]) => ({
    name, count,
  }))
})

const maxCount = computed(() =>
  Math.max(1, ...categories.value.map((c) => c.count))
)
</script>

<template>
  <div class="knowledge-stats" data-testid="knowledge-stats">
    <template v-if="stats">
      <div class="knowledge-stats__total" data-testid="total-fragments">
        總片段數: {{ stats.totalFragments }}
      </div>
      <div class="knowledge-stats__categories">
        <div
          v-for="cat in categories"
          :key="cat.name"
          class="knowledge-stats__bar-row"
          data-testid="category-bar"
        >
          <span class="knowledge-stats__cat-name">{{ cat.name }}</span>
          <div class="knowledge-stats__bar-track">
            <div
              class="knowledge-stats__bar"
              :style="{ width: (cat.count / maxCount * 100) + '%' }"
            />
          </div>
          <span>{{ cat.count }}</span>
        </div>
      </div>
      <div class="knowledge-stats__meta">
        <p data-testid="last-crawl">
          上次爬取: {{ stats.lastCrawlTime ?? '無' }} ({{ stats.lastCrawlStatus ?? '-' }})
        </p>
        <p data-testid="strategy-summary">
          策略: 共 {{ stats.strategySummary.total ?? 0 }} /
          高效 {{ stats.strategySummary.highEfficiency ?? 0 }} /
          待優化 {{ stats.strategySummary.needsOptimization ?? 0 }}
        </p>
      </div>
    </template>
    <p v-else data-testid="no-knowledge">暫無數據</p>
  </div>
</template>

<style scoped>
.knowledge-stats__total { font-weight: bold; margin-bottom: 8px; }
.knowledge-stats__bar-row { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
.knowledge-stats__cat-name { width: 100px; font-size: 13px; }
.knowledge-stats__bar-track { flex: 1; height: 14px; background: #e0e0e0; border-radius: 4px; }
.knowledge-stats__bar { height: 100%; background: #3f51b5; border-radius: 4px; }
</style>
