# Eliana — A Self-Improving Red-Team Assessment Agent

> **Autonomy with a leash** — 給它自主,但手上留一條韁繩。
>
> An authorized, human-in-the-loop red-team assessment agent: it orchestrates multiple
> tools, classifies findings against MITRE ATT&CK, and improves its own assessment
> behavior through a verifiable learning loop. It assesses and classifies — it does not
> perform exploitation or any offensive action.
>
> 一個授權、人在環路的成長型紅隊評估 agent:編排多種評估工具、將發現對應到 MITRE
> ATT&CK、並透過可驗證的學習閉環改進自己的評估行為。它做評估與分類,不執行攻擊。

---

## 📖 Portfolio & Write-ups

| | |
|---|---|
| 🌐 **Landing page** | https://arielchangdev.github.io/eliana-ai-agent/ |
| 📐 **Case Study** | [CASE_STUDY.md](CASE_STUDY.md) — 架構敘事與三支柱設計 |
| 🔧 **Engineering Blog** | [The hard part wasn't the AI](https://dev.to/arielchangdev/the-hard-part-wasnt-the-ai-6-wiring-bugs-from-building-a-self-improving-agent-3bd5) — 六個 wiring bug 的除錯過程 |
| 📝 **Changelog** | [CHANGELOG.md](CHANGELOG.md) — 能力演進紀錄 |

> The landing page and case study tell you **what** Eliana is and **why** it's built the
> way it is. This README goes one level down into **how** — the subsystems, the
> architecture, and the safety mechanisms that enforce scope in code.

---

## Three Pillars

1. **Autonomous architecture** — multi-tool orchestration across a phased assessment profile, operated conversationally over a Telegram runtime with a live dashboard.
2. **Bounded self-improvement** — an assessment memory feeds a verifiable learning loop that measurably changes behavior. In the proven case (**CLOSED-LOOP-PROVEN**), a tool moved from 5th to 3rd in execution order after the agent recalled relevant prior experience — a real, reproducible behavior shift, not a simulated one.
3. **Human-in-the-loop authorization** — a dual authorization gate, an evaluation-mode argument allowlist, and ATT&CK classification (not attack execution) keep scope enforced in code.

---

## English

### What it is

Eliana is an **autonomous, self-improving red-team assessment agent**, not a single-purpose
tool. A local LLM (served on-box) is its reasoning core; around that core sit cooperating
subsystems that give the agent a personality, a memory, a way to learn, a human-facing
control channel, and the ability to carry out **authorized** assessment tasks across more
than one machine — always under explicit human authorization.

Assessment work is wrapped in a strict authorization gate and restricted to an
evaluation-mode allowlist. Findings are classified against MITRE ATT&CK **for reporting**,
never used for exploitation. This repository focuses on the **agent architecture and its
safety design** — scanning internals and offensive techniques are intentionally left out.

### Architecture at a glance

```
                        ┌─────────────────────────────┐
                        │   Human (Telegram control)   │
                        └──────────────┬──────────────┘
                                       │ commands / approvals
                        ┌──────────────▼──────────────┐
   local LLM  ◀────────▶│      Integration layer       │
   (reasoning core)     │  event bus · lifecycle · DI  │
                        └───┬───────┬───────┬──────┬───┘
             ┌──────────────┘       │       │      └──────────────┐
     ┌───────▼──────┐      ┌────────▼────┐ ┌▼───────────┐ ┌───────▼──────┐
     │ personality  │      │  learning   │ │  dashboard │ │  assessment   │
     │ self-evolve  │      │  knowledge  │ │  + notify  │ │  (authorized) │
     └──────────────┘      └─────────────┘ └────────────┘ └───────┬───────┘
                                                                   │ SSH (authorized)
                                                          ┌────────▼────────┐
                                                          │  tooling host    │
                                                          └─────────────────┘
```

### Subsystems

| Subsystem | Role |
|-----------|------|
| **core-infra** | FastAPI app, local-LLM client, resource monitor, task scheduler, SSH channel |
| **personality** | Personality profiles that *self-evolve* within bounded limits (≤5% per change, ≤15% cumulative before human confirmation) |
| **learning-engine** | Crawl → process → optimize → knowledge base (vector store), with reflection; feeds the assessment memory |
| **dashboard** | Real-time monitoring + Telegram control, batched/priority notifications |
| **digital-wallet** | Encrypted ledger and backup for tracking task outcomes (testnet in this demo) |
| **assessment** | Authorized, human-gated capability; multi-tool orchestration + ATT&CK classification; **dry-run by default** |
| **integration** | Wires everything into one lifecycle with an event bus |

### Safety by design

- **Human-in-the-loop authorization** — sensitive actions require explicit approval; default is to refuse.
- **Dual authorization gate** — every assessment passes two independent authorization checks before any tool runs.
- **Evaluation-mode allowlist** — tool arguments are restricted to a vetted evaluation set; intrusive orchestration is excluded by design.
- **ATT&CK classification, not attacks** — findings map to MITRE ATT&CK for reporting only, never for exploitation.
- **Dry-run by default** — real execution needs an explicit flag that this demo never sets.
- **Bounded self-evolution** — the agent may adjust its own personality only within hard limits; larger shifts pause for a human.
- **Local reasoning** — the LLM runs on-box; no dependency on a third-party cloud model.
- **Secrets stay out of source** — all credentials load from the environment; this repo ships placeholders only.

### Status

All subsystems start cleanly and report healthy. This is a **portfolio / engineering
case study**, de-identified for public sharing. It is not financial, security, or legal advice.

---

## 中文

### 這是什麼

Eliana 是一個**自主、成長型的紅隊評估 agent**,不是單一用途的工具。它以一顆**本地 LLM**
(在機器上自架)作為推理核心,核心外圍由多個協作子系統組成,賦予這個 agent 人格、記憶、
學習能力、人機控制介面,以及跨多台主機執行**授權**評估任務的能力——而且**一律在明確的
人類授權之下**。

評估工作包在嚴格的授權閘門內,並限制在 evaluation-mode 白名單。發現會對應到 MITRE
ATT&CK **供報告使用**,絕不用於攻擊。本 repo 聚焦在 **agent 的架構與安全設計**——掃描
細節與攻擊手法刻意略去。

### 三支柱

1. **自主架構** — 多工具編排、分階段評估,透過 Telegram runtime 對話操作,搭配即時面板。
2. **有界的自我演化** — 評估記憶餵養可驗證的學習閉環,實際改變行為。在已驗證的案例(**CLOSED-LOOP-PROVEN**)中,agent 回想起相關過往經驗後,某個工具在執行順序從第 5 位升到第 3 位——一個真實、可重現的行為改變,不是模擬出來的。
3. **人在環路授權** — 雙閘門授權、evaluation-mode 白名單、ATT&CK 分類(非攻擊執行),把範圍限制寫死在程式碼裡。

### 子系統

| 子系統 | 角色 |
|--------|------|
| **core-infra** | FastAPI app、本地 LLM 客戶端、資源監控、任務排程、SSH 通道 |
| **personality** | 可**自我演化**的人格設定,但有硬性上限(單次 ≤5%、累計 ≤15% 需人工確認) |
| **learning-engine** | 爬取 → 處理 → 最佳化 → 知識庫(向量儲存),含反思機制;餵養評估記憶 |
| **dashboard** | 即時監控 + Telegram 控制、批次/優先級通知 |
| **digital-wallet** | 加密帳本與備份,追蹤任務成果(本展示使用測試網) |
| **assessment** | 授權、人工把關的能力;多工具編排 + ATT&CK 分類;**預設 dry-run** |
| **integration** | 以事件匯流排把所有元件接成單一生命週期 |

### 以設計守住安全

- **人在環路授權**——敏感操作需明確核准,預設拒絕。
- **雙閘門授權**——每次評估在任何工具執行前,都要通過兩道獨立授權檢查。
- **evaluation-mode 白名單**——工具參數限制在審核過的評估集,侵入性編排從設計上就排除。
- **ATT&CK 分類而非攻擊**——發現只對應到 MITRE ATT&CK 供報告,絕不用於攻擊。
- **預設 dry-run**——真實執行需要一個明確旗標,本展示從不開啟。
- **有界的自我演化**——agent 只能在硬性上限內調整自己的人格,更大的變動會暫停等待人工確認。
- **本地推理**——LLM 在機器上運行,不依賴第三方雲端模型。
- **機密不進原始碼**——所有憑證從環境載入,本 repo 只含佔位值。

### 狀態

所有子系統皆可乾淨啟動並回報健康。這是一份**作品集／工程案例研究**,已去識別化供公開分享。
本專案不構成財務、資安或法律建議。

---

## License

MIT — see [LICENSE](LICENSE).
