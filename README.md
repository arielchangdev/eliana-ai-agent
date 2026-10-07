# Eliana — An Autonomous AI Agent

> A self-hosted, locally-reasoning AI agent with an evolving personality, continuous
> learning, human-in-the-loop authorization, and cross-host task orchestration.
>
> 一個自架、以本地 LLM 推理的自主 AI agent：具備可演化的人格、持續學習、
> 人在環路授權，以及跨主機任務編排。

---

## English

### What it is

Eliana is an **autonomous AI agent**, not a single-purpose tool. A local LLM (served
on-box) is its reasoning core; around that core sit six cooperating subsystems that give
the agent a personality, a memory, a way to learn, a human-facing control channel, and
the ability to carry out tasks across more than one machine — always under explicit human
authorization.

Bug bounty automation is one of the agent's *task capabilities*, deliberately wrapped in a
strict authorization gate. This repository focuses on the **agent architecture and its
safety design**, not on offensive techniques — scanning internals are intentionally left out.

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
     │ personality  │      │  learning   │ │  dashboard │ │  task exec    │
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
| **learning-engine** | Crawl → process → optimize → knowledge base (vector store), with reflection |
| **dashboard** | Real-time monitoring + Telegram control, batched/priority notifications |
| **digital-wallet** | Encrypted ledger and backup for tracking task outcomes (testnet in this demo) |
| **task execution** | Authorized, human-gated capability; **dry-run by default** |
| **integration** | Wires everything into one lifecycle with an event bus |

### Safety by design

- **Human-in-the-loop authorization** — sensitive actions require explicit approval; default is to refuse.
- **Dry-run by default** — real execution needs an explicit flag that this demo never sets.
- **Bounded self-evolution** — the agent may adjust its own personality only within hard limits; larger shifts pause for a human.
- **Local reasoning** — the LLM runs on-box; no dependency on a third-party cloud model.
- **Secrets stay out of source** — all credentials load from the environment; this repo ships placeholders only.

### Status

All six subsystems start cleanly and report healthy. This is a **portfolio / engineering
case study**, de-identified for public sharing. It is not financial, security, or legal advice.

---

## 中文

### 這是什麼

Eliana 是一個**自主 AI agent**，不是單一用途的工具。它以一顆**本地 LLM**（在機器上自架）
作為推理核心，核心外圍由六個協作子系統組成，賦予這個 agent 人格、記憶、學習能力、
人機控制介面，以及跨多台主機執行任務的能力——而且**一律在明確的人類授權之下**。

Bug bounty 自動化只是這個 agent 的其中一種**任務能力**，並刻意包在嚴格的授權閘門內。
本 repo 聚焦在 **agent 的架構與安全設計**，不展示攻擊手法——掃描細節刻意略去。

### 子系統

| 子系統 | 角色 |
|--------|------|
| **core-infra** | FastAPI app、本地 LLM 客戶端、資源監控、任務排程、SSH 通道 |
| **personality** | 可**自我演化**的人格設定，但有硬性上限（單次 ≤5%、累計 ≤15% 需人工確認） |
| **learning-engine** | 爬取 → 處理 → 最佳化 → 知識庫（向量儲存），含反思機制 |
| **dashboard** | 即時監控 + Telegram 控制、批次/優先級通知 |
| **digital-wallet** | 加密帳本與備份，追蹤任務成果（本展示使用測試網） |
| **task execution** | 授權、人工把關的能力；**預設 dry-run** |
| **integration** | 以事件匯流排把所有元件接成單一生命週期 |

### 以設計守住安全

- **人在環路授權**——敏感操作需明確核准，預設拒絕。
- **預設 dry-run**——真實執行需要一個明確旗標，本展示從不開啟。
- **有界的自我演化**——agent 只能在硬性上限內調整自己的人格，更大的變動會暫停等待人工確認。
- **本地推理**——LLM 在機器上運行，不依賴第三方雲端模型。
- **機密不進原始碼**——所有憑證從環境載入，本 repo 只含佔位值。

### 狀態

六個子系統皆可乾淨啟動並回報健康。這是一份**作品集／工程案例研究**，已去識別化供公開分享。
本專案不構成財務、資安或法律建議。

---

## License

MIT — see [LICENSE](LICENSE).