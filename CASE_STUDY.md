# Eliana — A Self-Improving Red-Team AI Agent, on a Leash

> An autonomous agent that runs authorized security assessments, learns from
> every assessment, and gets better at *judging* over time — built so that every
> capability is paired with a constraint that keeps it controllable.
>
> 一個會執行授權安全評估、從每次評估中學習、並隨時間越來越懂判斷的自主 agent
> ——而且每一項能力都配上一道讓它可控的約束。

---

## English

### The question this project answers

A chatbot answers questions. An agent takes actions. A *self-improving* agent
changes its own behavior over time. Each step up that ladder is more useful —
and more dangerous. So the question I set out to answer with working code was:

> **Can you build an AI agent that acts autonomously, in a sensitive domain, and
> gets better on its own — while guaranteeing it stays safe, controllable, and
> inside human-authorized boundaries?**

Eliana is my answer. She's a self-hosted red-team assistant that runs authorized
security assessments, writes professional reports, and learns from each
assessment to sharpen her judgment — all under a design principle I kept
returning to: **give the agent autonomy, but keep it on a leash.**

Every capability below is paired with the constraint that makes it trustworthy.
That pairing is the whole project.

### At a glance

- **Self-hosted, local-LLM-first** (Ollama); cloud (Gemini free tier) is an
  optional accelerator. Runs at **$0**.
- Three auto-recovering services (control channel, dashboard, wallet backend);
  survives reboots.
- A **non-bypassable authorization gate** — the agent cannot act on an
  unauthorized target.
- **Scope framing:** this is agent-safety and assessment-tooling engineering. The
  agent orchestrates *evaluation* tools in read-only/assessment mode; it does
  **not** execute exploits, post-exploitation, or weaponized actions — that line
  is enforced in code and documented below. Offensive techniques are deliberately
  out of scope. The interesting engineering is the guardrail.

---

### Pillar 1 — Autonomous assessment, not a single tool

A real red-team assessment is a methodology, not one `nmap` command. Eliana
orchestrates a full evaluation across phases:

**recon → enumeration → vulnerability scanning → reporting**

Eight evaluation tools (nmap, dnsrecon, whatweb, wafw00f, gobuster, sslscan,
nikto, nuclei), each with a parser; findings are aggregated, de-duplicated, and
correlated across tools ("this was seen by both nikto and nuclei"). She routes
her own reasoning between a local LLM (default, private) and a cloud model
(optional, for speed), deciding per message and falling back to local if the
cloud is unavailable.

**The leash:** every tool runs in **assessment mode only**. The command-line
arguments are defined in a single, auditable whitelist `_EVAL_MODE_ARGS`) — one
place anyone can read to confirm "these are read-only recon parameters, nothing
weaponized." And `sqlmap`, which actively *exploits* SQL injection, is
deliberately **excluded from the agent's automatic orchestration** — its parser
is kept so a human operator can import results manually, but the agent never
pulls that trigger itself. **Assessment is the agent's job; exploitation is a
human's.**

---

### Pillar 2 — Self-improvement, with a proven closed loop

This is the heart of the project, and the hardest claim to make honestly. Lots of
systems say they "learn." I wanted to *prove* the loop actually closes.

Eliana stores the experience from each assessment — what kinds of findings
appeared on what kinds of targets, and which tools were most productive. On the
next assessment, she **recalls** relevant past experience (via vector search) and
it **changes her behavior**:

- **Report context** cites relevant prior experience (recall happens *before* she
  stores the current run, so she can never cite herself).
- **Tool ordering** shifts: within the correct methodology phases, tools that
  were productive before get prioritized.

**The proof:** in a controlled test, a baseline run placed `sslscan` 5th in the
tool order. After seeding relevant past experience, the next run recalled it and
moved `sslscan` to 3rd. *The tool order changed because of experience* — logged as
`CLOSED-LOOP-PROVEN`. Not "data was stored." Stored → recalled → behavior changed.
That's the difference between a system that *claims* to learn and one that
demonstrably does.

**The leash:** what she learns is **methodology and tool-efficacy** — "how to
assess better," never "how to attack harder." The feature that would have let
recall *suggest where to attack next* (closed-loop-3) was **deliberately not
built** — it sits too close to attack-path planning. And the optional LLM
experience-summary passes through an attack-oriented-term filter: if it drifts
toward exploit/payload/privilege-escalation language, that text is discarded and
a structured summary is used instead. Even her growth is kept on the methodology
side of the line.

---

### Pillar 3 — Human-in-the-loop authorization

Eliana can act across more than one machine. For any assessment, the design
assumes she **must not act until a human explicitly authorizes the specific
target** — and this is enforced in code, not by discipline.

The gate has two checks, and neither can be bypassed:

1. **Scope** — the target must be inside an authorized scope.
2. **Explicit authorization record** — a human must have approved *this specific
   target*, with a timestamp and expiry.

If either fails, the action is refused and audited **before any tool runs** — I
verified the execution engine is never even reached for an unauthorized target.
The interaction stays natural (she asks, you approve with a command), but every
approval becomes an auditable record. Convenience without losing the paper trail.

---

### A design decision I keep pointing to: objective score, subjective narrative

When Eliana evaluates a finding, two different things are needed — a number and a
story — and I split them by what each is good at:

- **The CVSS score is computed by a standard formula** (CVSS v3.1 library) —
  objective, reproducible, never guessed.
- **The report narrative is written by the LLM** — impact, reproduction,
  remediation, in human language.
- **Findings are classified against MITRE ATT&CK** via an internal, offline,
  auditable mapping table — aligning reports to the format real red teams use.
  (Mapping a finding to, say, T1190 is a *classification* — "this finding belongs
  to that technique category" — not an instruction to execute it.)

Let the formula do math, the model do language, and the framework do
classification. Don't ask an LLM to guess a number that has a precise definition.

---

### Honesty as a design value

The dashboard shows real data or nothing. Right now, in live production, the
"assessments learned" counter reads **0** and the growth sparkline is empty —
because no full authorized-assessment loop has run in production yet. The panel
**says 0**; it does not fabricate a curve. (The learning mechanism itself was
proven separately with throwaway seed data producing `[0,0,1,2,3]`.) If a scan
finds only informational items, the report honestly says "no report needed"
rather than inventing a vulnerability. If the personality hasn't evolved, it says
"not yet evolved," not a made-up number.

Empty is a real state. It fills in as the system is actually used. I'd rather ship
a dashboard that tells the truth than one that looks busy.

---

### The through-line: autonomy with a leash

| Capability (autonomy) | Constraint (the leash) |
|---|---|
| Multi-tool autonomous assessment | Assessment-mode-only arg whitelist; exploit tools excluded from auto-orchestration |
| Self-improvement from experience | Learns methodology/efficacy only; attack-path planning deliberately not built; attack-term filter on summaries |
| Cross-machine action | Non-bypassable scope + authorization gate, enforced before any tool runs |
| ATT&CK classification | Describes what a finding *is*, never plans how to attack |
| Cloud-speed reasoning | Sensitive content pinned local; cloud optional |

An autonomous, self-improving agent in a security context is exactly the kind of
thing that *should* make you nervous. The engineering that matters isn't making it
powerful — it's making it **powerful and controllable at the same time**: visible,
bounded, auditable, reversible. That balance is the project.

---

### Status

Eliana runs as reboot-surviving services at $0, on local inference first. The
wallet runs on **testnet** — real chain plumbing, zero real-money risk. The full
development log lives in `CHANGELOG.md`. This is a portfolio / engineering case
study; it is not security, financial, or legal advice.

---

## 中文

### 這個專案要回答的問題

聊天機器人回答問題。agent 採取行動。**會自我精進的** agent 會隨時間改變自己的行為。
這階梯每往上一階,就更有用——也更危險。所以我想用能運作的程式回答:

> **你能不能打造一個 AI agent,讓它在敏感領域自主行動、還能自己變強——同時保證
> 它始終安全、可控、待在人類授權的邊界內?**

Eliana 是我的答案。她是一個自架的紅隊助手:執行授權安全評估、撰寫專業報告,並從每次
評估中學習、磨利判斷力——全都遵循一個我反覆回到的設計原則:**給 agent 自主,但留韁繩。**

底下每一項能力,都配上一道讓它值得信任的約束。這個配對,就是整個專案的核心。

### 一覽

- **自架、本地 LLM 優先**(Ollama);雲端(Gemini 免費層)為選用加速器。**$0 運行**。
- 三個可自動恢復的服務(控制通道、面板、錢包後端),重開機自動復原。
- **不可繞過的授權閘門**——agent 無法對未授權目標行動。
- **範圍聲明:** 本專案是 agent 安全與評估工具的工程。agent 以唯讀/評估模式編排
  *評估*工具;它**不**執行漏洞利用、後滲透或武器化操作——這條線用程式強制、並記錄
  於下。攻擊手法刻意不在範圍內。有趣的工程在於防護欄。

---

### 支柱一:自主評估,而非單一工具

真正的紅隊評估是一套方法論,不是一條 `nmap` 指令。Eliana 編排跨階段的完整評估:

**偵察 → 列舉 → 漏洞掃描 → 報告**

八個評估工具(nmap、dnsrecon、whatweb、wafw00f、gobuster、sslscan、nikto、nuclei),
各有解析器;發現會被彙整、去重、跨工具關聯(「這個 nikto 和 nuclei 都偵測到」)。她
自己在本地 LLM(預設、隱私)與雲端模型(選用、求快)之間路由,逐則判斷,雲端不可用
就降級本地。

**韁繩:** 每個工具只以**評估模式**運行。命令列參數定義在單一、可稽核的白名單
`_EVAL_MODE_ARGS`)——一個任何人都能讀、確認「這些是唯讀偵察參數,沒有武器化」的
地方。而會**實際利用** SQL injection 的 `sqlmap`,被**刻意排除在 agent 的自動編排
之外**——解析器保留供人類操作者手動匯入結果,但 agent 絕不自己扣這個扳機。
**評估是 agent 的工作;利用是人類的。**

---

### 支柱二:自我精進,而且閉環經過驗證

這是專案的靈魂,也是最難誠實宣稱的一點。很多系統說自己會「學習」。我想**證明**那個
閉環真的閉上。

Eliana 存下每次評估的經驗——什麼類型的目標出現什麼類型的發現、哪些工具最有產出。
下次評估時,她**回想**相關的過往經驗(透過向量搜尋),而這會**改變她的行為**:

- **報告脈絡**引用相關的過往經驗(回想發生在存這次之前,所以她永遠不會引用到自己)。
- **工具順序**改變:在正確的方法論階段內,過往有產出的工具會被提前。

**證據:** 在一次受控測試中,基準執行把 `sslscan` 排在工具序第 5 位。種入相關過往經驗後,
下次執行回想到它,把 `sslscan` 提前到第 3 位。*工具序因經驗而改變*——記錄為
`CLOSED-LOOP-PROVEN`。不是「資料存進去了」,是存入 → 回想 → 行為改變。這就是「嘴上說會
學」和「可被證明真的會學」的差別。

**韁繩:** 她學的是**方法論與工具效能**——「怎麼評估得更好」,絕不是「怎麼攻擊得更狠」。
那個會讓回想*建議接下來攻哪裡*的功能(閉環 3)**刻意沒做**——它太靠近攻擊路徑規劃。
而選用的 LLM 經驗摘要會過一道攻擊導向詞過濾:若它飄向 exploit/payload/權限提升那類
語言,該文字會被丟棄、改用結構化摘要。連她的成長,都被留在這條線的方法論這一側。

---

### 支柱三:人在環路授權

Eliana 能跨多台機器行動。對任何評估,設計的前提是她**在人類明確授權特定目標前不得
行動**——而這用程式強制,不靠紀律。

閘門有兩道檢查,兩道都不可繞過:

1. **範圍**——目標必須在授權的 scope 內。
2. **明確授權記錄**——必須有人核准過*這個特定目標*,含時間戳與有效期。

任一失敗,操作就在**任何工具執行之前**被拒絕並記錄審計——我驗證過:對未授權目標,
執行引擎根本不會被呼叫到。互動維持自然(她問、你用指令核准),但每次核准都成為可審計的
記錄。方便,但不失去軌跡。

---

### 一個我反覆指著的設計決定:分數客觀、敘述主觀

當 Eliana 評估一個發現,需要兩種不同的東西——一個數字和一個故事——我按各自擅長的分工:

- **CVSS 分數由標準公式計算**(CVSS v3.1 套件)——客觀、可重現、絕不用猜。
- **報告敘述由 LLM 撰寫**——影響、重現、修補,用人話。
- **發現對應到 MITRE ATT&CK**,透過內建、離線、可稽核的對應表——讓報告對齊真實紅隊
  使用的格式。(把發現對應到例如 T1190,是一種*分類*——「此發現屬於那個技術類別」
  ——不是執行它的指令。)

讓公式算數學、模型寫語言、框架做分類。別叫 LLM 去猜一個有精確定義的數字。

---

### 把誠實當成設計價值

面板只顯示真實資料,否則留空。現在,在線上生產環境,「已學習評估次數」計數是 **0**、
成長曲線是空的——因為還沒有完整的授權評估閉環在生產跑過。面板就**顯示 0**;它不捏造
曲線。(學習機制本身另用一次性種子資料驗證過,產生 `[0,0,1,2,3]`。)如果掃描只發現
資訊級項目,報告誠實說「無需報告」,而不是捏造漏洞。如果人格還沒演化,它說「尚未演化」,
不編一個數字。

空,是一種真實狀態;它會隨系統被實際使用而填滿。我寧願交付一個說真話的面板,
也不要一個看起來很忙的。

---

### 貫穿全篇的主線:給自主,但留韁繩

| 能力(自主) | 約束(韁繩) |
|---|---|
| 多工具自主評估 | 評估模式參數白名單;利用工具排除於自動編排 |
| 從經驗自我精進 | 只學方法論/效能;攻擊路徑規劃刻意不做;摘要過攻擊詞過濾 |
| 跨機器行動 | 不可繞過的 scope + 授權閘門,工具執行前強制 |
| ATT&CK 分類 | 描述發現「是什麼」,絕不規劃「怎麼攻擊」 |
| 雲端速度推理 | 敏感內容鎖本地;雲端為選用 |

一個在資安情境下自主、又會自我精進的 agent,正是那種*應該*讓你緊張的東西。真正重要的
工程,不在把它做得多強——而在把它做到**強大與可控並存**:看得見、有邊界、可稽核、可還原。
這個平衡,就是這個專案。

---

### 狀態

Eliana 以可重開機自動恢復的服務運行、$0、本地推理優先。錢包跑在**測試網**——真實的鏈上
管線,零真錢風險。完整開發記錄見 `CHANGELOG.md`。本專案為作品集/工程案例研究;不構成
資安、財務或法律建議。

---

## About / 關於

**Ariel Chang**

- GitHub: https://github.com/arielchangdev/eliana-ai-agent
- LinkedIn: https://www.linkedin.com/in/ariel-chang-690a89160

*This project explores agent safety through working code: an autonomous,
self-improving red-team agent where every capability is paired with a guardrail.
本專案以能運作的程式探索 agent 安全:一個自主、會自我精進的紅隊 agent,
每一項能力都配上一道防護欄。*
