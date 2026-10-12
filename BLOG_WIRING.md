---
title: "The Hard Part Wasn't the AI — Six Wiring Bugs from Building a Self-Improving Agent"
published: false
description: "I built an autonomous red-team agent that learns from its own work. The capabilities were mostly already written. The real time went into the unglamorous part: wiring them to reality, to each other, and to the user. Six bugs that taught me where agent projects actually break."
tags: ai, python, agents, devops
---

# The Hard Part Wasn't the AI
# 難的從來不是 AI 那部分

> A war-stories post from building **Eliana**, a self-hosted, self-improving
> red-team AI agent. The headline features — autonomy, memory, learning — were the
> *easy* part to write. The time went somewhere else entirely: into wiring.
>
> 來自打造 **Eliana**(一個自架、會自我精進的紅隊 AI agent)的踩坑筆記。那些上得了
> 標題的功能——自主、記憶、學習——反而是*好寫*的部分。時間全花在別的地方:接線。

---

## English

I spent a few months building an autonomous agent that runs authorized security
assessments and learns from each one. When I look back at where the time actually
went, it's almost comical: the "AI" parts — the LLM reasoning, the personality,
the learning loop — were mostly already designed and written. What ate the weeks
was **wiring**: connecting capabilities to the real environment, to each other,
and to the place the user actually touches.

Here are six bugs that taught me where agent projects really break. None of them
are about the model. All of them are about plumbing.

> *(Scope note: this agent orchestrates evaluation tooling in assessment mode
> only, against authorized targets. This post is about the engineering of wiring
> and infrastructure — there are no offensive techniques here.)*

### Bug 1 — The scanner that scanned, then forgot everything

The agent ran a scan. It found something. It reported success. And the results
table was **empty**.

The capability was all there — the scan engine had full `INSERT INTO scans` logic.
But the engine was constructed as `ScanEngine(ssh_channel)` with no database
handle, and every persistence call was wrapped in `if self._db is not None`. So
the agent scanned, parsed, found a result — and silently dropped it on the floor.
It had no memory of its own work.

**The lesson:** a capability that exists in the code but isn't wired to its
dependency is worse than a missing feature — because it *looks* like it works. The
scan "succeeded." Only the empty table told the truth.

### Bug 2 — "Found: 0" that was actually a lie

Right after fixing Bug 1, a scan reported **0 findings**. I almost believed it —
until I realized the SSH channel to the tooling host was never connected before
the scan ran. The tool failed instantly, the error was swallowed, and "0 findings"
was reported as if it were a clean result.

A silent failure that masquerades as a *successful empty result* is the most
dangerous kind of bug in an agent — because the agent will confidently tell the
user "nothing found," and the user has no reason to doubt it.

**The lesson:** for an autonomous agent, "no result" and "failed to get a result"
must never look the same. Fix the connection, and make failure loud.

### Bug 3 — The score the database refused

CVSS scores are computed by a standard formula library — objective, not guessed.
Great. Except the library returns a `decimal.Decimal`, and SQLite refuses to bind
a `Decimal` parameter. The whole report-persistence path blew up on the score
field.

A one-line `float()` fix. But it's a perfect example of the seams you only find at
the boundary between two libraries that were each individually correct.

**The lesson:** the bugs don't live inside components. They live in the
*type mismatches between them*.

### Bug 4 — The agent that "learned" but never actually learned

This one is my favorite because it's the whole project in miniature. The learning
loop was designed: store assessment experience, recall it next time. The storage
worked. The recall function existed. I could have written "the agent learns from
experience" and technically not been lying.

But *did the recall actually change anything?* That's the difference between a
system that claims to learn and one that does. So I made it provable: a baseline
run put `sslscan` 5th in the tool order; after seeding relevant past experience,
the next run recalled it and moved `sslscan` to **3rd**. Stored → recalled →
behavior changed. I logged it as `CLOSED-LOOP-PROVEN` and refused to call the
feature done until that line appeared.

**The lesson:** "it learns" is a claim, not a feature. If you can't point to the
moment behavior changed *because of* what was learned, the loop isn't closed —
it's just a write followed by an unused read.

### Bug 5 — `%h` that became `/root`

I made the services survive reboots with systemd. The unit used `%h` to find the
user's home directory for the executable path. On start, it failed:
`can't open file '/root/.local/bin/...'`. In this system-service context, `%h`
resolved to root's home, not the service user's — so the path pointed at a binary
that wasn't there.

Absolute path on the box, `%h` convention in the public repo. Done. But it's a
reminder that "it works when I run it by hand" and "it works as a managed service"
are two different claims with two different environments.

### Bug 6 — When de-identification bit back

To keep the public repo clean, every real path and credential is replaced with a
placeholder and loaded from the environment at runtime. Correct and necessary. But
one service's env file was missing a couple of keys — so at runtime it fell back
to the *placeholder* values `YOUR_BOUNTY_DB`), and the agent dutifully created an
empty database file named after the placeholder. Authorization lookups started
failing against a database that was real but empty.

**The lesson:** de-identification is a feature with its own failure modes. The
fix confirmed the design was right — real values belong in the environment, the
repo holds only placeholders — but it taught me that "secrets via env" needs the
env to actually be complete, and a missing key should fail loudly, not fall back
silently to a placeholder.

---

## The pattern

Step back from the six and the shape is obvious. Not one was in the model, the
prompt, or the "intelligence." Every single one lived in the connective tissue:

- **capability-to-dependency** (scanner → db, Bug 1)
- **capability-to-resource** (scanner → SSH, Bug 2)
- **library-to-library** (Decimal → SQLite, Bug 3)
- **store-to-recall** (the learning loop, Bug 4)
- **code-to-runtime** (systemd `%h`, Bug 5)
- **secret-to-environment** (de-id fallback, Bug 6)

Building an agent in 2025 is deceptive. The frameworks make the glamorous parts —
reasoning, memory, tool use — look like the work. They aren't. The LLM call was
never the hard part. The hard part was making a dozen capabilities actually
*connect* — to their data, to their tools, to each other, to the runtime, and to
the one place a human actually types a command.

That connective tissue is where agents are honest or dishonest, reliable or
flaky, controllable or not. It's where "it works on my machine" quietly becomes
"it reports success and does nothing." And it's the part no demo ever shows you.
Boring is where agents live or die.

---

## 中文

我花了幾個月打造一個會執行授權安全評估、並從每次評估中學習的自主 agent。回頭看時間
到底花在哪,其實有點好笑:那些「AI」的部分——LLM 推理、人格、學習閉環——大多早就設計
好、寫好了。吃掉幾週時間的,是**接線**:把能力接到真實環境、接到彼此、接到使用者真正
碰得到的地方。

以下六個 bug 教會我 agent 專案真正會壞在哪。沒有一個是關於模型的。全部都是關於管線。

> *(範圍聲明:這個 agent 只以評估模式編排評估工具、對授權目標。本文談的是接線與基礎
> 設施的工程——這裡沒有任何攻擊手法。)*

### Bug 1 — 掃了、然後全忘光的掃描器

agent 跑了掃描。發現了東西。回報成功。然後結果表是**空的**。

能力全都在——掃描引擎有完整的 `INSERT INTO scans` 邏輯。但引擎被建成
`ScanEngine(ssh_channel)`,沒帶資料庫 handle,而每個持久化呼叫都包在
`if self._db is not None` 裡。所以 agent 掃了、解析了、找到結果——然後默默把它丟在地上。
它對自己做過的事毫無記憶。

**教訓:** 一個「程式裡存在、卻沒接上依賴」的能力,比缺功能更糟——因為它*看起來*會動。
掃描「成功」了。只有那張空表說了實話。

### Bug 2 — 其實是謊言的「發現:0」

修好 Bug 1 後,一次掃描回報 **0 筆發現**。我差點信了——直到我發現到工具主機的 SSH 通道
在掃描前根本沒連上。工具瞬間失敗、錯誤被吞掉,「0 筆發現」就被當成乾淨結果回報了。

一個**偽裝成「成功的空結果」的靜默失敗**,是 agent 裡最危險的 bug——因為 agent 會自信地
告訴使用者「什麼都沒找到」,而使用者沒有理由懷疑。

**教訓:** 對自主 agent 而言,「沒有結果」和「拿結果失敗」絕不能長得一樣。把連線修好,
並讓失敗大聲。

### Bug 3 — 資料庫拒收的分數

CVSS 分數由標準公式套件計算——客觀、不用猜。很好。只是那個套件回傳 `decimal.Decimal`,
而 SQLite 拒絕綁定 `Decimal` 參數。整條報告持久化路徑在分數欄位爆掉。

一行 `float()` 就修好。但它完美示範了那種只在「兩個各自正確的套件的交界處」才會出現的
接縫。

**教訓:** bug 不住在元件*裡*。它們住在元件*之間的型別不匹配*。

### Bug 4 — 「學會了」卻從沒真的學會的 agent

這個是我最愛,因為它是整個專案的縮影。學習閉環設計好了:存評估經驗、下次回想。存入會動。
回想函式存在。我大可以寫「agent 會從經驗學習」,技術上不算說謊。

但*回想真的改變了什麼嗎?* 這就是「宣稱會學」和「真的會學」的差別。所以我讓它可被證明:
基準執行把 `sslscan` 排在工具序第 5 位;種入相關過往經驗後,下次執行回想到它,把
`sslscan` 提前到**第 3 位**。存入 → 回想 → 行為改變。我記錄為 `CLOSED-LOOP-PROVEN`,
並拒絕在那行出現之前把這功能算完成。

**教訓:**「它會學」是一個宣稱,不是一個功能。如果你指不出「行為*因為*學到的東西而改變」
的那一刻,閉環就沒閉上——它只是一次寫入,後面跟著一次沒人用的讀取。

### Bug 5 — 變成 `/root` 的 `%h`

我用 systemd 讓服務能重開機自動恢復。unit 用 `%h` 去找使用者家目錄的執行檔路徑。啟動時
失敗`can't open file '/root/.local/bin/...'`。在這個 system service 情境下`%h` 解析成
root 的家,不是服務使用者的——所以路徑指向一個不存在的執行檔。

機器上用絕對路徑、公開 repo 用 `%h` 慣例。搞定。但它提醒我:「我手動跑它會動」和
「它作為受管服務會動」是兩個不同的宣稱,有兩個不同的環境。

### Bug 6 — 當去識別化反咬一口

為了讓公開 repo 乾淨,每個真實路徑和憑證都換成佔位符、執行時從環境載入。正確且必要。
但某個服務的 env 檔少了幾個鍵——於是執行時它 fallback 到*佔位符*的值`YOUR_BOUNTY_DB`),
而 agent 盡責地建了一個以佔位符命名的空資料庫檔。授權查詢開始對著一個真實但空的資料庫失敗。

**教訓:** 去識別化是一個有自己失敗模式的功能。這個修正證明了設計是對的——真實值該在環境、
repo 只放佔位符——但它教會我「機密走 env」需要 env 真的完整,而缺鍵應該大聲失敗,
不是默默 fallback 到佔位符。

---

## 模式

退一步看這六個,形狀很明顯。沒有一個在模型、prompt 或「智慧」裡。每一個都住在連接組織裡:

- **能力接依賴**(掃描器 → db,Bug 1)
- **能力接資源**(掃描器 → SSH,Bug 2)
- **套件接套件**(Decimal → SQLite,Bug 3)
- **存入接回想**(學習閉環,Bug 4)
- **程式接執行環境**(systemd `%h`,Bug 5)
- **機密接環境**(去識別化 fallback,Bug 6)

2025 年打造 agent 是會騙人的。框架把那些上得了檯面的部分——推理、記憶、工具使用——弄得
*看起來*像是工作。它們不是。LLM 呼叫從來不是難的部分。難的是讓十幾個能力真的*連接
起來*——接到它們的資料、它們的工具、彼此、執行環境,以及人類真正敲指令的那一個地方。

那層連接組織,正是 agent 誠實或不誠實、可靠或易壞、可控或失控的所在。它是「在我機器上
會動」悄悄變成「它回報成功卻什麼都沒做」的地方。也是任何 demo 永遠不會給你看的部分。
無聊的地方,才是 agent 的生死之處。

---

*Eliana 是一個自架、$0、本地推理優先的自我精進紅隊 agent。完整架構與設計決策見
[case study](https://github.com/arielchangdev/eliana-ai-agent)。*

*Eliana is a self-hosted, $0, local-inference-first self-improving red-team agent.
Full architecture and design decisions in the case study.*

**Ariel Chang** · [GitHub](https://github.com/arielchangdev/eliana-ai-agent) · [LinkedIn](https://www.linkedin.com/in/ariel-chang-690a89160)
