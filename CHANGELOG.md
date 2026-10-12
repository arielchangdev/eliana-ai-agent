# Changelog

Technical record of the "growth-oriented red-team agent" capability build.
Audience: developers / technical reviewers.

Compliance line held across all four stages: Eliana learns **assessment
methodology and tool efficacy**, classifies findings with **MITRE ATT&CK as
labels** (describing *what a finding is*, not *how to attack*), and only
processes the existing results of **authorized** scans. No exploit execution,
no payload/weaponization logic. Everything runs **locally at $0** (Ollama for
embeddings/LLM, on-disk Chroma, local sqlite). All host/credential values are
de-identified in the repo via `YOUR_*` placeholders and read from env at runtime.

---

## Growth capability build — overview

Four stages turned a single-tool scanner into an agent that assesses with
multiple tools in a methodology order, classifies findings, learns from each
authorized assessment, and surfaces that growth honestly.

| Stage | Theme | Key commit |
| ----- | ----- | ---------- |
| 1  | Multi-tool assessment orchestration (eval-mode only) | `1c2bf6e`, telegram wiring `1069c3c` |
| 2  | MITRE ATT&CK classification of findings | `3c37424` |
| 3  | Assessment-experience learning loop (store → recall → influence) | `8e8e77b` |
| 4  | Make growth visible in reports and the dashboard | `e4f532e` |

---

## Stage 1 — Multi-tool assessment orchestration (`1c2bf6e`, `1069c3c`)

**What it does.** Replaces single-tool scanning with a methodology-ordered,
multi-tool assessment. Tools run in `recon → enumeration → vuln_scanning`
order; each tool's arguments come from an auditable eval-mode allowlist.

**Key implementation.**
- `app/bounty/scanner.py`
  - `_AUTO_ORCHESTRATION_TOOLS`: single-source allowlist of tools the agent may
    auto-orchestrate. **sqlmap is deliberately excluded** from auto-orchestration
    (its result parser is kept for manual human import only).
  - `_EVAL_MODE_ARGS`: per-tool argument allowlist (assessment mode, auditable
    at a glance via inline comments) — e.g. non-intrusive flags only.
  - `_METHODOLOGY_PHASES`: ordered phase → tool mapping.
  - `build_phased_profile(...)`: builds a `ScanProfile` by filtering requested
    tools against the allowlist, then ordering them by methodology phase.
- Five result parsers added (whatweb / wafw00f / dnsrecon / sslscan / gobuster)
  normalizing tool output into findings.
- `deduplicate_findings(...)`: merges overlapping findings across tools.
- Kali toolbox availability confirmed: whatweb, wafw00f, dnsrecon, sslscan,
  gobuster.

**Telegram integration (`1069c3c`).** `/authorize` builds a phased profile and
runs the assessment in the background with progress updates. Fixed an env bug
where the telegram service lacked `ELIANA_BOUNTY__DB` / weapon host vars.

**Verified.** Real assessment ran end-to-end from Telegram (nmap + sslscan),
findings normalized and persisted.

---

## Stage 2 — MITRE ATT&CK classification (`3c37424`)

**What it does.** Tags each finding with an ATT&CK technique as a
**classification label** — describing what the finding is, not an attack plan.

**Key implementation.**
- `app/bounty/attack_mapping.py`
  - `_ATTACK_RULES`: single-source allowlist mapping (tool_source + keyword) →
    ATT&CK technique id/name/tactic, auditable via inline comments.
- `app/bounty/models.py`: `Vulnerability` gains `attack_technique_id`,
  `attack_technique_name`, `attack_tactic`.
- DB migration adds the three columns; `scanner.py` fills them during
  normalization; `Report` carries them through.
- `reporter.py` + dashboard: findings show an ATT&CK badge.

**Verified.** Classification correctness checked 13/13 against expected
mappings; a real scan wrote `T1592`-class labels to the db.

---

## Stage 3 — Assessment-experience learning loop (`8e8e77b`)

**What it does.** Closes the loop: each authorized assessment's experience is
**stored**, **recalled** on the next assessment, and **influences** behavior.
Decision set implemented: store = A+B+C, recall = loops 1+2+3.

**Key implementation.**
- `app/bounty/assessment_memory.py` (new)
  - Isolated Chroma collection `eliana_assessment_memory` (kept separate from
    conversation memory / knowledge base — clean semantics, independent panel
    count).
  - Embeddings via **Ollama `nomic-embed-text`** (chosen because
    `sentence_transformers` is not installed on the VM; mirrors the working
    `conversation_memory` approach).
  - **A** `_build_structured_experience`: objective finding patterns (target
    type, tools used, severity distribution, ATT&CK labels).
  - **B** `recommend_priority_tools`: per-target-type tool-efficacy stats
    (similarity × (1 + findings_count)) for orchestration ordering.
  - **C** `_llm_experience_summary`: local-LLM methodology summary with an
    **attack-oriented guard** (`_ATTACK_ORIENTED_TERMS`) — any
    exploit/payload/privilege-escalation/etc. wording causes the LLM text to be
    discarded and falls back to the structured summary.
- `app/bounty/authorized_scan.py`
  - Optional `assessment_memory` injection (None = off, no behavior change).
  - **Loop 1**: recalls similar past experience into the report, happening
    **before** this scan's experience is stored → cites genuine past, never
    itself.
  - `_record_experience`: stores experience after a scan completes.
- `app/bounty/scanner.py`
  - **Loop 2**: `build_phased_profile(prioritize_tools=...)` reorders tools
    **within a methodology phase only** — never moving a tool out of its phase,
    preserving recon→enum→vuln correctness.
  - **Loop 3**: `recall_focus_hints` surfaces past finding-type observations as
    assessment reminders (hints only — "prompt what to assess", not "plan an
    attack").
- Telegram `/authorize` derives prioritized tools from recalled experience
  (loop 2 in production).

**Verified — CLOSED-LOOP-PROVEN.** This is the key proof that growth is real,
not just stored: with no prior experience, `sslscan` sits at **position 5** in
the tool order; after relevant experience is recalled, it moves to
**position 3** — i.e. the second assessment genuinely recalled the first and
**changed behavior** (`tool order changed = True`), and recall surfaced the
prior experience. Store/recall/guard all validated (count 0→1, recall returns
prior docs, C guard blocks attack-oriented text and passes clean text).

---

## Stage 4 — Make growth visible (`e4f532e`)

**What it does.** Surfaces the growth loop so it is observable in reports and
on the dashboard — honestly (empty when nothing has accumulated).

**Key implementation.**
- `app/bounty/authorized_scan.py`: report now states **"this report cited N
  recalled past experiences"**, making it visible the report drew on prior
  experience rather than being written from scratch.
- `app/bounty/assessment_memory.py`: `growth_series(days)` returns a daily
  **cumulative experience-count** time series (pure counts; no finding/attack
  content); empty list when no experience exists.
- `eliana-dashboard/real_adapter.py`: dashboard snapshot carries the trend in
  `strategy_summary` (honest empty when none).
- `eliana-dashboard/frontend/src/components/KnowledgeStats.vue`: renders a
  compact SVG sparkline of the cumulative trend, shown **only** when there is
  actual accumulation.

**Verified.**
- LIVE (production, honest): assessment count `0`, trend `[]` — no real
  assessment has run the full loop in production, so the panel does not fake a
  curve.
- PROVE (seeded throwaway collection, mechanism correct): 3 experiences across
  3 days → cumulative `[0, 0, 1, 2, 3]`, monotonically non-decreasing, ending
  at total 3. Sparkline renders once real experience accumulates.
- Frontend type-check (`vue-tsc`) and build pass; served bundle contains the
  trend markup.

---

## Runtime / deployment notes

- Services run under systemd as user `eliana` on the agent VM:
  `eliana-dashboard` (serves the built frontend + FastAPI snapshot API),
  `eliana-telegram`, `eliana-electrum` (testnet-locked).
- Config via env files; de-identified placeholders in the repo must be set to
  real values on the host (`ELIANA_BOUNTY__DB`, `ELIANA_WEAPON__*`,
  `ELIANA_MEMORY__DIR`, dashboard `ELIANA_DASH__*`).
- Assessment memory persists under the memory dir in the
  `eliana_assessment_memory` Chroma collection, separate from
  `eliana_conversations`.
