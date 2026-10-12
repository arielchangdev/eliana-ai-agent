---
title: "The Hard Part Wasn't the AI — 6 Wiring Bugs from Building a Self-Improving Agent"
published: false
description: "I built an autonomous agent that learns from its own work. The capabilities were mostly already written — the real time went into wiring them to reality, to each other, and to the user. Six bugs about where agent projects actually break."
tags: ai, python, agents, devops
canonical_url: https://github.com/arielchangdev/eliana-ai-agent/blob/main/BLOG_WIRING.md
---

I spent a few months building **Eliana** — a self-hosted, self-improving agent
that runs authorized security assessments and learns from each one. Looking back
at where the time actually went is almost comical: the "AI" parts — LLM reasoning,
personality, the learning loop — were mostly already designed and written. What
ate the weeks was **wiring**: connecting capabilities to the real environment, to
each other, and to the one place a human actually types a command.

Here are six bugs that taught me where agent projects really break. Not one is
about the model. All of them are about plumbing.

> *Scope note: this agent orchestrates evaluation tooling in assessment mode only,
> against authorized targets. This post is about wiring and infrastructure
> engineering — there are no offensive techniques here.*

## Bug 1 — The scanner that scanned, then forgot everything

The agent ran a scan. It found something. It reported success. And the results
table was **empty**.

The capability was all there — the engine had full `INSERT INTO scans` logic. But
it was constructed with no database handle, and every persistence call was wrapped
in `if self._db is not None`. So the agent scanned, parsed, found a result — and
silently dropped it on the floor. It had no memory of its own work.

**Lesson:** a capability that exists in code but isn't wired to its dependency is
worse than a missing feature — because it *looks* like it works. The scan
"succeeded." Only the empty table told the truth.

## Bug 2 — "Found: 0" that was actually a lie

Right after fixing Bug 1, a scan reported **0 findings**. I almost believed it —
until I realized the SSH channel to the tooling host was never connected before
the scan ran. The tool failed instantly, the error was swallowed, and "0 findings"
was reported as if it were a clean result.

A silent failure that masquerades as a *successful empty result* is the most
dangerous kind of bug in an agent — because the agent will confidently tell the
user "nothing found," and the user has no reason to doubt it.

**Lesson:** for an autonomous agent, "no result" and "failed to get a result"
must never look the same. Make failure loud.

## Bug 3 — The score the database refused

CVSS scores are computed by a standard formula library — objective, not guessed.
Except the library returns a `decimal.Decimal`, and SQLite refuses to bind a
`Decimal`. The whole report-persistence path blew up on the score field.

A one-line `float()` fix. But it's a perfect example of the seams you only find at
the boundary between two libraries that were each individually correct.

**Lesson:** bugs don't live inside components. They live in the *type mismatches
between them*.

## Bug 4 — The agent that "learned" but never actually learned

My favorite, because it's the whole project in miniature. The learning loop was
designed: store assessment experience, recall it next time. Storage worked. The
recall function existed. I could have written "the agent learns from experience"
and technically not been lying.

But *did the recall actually change anything?* That's the difference between a
system that claims to learn and one that does. So I made it provable: a baseline
run put `sslscan` 5th in the tool order; after seeding relevant past experience,
the next run recalled it and moved `sslscan` to **3rd**. Stored → recalled →
behavior changed. I logged it as `CLOSED-LOOP-PROVEN` and refused to call the
feature done until that line appeared.

**Lesson:** "it learns" is a claim, not a feature. If you can't point to the
moment behavior changed *because of* what was learned, the loop isn't closed —
it's a write followed by an unused read.

## Bug 5 — `%h` that became `/root`

I made the services survive reboots with systemd. The unit used `%h` to find the
user's home directory for the executable path. On start it failed:
`can't open file '/root/.local/bin/...'`. In this system-service context, `%h`
resolved to root's home, not the service user's — pointing at a binary that
wasn't there.

**Lesson:** "it works when I run it by hand" and "it works as a managed service"
are two different claims, with two different environments.

## Bug 6 — When de-identification bit back

To keep the public repo clean, every real path and credential is replaced with a
placeholder and loaded from the environment at runtime. Correct and necessary. But
one service's env file was missing a couple of keys — so at runtime it fell back
to the *placeholder* values, and the agent dutifully created an empty database
file named after the placeholder. Lookups started failing against a database that
was real but empty.

**Lesson:** de-identification is a feature with its own failure modes. "Secrets
via env" needs the env to actually be complete — and a missing key should fail
loudly, not fall back silently to a placeholder.

---

## The pattern

Step back and the shape is obvious. Not one bug was in the model, the prompt, or
the "intelligence." Every single one lived in the connective tissue:

- **capability → dependency** (scanner → db, Bug 1)
- **capability → resource** (scanner → SSH, Bug 2)
- **library → library** (Decimal → SQLite, Bug 3)
- **store → recall** (the learning loop, Bug 4)
- **code → runtime** (systemd `%h`, Bug 5)
- **secret → environment** (de-id fallback, Bug 6)

Building an agent in 2025 is deceptive. The frameworks make the glamorous parts —
reasoning, memory, tool use — look like the work. They aren't. The LLM call was
never the hard part. The hard part was making a dozen capabilities actually
*connect* — to their data, their tools, each other, the runtime, and the one place
a human types a command.

That connective tissue is where agents are honest or dishonest, reliable or
flaky, controllable or not. It's where "it works on my machine" quietly becomes
"it reports success and does nothing." And it's the part no demo ever shows you.
Boring is where agents live or die.

---

*Eliana is a self-hosted, $0, local-inference-first self-improving agent, built so
every capability is paired with a guardrail that keeps it controllable. Full
architecture and design decisions in the [case study](https://github.com/arielchangdev/eliana-ai-agent).*

*By* *Ariel Chang** — [GitHub](https://github.com/arielchangdev/eliana-ai-agent) · [LinkedIn](https://www.linkedin.com/in/ariel-chang-690a89160)*
