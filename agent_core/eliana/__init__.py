"""agent_core.eliana — Eliana-specific wiring of the agent-agnostic core.

This subpackage holds the pieces that know about Eliana's actual tools and
capabilities (MCP server, local planner, memory adapter). The reusable core in
the parent package (`models`, `ports`, `guardrail`, and later `planning_loop`)
stays agent-agnostic so a future finance agent can reuse it with a different
tool set and guardrail policy.
"""
