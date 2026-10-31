"""agent_core — reusable agentic core (planning loop, ports, guardrail gate, models).

Agent-agnostic by design: no Eliana-specific tool names or constants live here.
Eliana-specific wiring lives under `agent_core/eliana/`. A future finance agent
(Angelina) can reuse the same loop and gate with a different tool set / policy.

This package currently implements the data models (`models`), the core ports
(`ports`), and the `GuardrailGate` (`guardrail`). See the eliana-agent-core spec.
"""
