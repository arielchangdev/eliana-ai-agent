"""Real Telegram adapter: bridges the agent to a human via Telegram.

Wires onto:
- TelegramBotHandler (dashboard) for command parsing / whitelist / status format
- PersonalityAdapter (integration) for persona-flavored chat replies
- ResourceMonitor (core) for real /status metrics

Uses python-telegram-bot (polling). Token/chat_id/whitelist come from env.
No secrets are hardcoded. Safe to run alongside the integration app or standalone.
"""
from __future__ import annotations

import os as _os, sys as _sys
_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))
_sys.path[:] = [p for p in _sys.path if _os.path.abspath(p or '.') != _SCRIPT_DIR]
_ENGINE_ROOT = _os.environ.get('ELIANA_ROOT') or '/opt/eliana'
if _ENGINE_ROOT not in _sys.path:
    _sys.path.insert(0, _ENGINE_ROOT)

import asyncio
import logging
import os
from typing import Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eliana.telegram")


def _load_cfg() -> dict:
    token = os.environ.get("ELIANA_TELEGRAM__BOT_TOKEN", "").strip()
    chat_id = os.environ.get("ELIANA_TELEGRAM__CHAT_ID", "").strip()
    wl = os.environ.get("ELIANA_TELEGRAM__WHITELIST", "").strip()
    whitelist = [int(x) for x in wl.replace(",", " ").split() if x.strip().isdigit()]
    return {"token": token, "chat_id": chat_id, "whitelist": whitelist}


class TelegramRuntime:
    """Owns the PTB Application and connects it to agent subsystems."""

    def __init__(
        self,
        *,
        personality: Any | None = None,
        resource_monitor: Any | None = None,
        scanner: Any | None = None,
        knowledge_store: Any | None = None,
        agent: Any | None = None,
    ) -> None:
        self._cfg = _load_cfg()
        self._personality = personality
        self._rm = resource_monitor
        self._scanner = scanner
        self._knowledge = knowledge_store
        # agent config: {"loop": PlanningLoop} (or None). Only used when the
        # ELIANA_AGENT__LOOP_ENABLED flag is on; default-off keeps legacy path.
        self._agent = agent
        self._pending_scan = {}   # chat_id -> target awaiting /authorize
        self._running_assessments = {}  # chat_id -> asyncio.Task of in-flight scan
        self._app = None

    def _authorized(self, user_id: int) -> bool:
        wl = self._cfg["whitelist"]
        return (not wl) or (user_id in wl)

    async def _reply_unauthorized(self, update) -> None:
        await update.message.reply_text("Unauthorized. Your id is not on the allowlist.")

    async def cmd_start(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        await update.message.reply_text(
            "Eliana is online. Commands: /status  /chat <message>  /help")

    async def cmd_help(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        await update.message.reply_text(
            "/status - live system state\n"
            "/local /cloud /auto - 切換 LLM 路由模式\n"
            "/persona /undo /evolve - 人格演化查看與控制\n"
            "/scan /authorize /cancel - 授權評估流程\n"
            "/stop - 中止進行中的評估掃描\n"
            "/learn <內容> - 教 Eliana 一條知識（收進知識庫，不聊天）\n"
            "/reset - 開新話題（清短期脈絡；長期記憶保留）\n"
            "/chat <message> - talk to Eliana (local LLM + persona)\n"
            "/help - this message")

    async def cmd_local(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is not None:
            self._personality.force_mode = "local"
        await update.message.reply_text("已切換：強制使用本地模型（local）。")

    async def cmd_cloud(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is not None:
            self._personality.force_mode = "cloud"
        await update.message.reply_text("已切換：強制使用雲端模型（Gemini）。")

    async def cmd_auto(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is not None:
            self._personality.force_mode = None
        await update.message.reply_text("已切換：自動路由（敏感內容走本地，其餘走雲端）。")

    async def cmd_scan(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._scanner is None:
            return await update.message.reply_text("掃描子系統未啟用。")
        target = (context.args[0].strip() if context.args else "")
        if not target:
            return await update.message.reply_text("用法：/scan <目標網域或網址>")
        self._pending_scan[str(update.effective_chat.id)] = target
        msg = (
            "\u26a0\ufe0f 掃描授權確認\n"
            f"目標：{target}\n\n"
            "掃描前請確認：\n"
            "1. 這是你擁有、或在合法 bug bounty 專案中有明確授權測試的目標嗎？\n"
            "2. 這在該專案的 scope 範圍內嗎？\n\n"
            f"確認請回覆：/authorize {target}\n"
            "取消請回覆：/cancel"
        )
        await update.message.reply_text(msg)

    async def cmd_authorize(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._scanner is None:
            return await update.message.reply_text("掃描子系統未啟用。")
        target = (context.args[0].strip() if context.args else "")
        pending = self._pending_scan.get(str(update.effective_chat.id))
        if not target or target != pending:
            return await update.message.reply_text(
                "請先用 /scan <目標> 發起，再用 /authorize <同一個目標> 確認。")
        # ---- SHARED (both paths, unchanged): record explicit human
        # authorization, then derive scope. The planner NEVER creates or
        # modifies authorization — this record is what GuardrailGate reads. ----
        try:
            self._scanner.grant_authorization(target, validity_hours=24)
        except Exception as exc:
            return await update.message.reply_text(f"授權記錄失敗：{exc}")
        from app.bounty.models import ProgramScope
        host = target.split("://")[-1].split("/")[0]
        scope = ProgramScope(domains=[host])
        self._pending_scan.pop(str(update.effective_chat.id), None)
        chat_id = update.effective_chat.id

        # ---- FORK (only here): agent loop vs legacy build_phased_profile. ----
        # feature flag ELIANA_AGENT__LOOP_ENABLED (default OFF) selects the path.
        # When ON, the agent path internally falls back to the legacy GATED path
        # on PlannerUnavailable (fail-closed to a gated path, never raw exec).
        if self._agent_loop_enabled() and self._agent is not None:
            await self._start_agent_assessment(update, chat_id, target, scope)
        else:
            await self._start_legacy_assessment(update, chat_id, target, scope)

    # -- feature flag ---------------------------------------------------- #
    @staticmethod
    def _agent_loop_enabled() -> bool:
        """ELIANA_AGENT__LOOP_ENABLED: default OFF. Any of 1/true/yes/on enables
        the agent planning loop; anything else (incl. unset) keeps the legacy
        build_phased_profile path so production behavior is unchanged by default."""
        return os.environ.get("ELIANA_AGENT__LOOP_ENABLED", "").strip().lower() \
            in ("1", "true", "yes", "on")

    # -- legacy path (unchanged behavior; also the fallback) ------------- #
    async def _start_legacy_assessment(self, update, chat_id, target, scope) -> None:
        """The pre-agent path: build_phased_profile -> scanner.scan. This is the
        default when the flag is off, and the fail-closed fallback when the
        planner is unavailable. It is itself gated (eval-mode allowlist +
        authorization), never raw tool execution."""
        from app.bounty.scanner import build_phased_profile
        from app.bounty.enums import ScanTool
        host = target.split("://")[-1].split("/")[0]
        # 成長閉環-2：回想過往評估經驗，推導「對這類目標較有產出的評估工具」。
        prio_tools = []
        mem = getattr(self._scanner, "_assessment_memory", None)
        if mem is not None:
            try:
                names = mem.recommend_priority_tools("web_app",
                        query=f"assessment of {host}")
                name2tool = {t.value: t for t in ScanTool}
                prio_tools = [name2tool[n] for n in names if n in name2tool]
            except Exception:
                prio_tools = []
        profile = build_phased_profile(prioritize_tools=prio_tools)
        tool_names = ", ".join(t.value for t in profile.tools)
        await update.message.reply_text(
            f"已授權 {target}，開始多工具評估（評估模式）。\n"
            f"編排工具：{tool_names}\n"
            f"方法論階段：偵察 → 列舉 → 漏洞掃描\n"
            f"這會花幾分鐘，完成後我會回報結果，請稍候…")
        task = asyncio.create_task(
            self._run_assessment(chat_id, target, scope, profile))
        self._running_assessments[str(chat_id)] = task

    # -- agent path (new; falls back to legacy on PlannerUnavailable) ---- #
    async def _start_agent_assessment(self, update, chat_id, target, scope) -> None:
        """New path: construct an AssessmentGoal and run PlanningLoop. On
        PlannerUnavailable, fall back to the legacy GATED path (fail-closed)."""
        await update.message.reply_text(
            f"已授權 {target}，開始 agent 規劃評估（評估模式，實驗性）。\n"
            f"規劃核心：本地模型；每步經授權閘門把關。\n"
            f"這會花幾分鐘，完成後我會回報結果，請稍候…")
        task = asyncio.create_task(
            self._run_agent_assessment(update, chat_id, target, scope))
        self._running_assessments[str(chat_id)] = task

    async def _run_agent_assessment(self, update, chat_id, target, scope) -> None:
        """Background: run PlanningLoop; on PlannerUnavailable fall back to the
        legacy gated path. Reports results to the chat (honest)."""
        from agent_core.models import AssessmentGoal
        from agent_core.planning_loop import PLANNER_UNAVAILABLE_REASON
        goal = AssessmentGoal(target_url=target, scope=scope,
                              description="assess web_app attack surface")
        try:
            outcome = await self._agent["loop"].run(goal)
        except asyncio.CancelledError:
            try:
                await self._app.bot.send_message(
                    chat_id=int(chat_id),
                    text=f"🛑 已中止 agent 評估：{target}")
            except Exception:
                logger.warning("agent cancel notice send failed")
            raise
        except Exception as exc:  # noqa: BLE001
            # any unexpected agent-path error -> fall back to the gated legacy path
            logger.warning("agent path error, falling back to legacy: %s", exc)
            await self._fallback_to_legacy(update, chat_id, target, scope,
                                           reason=str(exc))
            return
        finally:
            self._running_assessments.pop(str(chat_id), None)

        # planner unavailable -> fail closed to the legacy GATED path
        if outcome.stopped_reason == PLANNER_UNAVAILABLE_REASON:
            await self._fallback_to_legacy(update, chat_id, target, scope,
                                           reason="planner unavailable")
            return

        findings = outcome.findings
        dist: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info") if isinstance(f, dict) else "info"
            dist[sev] = dist.get(sev, 0) + 1
        dist_str = ", ".join(f"{k}:{n}" for k, n in dist.items()) if dist else "無"
        steps = len(outcome.trace.steps)
        lines = [
            f"✅ agent 評估完成：{target}",
            f"規劃步數：{steps}",
            f"發現項目：{len(findings)}",
            f"嚴重度分佈：{dist_str}",
            f"停止原因：{outcome.stopped_reason}",
        ]
        if not findings:
            lines.append("（本次評估未發現項目——這是真實結果）")
        try:
            await self._app.bot.send_message(chat_id=int(chat_id),
                                             text="\n".join(lines))
        except Exception:
            logger.warning("agent result send failed")

    async def _fallback_to_legacy(self, update, chat_id, target, scope,
                                  reason: str) -> None:
        """Fail-closed fallback: run the legacy GATED path when the agent path
        cannot proceed. Never raw execution — build_phased_profile is gated."""
        try:
            await self._app.bot.send_message(
                chat_id=int(chat_id),
                text=(f"ℹ️ agent 規劃不可用（{reason}），退回既有閘門評估流程。"))
        except Exception:
            pass
        from app.bounty.scanner import build_phased_profile
        from app.bounty.enums import ScanTool
        host = target.split("://")[-1].split("/")[0]
        prio_tools = []
        mem = getattr(self._scanner, "_assessment_memory", None)
        if mem is not None:
            try:
                names = mem.recommend_priority_tools("web_app",
                        query=f"assessment of {host}")
                name2tool = {t.value: t for t in ScanTool}
                prio_tools = [name2tool[n] for n in names if n in name2tool]
            except Exception:
                prio_tools = []
        profile = build_phased_profile(prioritize_tools=prio_tools)
        task = asyncio.create_task(
            self._run_assessment(chat_id, target, scope, profile))
        self._running_assessments[str(chat_id)] = task

    async def _run_assessment(self, chat_id, target, scope, profile) -> None:
        """背景執行授權評估並把結果回報到對話（誠實呈現）。"""
        msg = None
        try:
            result = await self._scanner.scan(target, scope, profile)
            vulns = (result.get("vulnerabilities", [])
                     if isinstance(result, dict)
                     else getattr(result, "vulnerabilities", []))
            tools_used = getattr(result, "tools_used", []) if not isinstance(result, dict) else []
            # severity 分佈
            dist: dict[str, int] = {}
            for v in vulns:
                sev = v.severity.value if hasattr(v, "severity") else "info"
                dist[sev] = dist.get(sev, 0) + 1
            dist_str = ", ".join(f"{k}:{n}" for k, n in dist.items()) if dist else "無"
            tools_str = ", ".join(t.value for t in tools_used) if tools_used else "（無）"
            lines = [
                f"✅ 評估完成：{target}",
                f"編排工具：{tools_str}",
                f"發現項目（去重後）：{len(vulns)}",
                f"嚴重度分佈：{dist_str}",
            ]
            if not vulns:
                lines.append("（本次評估未發現項目——這是真實結果）")
            msg = "\n".join(lines)
        except asyncio.CancelledError:
            # /stop 觸發：停止等待掃描、關閉底層 SSH 連線。誠實告知使用者
            # 這是「停止等待並中斷連線」，不保證強制殺掉遠端已啟動的工具進程。
            try:
                await self._app.bot.send_message(
                    chat_id=int(chat_id),
                    text=(f"🛑 已中止評估：{target}\n"
                          "（已停止等待並關閉掃描連線；若有工具正在遠端執行，"
                          "通常會隨連線關閉而結束。）"))
            except Exception:
                logger.warning("assessment cancel notice send failed")
            raise  # 讓 task 正常進入 cancelled 狀態
        except Exception as exc:
            msg = f"評估結束（{type(exc).__name__}）：{exc}"
        finally:
            # 無論完成/失敗/取消，都清掉這個 chat 的 task handle
            self._running_assessments.pop(str(chat_id), None)
        if msg is not None:
            try:
                await self._app.bot.send_message(chat_id=int(chat_id), text=msg)
            except Exception:
                logger.warning("assessment result send failed")

    async def cmd_cancel(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        self._pending_scan.pop(str(update.effective_chat.id), None)
        await update.message.reply_text("已取消。")

    async def cmd_stop(self, update, context) -> None:
        """中止「進行中」的評估掃描（最保險做法：只取消 asyncio task，
        由既有機制連帶關閉 SSH 連線；不對遠端送 kill，避免影響系統穩定性）。"""
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        key = str(update.effective_chat.id)
        task = self._running_assessments.get(key)
        if task is None or task.done():
            return await update.message.reply_text("目前沒有進行中的掃描可中止。")
        task.cancel()  # _run_assessment 的 CancelledError 分支會推播中止訊息
        await update.message.reply_text("已送出中止，正在停止掃描…")

    async def cmd_persona(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is None:
            return await update.message.reply_text("persona: not wired")
        await self._personality._ensure_components()
        knobs = self._personality._snapshot_knobs(self._personality._active_profile())
        if not knobs:
            return await update.message.reply_text("目前沒有可顯示的人格參數。")
        lines = ["我目前的人格參數："] + [f"- {k}: {v}" for k, v in knobs.items()]
        en = "開啟" if getattr(self._personality, "_evolve_enabled", True) else "暫停"
        lines.append(f"演化狀態：{en}")
        await update.message.reply_text("\n".join(lines))

    async def cmd_undo(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is None:
            return await update.message.reply_text("undo: not wired")
        comps = await self._personality._ensure_components()
        if comps is None:
            return await update.message.reply_text("undo: components unavailable")
        try:
            hist = await comps.evolution.get_version_history(limit=2)
            if not hist or len(hist) < 2:
                return await update.message.reply_text("沒有可還原的前一個版本。")
            prev = hist[1]
            vid = prev.get("version_id") if isinstance(prev, dict) else getattr(prev, "version_id", None)
            await comps.evolution.rollback_to_version(vid)
            await update.message.reply_text("已還原到上一個人格版本。")
        except Exception as exc:
            await update.message.reply_text(f"還原失敗：{exc}")

    async def cmd_evolve(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        arg = (context.args[0].lower() if context.args else "")
        if arg not in ("on", "off"):
            cur = "開啟" if getattr(self._personality, "_evolve_enabled", True) else "暫停"
            return await update.message.reply_text(f"用法：/evolve on 或 /evolve off（目前：{cur}）")
        if self._personality is not None:
            self._personality._evolve_enabled = (arg == "on")
        await update.message.reply_text(f"人格演化已{'開啟' if arg=='on' else '暫停'}。")

    async def cmd_learn(self, update, context) -> None:
        """教 Eliana 一條知識：寫進知識庫（面板「你教的」），不走對話生成、
        不帶對話歷史、不觸發演化——這就是把「教它」和「跟它聊」分流。"""
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._knowledge is None:
            return await update.message.reply_text("知識庫未啟用。")
        text = " ".join(context.args) if context.args else ""
        if not text.strip():
            return await update.message.reply_text(
                "用法：/learn <要我記住的知識>\n（這會收進知識庫，不會當成聊天回覆）")
        try:
            ok = self._knowledge.learn(text, source="telegram")
            cnt = self._knowledge.count()
        except Exception as exc:  # noqa: BLE001
            return await update.message.reply_text(f"記下失敗：{exc}")
        if ok:
            await update.message.reply_text(
                f"已記下，收進知識庫（你教的）。目前這類知識共 {cnt} 筆。")
        else:
            await update.message.reply_text(
                "沒記成——embedding 或知識庫寫入失敗，這條沒存進去（誠實回報）。")

    async def cmd_reset(self, update, context) -> None:
        """開新話題：清掉這個對話的短期脈絡；長期向量記憶保留。"""
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._personality is None:
            return await update.message.reply_text("reset: personality not wired")
        try:
            self._personality.reset_history(str(update.effective_chat.id))
        except Exception as exc:  # noqa: BLE001
            return await update.message.reply_text(f"reset 失敗：{exc}")
        await update.message.reply_text(
            "好，開新話題了。短期脈絡清掉，接下來不會接著剛剛的話題。\n"
            "（長期記憶保留，之後需要我還是回想得起來。）")

    async def cmd_status(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        if self._rm is None:
            return await update.message.reply_text("status: resource monitor not wired")
        try:
            from eliana_core.models.task import HostTarget
            m = await self._rm.collect_metrics(HostTarget.CORE)
            txt = (f"Eliana status\n"
                   f"CPU {m.cpu_percent:.0f}% | MEM {m.memory_percent:.0f}% "
                   f"({m.memory_used_gb:.1f}/{m.memory_total_gb:.1f} GB) | "
                   f"DISK {m.disk_percent:.0f}%")
            await update.message.reply_text(txt)
        except Exception as exc:  # noqa: BLE001
            await update.message.reply_text(f"status error: {exc}")

    async def _stream_reply(self, update, text: str) -> None:
        """Send a placeholder, then stream the persona reply editing the message in place."""
        if self._personality is None:
            return await update.message.reply_text("chat: personality not wired")
        placeholder = await update.message.reply_text("\u601d\u8003\u4e2d\u2026")  # 思考中…
        buf = []
        last_edit_len = 0
        header = ""
        import time as _t
        last_t = _t.monotonic()
        try:
            async for chunk in self._personality.generate_reply_stream({"prompt": text, "history_key": str(update.effective_chat.id)}):
                if isinstance(chunk, str) and chunk.startswith("__BACKEND__:"):
                    lbl = chunk.split(":", 1)[1].strip()
                    header = ("\u2601\ufe0f \u96f2\u7aef (Gemini)\n\n" if lbl == "cloud"
                              else "\U0001f5a5\ufe0f \u672c\u5730 (\u672c\u6a5f\u6a21\u578b)\n\n")
                    continue
                buf.append(chunk)
                cur = header + "".join(buf)
                # 節流：每累積 >=60 字或每 2 秒才編輯一次，避免觸發 Telegram 限流
                if len(cur) - last_edit_len >= 60 or (_t.monotonic() - last_t) >= 2.0:
                    if cur.strip() and cur[:4000] != "":
                        try:
                            await placeholder.edit_text(cur[:4000])
                            last_edit_len = len(cur)
                            last_t = _t.monotonic()
                        except Exception:
                            pass
            final = (header + "".join(buf).strip()) or "(no reply)"
            try:
                await placeholder.edit_text(final[:4000])
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            try:
                await placeholder.edit_text(f"error: {exc}")
            except Exception:
                pass

    async def cmd_chat(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        text = " ".join(context.args) if context.args else ""
        if not text:
            return await update.message.reply_text("usage: /chat <message>")
        await self._stream_reply(update, text)

    async def on_text(self, update, context) -> None:
        """Plain text (no slash) -> treat as chat."""
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        text = (update.message.text or "").strip()
        if not text:
            return
        await self._stream_reply(update, text)

    def build(self):
        from telegram.ext import (
            ApplicationBuilder, CommandHandler, MessageHandler, filters,
        )
        if not self._cfg["token"]:
            raise RuntimeError("ELIANA_TELEGRAM__BOT_TOKEN not set")
        app = ApplicationBuilder().token(self._cfg["token"]).build()
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("help", self.cmd_help))
        app.add_handler(CommandHandler("status", self.cmd_status))
        app.add_handler(CommandHandler("local", self.cmd_local))
        app.add_handler(CommandHandler("cloud", self.cmd_cloud))
        app.add_handler(CommandHandler("auto", self.cmd_auto))
        app.add_handler(CommandHandler("persona", self.cmd_persona))
        app.add_handler(CommandHandler("undo", self.cmd_undo))
        app.add_handler(CommandHandler("evolve", self.cmd_evolve))
        app.add_handler(CommandHandler("scan", self.cmd_scan))
        app.add_handler(CommandHandler("authorize", self.cmd_authorize))
        app.add_handler(CommandHandler("cancel", self.cmd_cancel))
        app.add_handler(CommandHandler("stop", self.cmd_stop))
        app.add_handler(CommandHandler("learn", self.cmd_learn))
        app.add_handler(CommandHandler("reset", self.cmd_reset))
        app.add_handler(CommandHandler("chat", self.cmd_chat))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.on_text))
        self._app = app
        return app

    async def announce_online(self) -> None:
        """Proactively DM the owner that Eliana is up."""
        if not self._app or not self._cfg["chat_id"]:
            return
        try:
            await self._app.bot.send_message(
                chat_id=int(self._cfg["chat_id"]),
                text="Eliana is online and listening. Try /status or /chat hello")
        except Exception as exc:  # noqa: BLE001
            logger.warning("announce_failed: %s", exc)


def build_subsystems():
    """Build personality + resource_monitor for standalone Telegram run."""
    from eliana_core.services.local_llm import LocalLLM
    from eliana_core.services.resource_monitor import ResourceMonitor
    from app.integration.personality_adapter import PersonalityAdapter
    base_url = os.environ.get("ELIANA_OLLAMA__BASE_URL", "http://127.0.0.1:11434")
    model = os.environ.get("ELIANA_OLLAMA__MODEL", "llama3.1")
    llm = LocalLLM(base_url=base_url)
    personality = PersonalityAdapter(local_llm=llm, model=model)
    # scan subsystem: SSHChannel(kali) -> ScanEngine -> AuthorizedScanner
    scanner = None
    ssh = None
    try:
        from eliana_core.services.ssh_channel import SSHChannel
        from app.bounty.scanner import ScanEngine
        from app.bounty.authorized_scan import AuthorizedScanner
        weapon_host = os.environ.get("ELIANA_WEAPON__HOST", "YOUR_WEAPON_HOST")
        weapon_user = os.environ.get("ELIANA_WEAPON__USER", "YOUR_WEAPON_USER")
        weapon_key = os.environ.get("ELIANA_WEAPON__KEY", "/etc/eliana/keys/kali_ed25519")
        ssh = SSHChannel(host=weapon_host, username=weapon_user,
                         private_key_path=weapon_key, known_hosts_path=None,
                         connect_timeout=8.0)
        engine = ScanEngine(ssh_channel=ssh)
        bounty_db = os.environ.get("ELIANA_BOUNTY__DB", "YOUR_BOUNTY_DB")
        # Report narrative uses the local Ollama model (reuse the LocalLLM built
        # above). CVSS score stays objective (cvss formula); LLM writes prose
        # only. Local model = $0, no cloud quota, sensitive data stays on host.
        from app.bounty.authorized_scan import OllamaReportLLM
        report_llm = OllamaReportLLM(local_llm=llm)
        # Growth loop: assessment memory records findings-pattern experience and
        # lets future assessments recall it. Same persist dir as the dashboard's
        # memory so the panel can show the accumulated experience count.
        from app.bounty.assessment_memory import AssessmentMemory
        mem_dir = os.environ.get("ELIANA_MEMORY__DIR", "data/eliana_memory")
        assessment_memory = AssessmentMemory(persist_dir=mem_dir)
        scanner = AuthorizedScanner(db_path=bounty_db, scan_engine=engine,
                                    report_llm=report_llm,
                                    assessment_memory=assessment_memory)
    except Exception as exc:
        logger.warning("scan subsystem not wired: %s", exc)

    # Agent core (task 10.1): assemble the PlanningLoop from the SAME existing
    # pieces (engine / attack mapper / assessment_memory / authorization record).
    # Built unconditionally so it's ready, but only USED when the
    # ELIANA_AGENT__LOOP_ENABLED flag is on (default off -> legacy path).
    agent = None
    if scanner is not None:
        try:
            from app.bounty.attack_mapping import map_finding_to_attack
            from agent_core.eliana.mcp_server import ElianaMCPServer
            from agent_core.eliana.local_planner import LocalPlannerLLM
            from agent_core.eliana.memory_adapter import MemoryAdapter
            from agent_core.guardrail import GuardrailGate
            from agent_core.planning_loop import PlanningLoop

            mcp = ElianaMCPServer(scan_engine=engine,
                                  attack_mapper=map_finding_to_attack,
                                  memory=assessment_memory)
            gate = GuardrailGate()
            planner_model = os.environ.get("ELIANA_AGENT__MODEL", "llama3.2:3b")
            planner = LocalPlannerLLM(base_url=base_url, model=planner_model)
            mem_adapter = MemoryAdapter(assessment_memory)
            # AuthorizationPort = the AuthorizedScanner's is_authorized record check.
            loop = PlanningLoop(planner=planner, gate=gate, tools=mcp,
                                authorizer=scanner, memory=mem_adapter)
            agent = {"loop": loop}
        except Exception as exc:  # noqa: BLE001
            logger.warning("agent core not wired: %s", exc)
    rm = ResourceMonitor(ssh_channel=ssh)
    # /learn knowledge store: writes taught knowledge into the dashboard's
    # knowledge base (ariel_knowledge = 面板「你教的」). Separate persist dir
    # from conversation memory; ELIANA_KNOWLEDGE__DIR points at it.
    knowledge_store = None
    try:
        from app.integration.knowledge_store import KnowledgeStore
        knowledge_store = KnowledgeStore()
    except Exception as exc:
        logger.warning("knowledge store not wired: %s", exc)
    return personality, rm, scanner, knowledge_store, agent


def main() -> int:
    personality, rm, scanner, knowledge_store, agent = build_subsystems()
    rt = TelegramRuntime(personality=personality, resource_monitor=rm,
                         scanner=scanner, knowledge_store=knowledge_store,
                         agent=agent)
    app = rt.build()

    async def _post_init(application):
        await rt.announce_online()
        # wire evolution notifications to the owner's chat
        chat_id = rt._cfg.get("chat_id")
        if rt._personality is not None and chat_id:
            async def _notify(text):
                try:
                    await application.bot.send_message(chat_id=int(chat_id), text=text)
                except Exception:
                    pass
            if hasattr(rt._personality, "set_notify_callback"):
                rt._personality.set_notify_callback(_notify)

    app.post_init = _post_init
    logger.info("starting telegram polling")
    app.run_polling(drop_pending_updates=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())