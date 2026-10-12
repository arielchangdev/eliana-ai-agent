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
    ) -> None:
        self._cfg = _load_cfg()
        self._personality = personality
        self._rm = resource_monitor
        self._scanner = scanner
        self._pending_scan = {}   # chat_id -> target awaiting /authorize
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
        # record explicit human authorization, then run the gated scan
        try:
            self._scanner.grant_authorization(target, validity_hours=24)
        except Exception as exc:
            return await update.message.reply_text(f"授權記錄失敗：{exc}")
        from app.bounty.models import ProgramScope
        from app.bounty.scanner import build_phased_profile
        from app.bounty.enums import ScanTool
        host = target.split("://")[-1].split("/")[0]
        scope = ProgramScope(domains=[host])
        # 成長閉環-2：回想過往評估經驗，推導「對這類目標較有產出的評估工具」，
        # 讓這次的工具編排在階段內把高產出工具提前（越評估越懂先用哪些）。
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
        # 多工具階段化評估（評估模式；build_phased_profile 自動過濾非評估工具、
        # 填入評估白名單 args）。依方法論 recon→enumeration→vuln_scanning 編排。
        profile = build_phased_profile(prioritize_tools=prio_tools)
        self._pending_scan.pop(str(update.effective_chat.id), None)

        tool_names = ", ".join(t.value for t in profile.tools)
        await update.message.reply_text(
            f"已授權 {target}，開始多工具評估（評估模式）。\n"
            f"編排工具：{tool_names}\n"
            f"方法論階段：偵察 → 列舉 → 漏洞掃描\n"
            f"這會花幾分鐘，完成後我會回報結果，請稍候…")

        # 背景執行，避免阻塞 handler；完成後主動把結果發回此對話
        chat_id = update.effective_chat.id
        asyncio.create_task(self._run_assessment(chat_id, target, scope, profile))

    async def _run_assessment(self, chat_id, target, scope, profile) -> None:
        """背景執行授權評估並把結果回報到對話（誠實呈現）。"""
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
        except Exception as exc:
            msg = f"評估結束（{type(exc).__name__}）：{exc}"
        try:
            await self._app.bot.send_message(chat_id=int(chat_id), text=msg)
        except Exception:
            logger.warning("assessment result send failed")

    async def cmd_cancel(self, update, context) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._reply_unauthorized(update)
        self._pending_scan.pop(str(update.effective_chat.id), None)
        await update.message.reply_text("已取消。")

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
    rm = ResourceMonitor(ssh_channel=ssh)
    return personality, rm, scanner


def main() -> int:
    personality, rm, scanner = build_subsystems()
    rt = TelegramRuntime(personality=personality, resource_monitor=rm, scanner=scanner)
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