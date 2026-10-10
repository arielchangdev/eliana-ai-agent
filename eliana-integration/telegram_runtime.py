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
    ) -> None:
        self._cfg = _load_cfg()
        self._personality = personality
        self._rm = resource_monitor
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
    rm = ResourceMonitor()
    return personality, rm


def main() -> int:
    personality, rm = build_subsystems()
    rt = TelegramRuntime(personality=personality, resource_monitor=rm)
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