"""Eliana Integration_App VM 啟動進入點。

把 config（eliana.yaml）+ 真實 startup checks + 六個引擎 + 接線 wrapper 串起來，
產生一個可由 uvicorn 啟動的 FastAPI app。

用法（RHEL VM，於 eliana-integration/ 目錄）：
    # 先填敏感環境變數
    source /etc/eliana/env.local

    # 開發/驗證整合層（不接真實引擎、掃描 dry-run、可跳過依賴驗證）：
    ELIANA_APP__SKIP_VALIDATION=true python3 run_server.py --standalone

    # 正式（接真實引擎、真實依賴驗證；掃描仍預設 dry-run）：
    python3 run_server.py --config /etc/eliana/eliana.yaml

    # 真正對「已授權目標」執行掃描（明確關閉 dry-run；你負責授權判斷）：
    python3 run_server.py --config /etc/eliana/eliana.yaml --enable-real-scan

也可用 uvicorn factory：
    uvicorn run_server:build --factory --host 0.0.0.0 --port 8000

安全預設：
- 掃描 dry_run 預設 True（不真的呼叫 Kali 工具），須 --enable-real-scan 才真跑。
- AUTHORIZE 為安全閘門：送出請求後 pipeline 停等人工核准，不自動進 SCAN。
- 機敏值（token/密碼）不寫在程式，一律讀環境變數。
"""
from __future__ import annotations

import argparse
import os
import sys

# --- sys.path fix ---
# This file lives in eliana-integration/, whose app/ package (integration only)
# clashes with the top-level app/ (bounty, personality). Python puts the script
# dir at sys.path[0], making app.bounty resolve to the wrong app. Remove the
# script dir and ensure the engine root wins so app.* resolves correctly.
import os as _os
_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if _os.path.abspath(p or ".") != _SCRIPT_DIR]
_ENGINE_ROOT = _os.environ.get("ELIANA_ROOT") or _os.getcwd()
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

import structlog

logger = structlog.get_logger(__name__)


def _load_config(config_path: str | None):
    from app.integration.config_manager import ConfigManager
    from app.integration.schema import ELIANA_SCHEMA

    mgr = ConfigManager(config_path=config_path, schema=ELIANA_SCHEMA)
    mgr.load()
    return mgr


def _try_wire_engines(dry_run: bool, config: dict | None = None):
    """嘗試建立六個引擎的真實物件與 adapter。

    引擎不在 sys.path 或初始化失敗時，回傳 None（該部分保持未接線），
    整合層仍可啟動（standalone / 健康檢查可運作，pipeline 對應階段會回報未接線）。
    回傳 (bounty_adapter, wallet_adapter, learning_adapter, backends)。
    """
    from app.integration.engine_adapters import (
        BountyHunterAdapter,
        LearningAdapter,
        WalletAdapter,
    )

    bounty = wallet = learning = None
    backends: dict = {}

    # --- bounty-hunter ---
    try:
        from app.bounty.crawler import BountyCrawler
        from app.bounty.authorization import AuthorizationGate
        from app.bounty.scanner import ScanEngine
        from app.bounty.reporter import ReportGenerator

        bounty_db = os.environ.get("ELIANA_BOUNTY__DB", "data/bounty.db")

        ssh_channel = None
        try:
            from eliana_core.services.ssh_channel import SSHChannel
            weapon = (config or {}).get("hosts", {}).get("weapon_host", {})
            if weapon:
                ssh_channel = SSHChannel(
                    host=weapon.get("hostname", "127.0.0.1"),
                    port=int(weapon.get("ssh_port", 22)),
                    username=weapon.get("ssh_user", "eliana"),
                    private_key_path=weapon.get("ssh_key_path", "~/.ssh/id_ed25519"),
                )
        except Exception as exc:
            logger.warning("ssh_channel_build_failed", error=str(exc))

        scan_engine = ScanEngine(ssh_channel=ssh_channel)
        bounty = BountyHunterAdapter(
            crawler=BountyCrawler(),
            auth_gate=AuthorizationGate(db_path=bounty_db),
            scan_engine=scan_engine,
            report_gen=ReportGenerator(),
            dry_run=dry_run,
            auth_db_path=bounty_db,
            ssh_channel=ssh_channel,
        )
        backends["bounty_hunter"] = bounty
        logger.info("wired_bounty_hunter", dry_run=dry_run, bounty_db=bounty_db, ssh=bool(ssh_channel))
    except Exception as exc:  # noqa: BLE001
        logger.warning("bounty_hunter_not_wired", error=str(exc))

    # --- digital-wallet ---
    try:
        from eliana_digital_wallet.services.transaction_ledger import TransactionLedger

        ledger = TransactionLedger(db_path=os.environ.get(
            "ELIANA_WALLET__LEDGER_DB", "data/wallet.db"))
        wallet = WalletAdapter(ledger=ledger)
        backends["digital_wallet"] = wallet
        logger.info("wired_digital_wallet")
    except Exception as exc:  # noqa: BLE001
        logger.warning("digital_wallet_not_wired", error=str(exc))

    # --- learning-engine ---
    try:
        import src.db  # noqa: F401
        import src.optimizer.strategy_optimizer  # noqa: F401

        learning_db = os.environ.get("ELIANA_LEARNING__DB", "data/learning.db")
        learning = LearningAdapter(db_path=learning_db)
        logger.info("wired_learning_engine", db_path=learning_db)
    except Exception as exc:  # noqa: BLE001
        logger.warning("learning_engine_not_wired", error=str(exc))

    # --- personality (support-type subsystem, peer to learning) ---
    personality = None
    try:
        from app.integration.personality_adapter import PersonalityAdapter
        from eliana_core.services.local_llm import LocalLLM
        ollama_cfg = (config or {}).get("ollama", {})
        base_url = ollama_cfg.get("base_url", "http://127.0.0.1:11434")
        model = ollama_cfg.get("model")
        local_llm = LocalLLM(base_url=base_url)
        personality = PersonalityAdapter(
            local_llm=local_llm,
            model=model,
            auth_gate=None,  # default-deny until bounty Authorization_Gate is bridged
        )
        backends["personality"] = personality
        logger.info("wired_personality", base_url=base_url, model=model)
    except Exception as exc:  # noqa: BLE001
        logger.warning("personality_not_wired", error=str(exc))

    return bounty, wallet, learning, personality, backends


def build(argv: list[str] | None = None):
    """建立並回傳 FastAPI app（供 uvicorn --factory 或直接執行）。"""
    parser = argparse.ArgumentParser(description="Eliana Integration_App")
    parser.add_argument("--config", default=os.environ.get(
        "ELIANA_CONFIG", "/etc/eliana/eliana.yaml"))
    parser.add_argument("--standalone", action="store_true",
                        help="模組獨立模式，跳過跨系統啟動驗證")
    parser.add_argument("--skip-validation", action="store_true",
                        help="跳過依賴驗證（開發用）")
    parser.add_argument("--enable-real-scan", action="store_true",
                        help="關閉掃描 dry-run，對已授權目標真正執行（你負責授權判斷）")
    args = parser.parse_args(argv if argv is not None else [])

    from app.integration.main import create_app
    from app.integration.startup_validator import StartupValidator
    from app.integration.event_bus import EventBus

    # 載入設定（standalone 也載，供 /config 端點）
    config_path = args.config if os.path.exists(args.config) else None
    if config_path is None:
        logger.warning("config_not_found_using_defaults", path=args.config)
    cfg_mgr = _load_config(config_path) if config_path else None

    dry_run = not args.enable_real_scan
    if args.enable_real_scan:
        logger.warning("REAL_SCAN_ENABLED",
                       note="掃描將真正對目標執行，請確認目標已獲授權")

    _cfg = cfg_mgr.config if cfg_mgr is not None else {}
    bounty, wallet, learning, personality, backends = _try_wire_engines(dry_run=dry_run, config=_cfg)

    # 組裝 startup checks（真實探測），standalone 時不使用
    kwargs: dict = {
        "standalone": args.standalone,
        "skip_validation": args.skip_validation,
        "bounty": bounty,
        "wallet": wallet,
        "learning": learning,
        "backends": backends,
    }
    if cfg_mgr is not None:
        kwargs["config_manager"] = cfg_mgr
        if not args.standalone:
            from app.integration.startup_checks import build_checks_from_config

            bus = EventBus()
            checks = build_checks_from_config(cfg_mgr.config, secrets=dict(os.environ))
            kwargs["event_bus"] = bus
            kwargs["startup_validator"] = StartupValidator(bus, checks)

    app = create_app(**kwargs)
    logger.info("integration_app_built",
                standalone=args.standalone, dry_run=dry_run,
                wired=list(backends.keys()))
    return app


def main() -> int:
    import uvicorn

    args_app = build(sys.argv[1:])
    # 從環境或預設取 host/port
    host = os.environ.get("ELIANA_HOST", "0.0.0.0")
    port = int(os.environ.get("ELIANA_PORT", "8000"))
    uvicorn.run(args_app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
