# Eliana Integration Module — 整合與部署筆記

本模組（第七子模組）將六個既有子系統整合為統一的 FastAPI 應用程式。所有外部
依賴在本機以**注入式介面 + mock** 驗證；真實服務的接線留待 RHEL VM 部署階段。

## 本機驗證狀態

- 單元測試 51 + 整合測試 7 = **58 passed**
- 12 項正確性 Property (P1–P12) 全數通過
- 執行：`python -m pytest`（於 `eliana-integration/` 目錄）

| 元件 | 檔案 | Property |
|------|------|----------|
| Event_Bus | `app/integration/event_bus.py` | P1 發布/訂閱、P2 失敗重試 |
| Pipeline_Orchestrator | `app/integration/pipeline.py` | P3 階段順序、P4 ID 唯一、P5 失敗停止、P6 完成觸發 |
| Startup_Validator | `app/integration/startup_validator.py` | P7 啟動阻斷 |
| License_Scanner | `app/integration/license_scanner.py` | P8 分類、P9 報告完整 |
| Config_Manager | `app/integration/config_manager.py` | P10 驗證、P11 env 覆寫 |
| Health_Endpoint | `app/integration/health_endpoint.py` | P12 健康回應 |

## 注入式邊界（本機用 mock，VM 接真實）

整合模組本身不直接連線外部服務。以下相依皆為建構子注入，本機以 mock 驗證：

| 注入點 | 型別 | 本機（mock） | VM（真實） |
|--------|------|--------------|------------|
| `StartupValidator(checks=...)` | `dict[str, () -> Awaitable[bool]]` | 回傳 True/False 的 async fn | 實際探測 SSH/Ollama/Electrum/ChromaDB/Telegram |
| `PipelineOrchestrator(handlers=...)` | `dict[PipelineStage, StageHandler]` | 回傳固定 dict | 呼叫 bounty-hunter / digital-wallet / personality |
| `LicenseScanner(lookup=...)` | `(name) -> (version, license)` | 假授權表 | `importlib.metadata`（預設）|
| `ConfigManager(config_path=...)` | YAML 路徑 | inline dict | 真實 `eliana.yaml` |
| `build_all_adapters(backends=...)` | `dict[str, Any]` | None（就緒無操作） | 六個子系統實例 |

## RHEL VM 部署清單

### 1. 系統前置
- RHEL 10（身體）：Python 3.11+、六大子引擎程式碼、本整合模組
- Kali Linux（雙手）：nmap / nuclei / sqlmap 等工具，SSH 金鑰認證開通
- RHEL ↔ Kali 內網 SSH 連通（core-infra `SSH_Channel` 使用金鑰路徑）

### 2. 安裝相依
```bash
cd eliana-integration
pip install -e ".[dev]"
```

### 3. 外部服務就緒
- Ollama daemon 執行中（本地推論）
- Electrum daemon 執行中（digital-wallet）
- ChromaDB 可連線（learning-engine 向量庫）
- Telegram Bot token 有效（dashboard 通知）

### 4. 接線真實子系統（取代 mock）
於啟動腳本注入真實相依，範例：
```python
from app.integration.main import create_app

app = create_app(
    config_manager=ConfigManager(config_path="/etc/eliana/eliana.yaml", schema=ELIANA_SCHEMA),
    startup_validator=StartupValidator(bus, checks={
        "ssh": real_ssh_check,        # 呼叫 core-infra SSH_Channel
        "ollama": real_ollama_check,  # 探測 Ollama /api/tags
        "electrum": real_electrum_check,
        "chromadb": real_chromadb_check,
        "telegram": real_telegram_check,
    }),
    pipeline_handlers={
        PipelineStage.SEARCH: bounty_crawler_handler,
        PipelineStage.AUTHORIZE: authorization_gate_handler,
        PipelineStage.SCAN: scan_engine_handler,       # 經 SSH → Kali 工具
        PipelineStage.REPORT: report_generator_handler,
        PipelineStage.TRACK_BOUNTY: wallet_ledger_handler,
    },
    backends={
        "core_infra": core_infra_instance,
        "bounty_hunter": bounty_hunter_instance,
        "digital_wallet": digital_wallet_instance,
        "learning_engine": learning_engine_instance,
        "personality": personality_instance,
        "dashboard": dashboard_instance,
    },
)
```

### 5. 啟動模式
- 整合模式（預設）：`standalone=False`，啟動前執行全部依賴驗證
- 獨立模式：`standalone=True`，跳過跨系統驗證（單一子系統開發用）
- 開發跳過驗證：`skip_validation=True`

### 6. 執行
```bash
uvicorn app.integration.main:create_app --factory --host 0.0.0.0 --port 8000
```

### 7. 端點驗收（VM 上）
- `GET /health` → 全 healthy 200 / 任一 unhealthy 503，含六子模組狀態
- `POST /pipeline` → 觸發 SEARCH→…→TRACK_BOUNTY，回傳 pipeline_id 與階段狀態
- `GET /pipeline/{id}` → 查詢流程狀態
- `GET /config` → 目前生效配置
- `GET /compliance?packages=a,b` → 授權合規報告

## 安全邊界（不變式）

- 掃描階段僅在 AUTHORIZE 通過後執行，且僅呼叫 Kali 上既有開源工具
- 整合模組不產生 exploit / 攻擊 payload
- License_Scanner 強制零成本約束（僅允許 8 種開源授權）
- 私鑰、Telegram token 等敏感值僅由對應子系統持有，整合模組不落地

## 尚待整合階段完成（本機無法驗證）

- 真實 SSH → Kali 工具鏈端對端執行
- 真實 Ollama / Electrum / ChromaDB / Telegram 連線與逾時行為
- 雙機故障情境（Kali 斷線→Task_Scheduler 暫停）
- 跨六引擎的實際事件往返與 100ms 分派延遲量測
