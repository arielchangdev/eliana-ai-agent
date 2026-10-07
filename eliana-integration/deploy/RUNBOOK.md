# Eliana 部署手把手 RUNBOOK

給不確定每步怎麼做的你。照順序做，每一步都有可複製的指令。
兩台機器：
- **RHEL VM（身體）**：`<ELIANA_HOST_IP>`
- **Kali（雙手）**：`<WEAPON_HOST_IP>`，主機名 `kali`

> 重要前提：Eliana 的掃描階段會對目標跑 nmap/nuclei/sqlmap。**只能掃你自己擁有
> 或有書面授權的目標**（例如你參加的 bug bounty 計畫範疇）。這個判斷只有你能做。

---

## 階段 A：Kali 端準備（在 <WEAPON_HOST_IP> 上）

1. 登入 Kali，把 `deploy/kali_check.sh` 複製過去（或整個 repo）。
2. 建 Eliana 專用帳號（若還沒有）：
   ```bash
   sudo useradd -m eliana
   ```
3. 確認 SSH 服務開著：
   ```bash
   sudo systemctl enable --now ssh
   ```
4. 確認工具在（沒有就裝）：
   ```bash
   sudo apt update && sudo apt install -y nmap nuclei sqlmap
   ```
5. 跑檢查腳本確認：
   ```bash
   chmod +x kali_check.sh && ./kali_check.sh
   ```
   看到 nmap/nuclei/sqlmap 都 `[ok]` 就對了。（`authorized_keys` 這步等階段 B 做完。）

---

## 階段 B：RHEL 端準備（在 <ELIANA_HOST_IP> 上）

0. 把整個 `eliana-integration/`（連同六個引擎的程式碼）放到 RHEL，例如 `/opt/eliana/`。
   然後一鍵準備環境（裝套件、建 venv、建目錄、開防火牆埠）：
   ```bash
   cd /opt/eliana/eliana-integration
   chmod +x deploy/setup_rhel.sh && ./deploy/setup_rhel.sh
   ```
   這支腳本**不含任何掃描動作**，純環境設定。跑完照它印出的提示往下走。

1. 產生連 Kali 的 SSH 金鑰：
   ```bash
   sudo mkdir -p /etc/eliana/keys && sudo chown -R $USER /etc/eliana
   ssh-keygen -t ed25519 -f /etc/eliana/keys/kali_ed25519 -N ''
   ```
3. 把公鑰送到 Kali（會問一次 Kali 的 eliana 密碼）：
   ```bash
   ssh-copy-id -i /etc/eliana/keys/kali_ed25519.pub eliana@<WEAPON_HOST_IP>
   ```
4. 測連線（應印出 `ok`）：
   ```bash
   ssh -i /etc/eliana/keys/kali_ed25519 eliana@<WEAPON_HOST_IP> 'echo ok'
   ```

---

## 階段 C：本地服務（在 RHEL 上起三個服務）

> 這三個是 Eliana 的依賴。分別開三個終端機或用背景執行。

1. **Ollama**（本地 LLM）：
   ```bash
   ollama serve &
   ollama pull llama3.1        # 或你要用的模型
   ```
2. **ChromaDB**（向量庫，埠 8001）：
   ```bash
   pip install --user chromadb
   chroma run --host 127.0.0.1 --port 8001 &
   ```
3. **Electrum daemon**（錢包 RPC，埠 7777）：
   ```bash
   electrum daemon -d
   # 設定 RPC 埠與帳密請參考 Electrum 文件
   ```

> 若某埠號跟預設不同，改 `/etc/eliana/eliana.yaml` 或用環境變數覆寫。

---

## 階段 D：部署 Integration_App（在 RHEL 上）

1. 進目錄跑部署腳本：
   ```bash
   cd /opt/eliana/eliana-integration
   chmod +x deploy/deploy.sh && ./deploy/deploy.sh
   ```
   它會裝依賴、建設定目錄、測 SSH、檢查三個服務的埠。看 `[warn]` 的項目補齊。

2. 填敏感值（Telegram token、Electrum 密碼）：
   ```bash
   cp deploy/env.example /etc/eliana/env.local
   nano /etc/eliana/env.local     # 填入真實值
   chmod 600 /etc/eliana/env.local
   source /etc/eliana/env.local
   ```

3. 啟動（先前景測試）：
   ```bash
   python3 -m uvicorn app.integration.main:create_app --factory --host 0.0.0.0 --port 8000
   ```
   看到啟動成功、沒有 StartupValidationError 就對了。
   （若某依賴還沒好，會擋啟動——這是設計。開發時可暫時 `export ELIANA_APP__SKIP_VALIDATION=true`。）

4. 另開一個終端機跑煙霧測試：
   ```bash
   ./deploy/smoke_test.sh
   ```
   `/health`、`/config`、`/compliance` 都 `[pass]` 即成功。

5. （選用）裝成開機自啟服務：
   ```bash
   sudo cp deploy/eliana-integration.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now eliana-integration
   journalctl -u eliana-integration -f     # 看日誌
   ```

---

## 階段 E：接上六個引擎（已幫你接好，你只需擺對位置）

引擎接線已經寫好（`app/integration/engine_adapters.py` + `run_server.py`）。
你只要讓六個引擎在 PYTHONPATH 上，`run_server.py` 會自動接：

1. 把六個引擎程式碼放在 `/opt/eliana/` 下，維持這些匯入路徑：
   - bounty-hunter → `app/bounty/`
   - digital-wallet → `eliana_digital_wallet/`
   - learning-engine → `src/`
   - core-infra → `eliana_core/`
   - personality → `app/personality/`
2. 設定 PYTHONPATH 後啟動：
   ```bash
   source /opt/eliana/venv/bin/activate
   export PYTHONPATH="/opt/eliana:${PYTHONPATH}"
   source /etc/eliana/env.local
   python run_server.py --config /etc/eliana/eliana.yaml
   ```
   啟動日誌會印 `wired=[...]` 顯示哪些引擎接上了。沒接上的會有 `*_not_wired` warning，
   把 warning 貼給 Kiro 可協助排（通常是 import 路徑或引擎初始化參數問題）。

### 掃描的安全開關（重要）

- **預設 dry-run**：`run_server.py` 不加 `--enable-real-scan` 時，SCAN 階段只印出
  「將執行的掃描計畫」，**不會**真的呼叫 Kali 工具。可安全驗證整條流程。
- **AUTHORIZE 安全閘門**：授權階段送出請求後，pipeline 會停在等待狀態，
  **不會**自動往 SCAN 前進，需人工在 Authorization_Gate 核准。
- **真正掃描**：確認目標已獲授權後，才加旗標：
  ```bash
  python run_server.py --config /etc/eliana/eliana.yaml --enable-real-scan
  ```
  加上這個旗標代表**你**確認要對目標發動真實掃描，且該目標在你的授權範疇內。

---

## 常見狀況

- **啟動被擋（StartupValidationError）**：某依賴沒起來。看錯誤裡的 failed_components，
  回階段 C 補；開發階段可暫時 `ELIANA_APP__SKIP_VALIDATION=true`。
- **SSH 測試失敗**：確認 Kali 的 eliana 帳號有你的公鑰、<WEAPON_HOST_IP> 網路可達。
- **/health 回 503**：某子模組 unhealthy，看回應的 modules 陣列哪個 state 不是 healthy。
- **/pipeline 回 500**：子系統還沒接（階段 E）。在只驗證整合層時屬預期。
