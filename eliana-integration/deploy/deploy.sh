#!/usr/bin/env bash
#
# Eliana RHEL VM (<ELIANA_HOST_IP>) 部署腳本
# 用途：安裝依賴、建立設定目錄、檢查外部服務、啟動 Integration_App
#
# 用法（在 RHEL VM 上，於 eliana-integration/ 目錄執行）：
#   chmod +x deploy/deploy.sh
#   ./deploy/deploy.sh
#
# 這支腳本「不」處理任何密碼/token。敏感值請先 export 環境變數（見 deploy/env.example）。

set -euo pipefail

ELIANA_DIR="/etc/eliana"
KEY_DIR="${ELIANA_DIR}/keys"
KALI_IP="<WEAPON_HOST_IP>"
KALI_USER="eliana"
KEY_PATH="${KEY_DIR}/kali_ed25519"

log()  { printf '\033[1;34m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# --------------------------------------------------------------------------- #
# 1. 檢查 Python
# --------------------------------------------------------------------------- #
log "步驟 1/6：檢查 Python 版本"
if ! command -v python3 >/dev/null 2>&1; then
    err "找不到 python3，請先安裝 Python 3.11+"
    exit 1
fi
PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
log "Python 版本：${PYVER}"

# --------------------------------------------------------------------------- #
# 2. 安裝依賴
# --------------------------------------------------------------------------- #
log "步驟 2/6：安裝 Python 依賴"
python3 -m pip install --user -e ".[dev]"

# --------------------------------------------------------------------------- #
# 3. 建立設定目錄
# --------------------------------------------------------------------------- #
log "步驟 3/6：建立設定目錄 ${ELIANA_DIR}"
if [ ! -d "${ELIANA_DIR}" ]; then
    sudo mkdir -p "${KEY_DIR}"
    sudo chown -R "$(id -un):$(id -gn)" "${ELIANA_DIR}"
    chmod 700 "${ELIANA_DIR}" "${KEY_DIR}"
fi
if [ ! -f "${ELIANA_DIR}/eliana.yaml" ]; then
    cp deploy/eliana.yaml "${ELIANA_DIR}/eliana.yaml"
    log "已複製 eliana.yaml 到 ${ELIANA_DIR}/（請視需要編輯）"
else
    warn "${ELIANA_DIR}/eliana.yaml 已存在，未覆蓋"
fi

# --------------------------------------------------------------------------- #
# 4. SSH 金鑰（連 Kali）
# --------------------------------------------------------------------------- #
log "步驟 4/6：檢查連 Kali (${KALI_IP}) 的 SSH 金鑰"
if [ ! -f "${KEY_PATH}" ]; then
    warn "找不到私鑰 ${KEY_PATH}"
    warn "請執行：ssh-keygen -t ed25519 -f ${KEY_PATH} -N ''"
    warn "再把公鑰送到 Kali：ssh-copy-id -i ${KEY_PATH}.pub ${KALI_USER}@${KALI_IP}"
else
    chmod 600 "${KEY_PATH}"
    log "測試 SSH 連線至 Kali..."
    if ssh -i "${KEY_PATH}" -o BatchMode=yes -o ConnectTimeout=5 \
        "${KALI_USER}@${KALI_IP}" 'echo ok' 2>/dev/null | grep -q ok; then
        log "SSH 至 Kali 連線成功"
    else
        warn "SSH 至 Kali 連線失敗，請確認金鑰已佈署與網路連通"
    fi
fi

# --------------------------------------------------------------------------- #
# 5. 檢查外部服務（本機 RHEL 上）
# --------------------------------------------------------------------------- #
log "步驟 5/6：檢查本機外部服務"
check_port() {
    local name="$1" host="$2" port="$3"
    if timeout 3 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
        log "  ${name} (${host}:${port}) 可連線"
    else
        warn "  ${name} (${host}:${port}) 無法連線"
    fi
}
check_port "Ollama"   "127.0.0.1" "11434"
check_port "ChromaDB" "127.0.0.1" "8001"
check_port "Electrum" "127.0.0.1" "7777"

# --------------------------------------------------------------------------- #
# 6. 提示啟動
# --------------------------------------------------------------------------- #
log "步驟 6/6：部署檢查完成"
cat <<'EOF'

下一步：
  1) 確認已 export 敏感環境變數（參考 deploy/env.example）：
       source deploy/env.example   # 編輯填入真實值後
  2) 啟動服務（前景測試）：
       python3 -m uvicorn app.integration.main:create_app --factory \
         --host 0.0.0.0 --port 8000
     或安裝為 systemd 服務：
       sudo cp deploy/eliana-integration.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now eliana-integration
  3) 跑煙霧測試：
       ./deploy/smoke_test.sh

EOF
