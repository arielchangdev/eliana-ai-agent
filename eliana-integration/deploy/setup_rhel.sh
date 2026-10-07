#!/usr/bin/env bash
#
# Eliana RHEL VM (<ELIANA_HOST_IP>) 環境準備腳本
# 用途：裝系統套件、建 Python venv、建目錄與權限、開防火牆埠
#       （純環境設定，不含任何掃描動作）
#
# 用法（在 RHEL VM 上，於 eliana-integration/ 目錄執行）：
#   chmod +x deploy/setup_rhel.sh
#   ./deploy/setup_rhel.sh
#
# 執行後仍需：填 /etc/eliana/env.local（機敏值）、起 Ollama/ChromaDB/Electrum、
#            跑 deploy/deploy.sh 與 deploy/smoke_test.sh（見 RUNBOOK.md）。

set -euo pipefail

ELIANA_HOME="/opt/eliana"
ELIANA_ETC="/etc/eliana"
VENV_DIR="${ELIANA_HOME}/venv"
APP_PORT="8000"

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# --------------------------------------------------------------------------- #
# 1. 系統套件
# --------------------------------------------------------------------------- #
log "步驟 1/5：安裝系統套件（需 sudo）"
if command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3.11 python3.11-pip python3.11-devel git curl \
        openssh-clients firewalld || warn "部分套件安裝失敗，請手動檢查"
else
    warn "找不到 dnf，請確認這是 RHEL/Fedora 系統，或手動安裝 python3.11 git curl"
fi

PYBIN="python3.11"
command -v "${PYBIN}" >/dev/null 2>&1 || PYBIN="python3"
log "使用 Python：$(${PYBIN} --version 2>&1)"

# --------------------------------------------------------------------------- #
# 2. Python venv
# --------------------------------------------------------------------------- #
log "步驟 2/5：建立 Python 虛擬環境 ${VENV_DIR}"
sudo mkdir -p "${ELIANA_HOME}"
sudo chown -R "$(id -un):$(id -gn)" "${ELIANA_HOME}"
if [ ! -d "${VENV_DIR}" ]; then
    "${PYBIN}" -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip
log "安裝整合模組依賴"
python -m pip install -e ".[dev]"

# --------------------------------------------------------------------------- #
# 3. 設定目錄與權限
# --------------------------------------------------------------------------- #
log "步驟 3/5：建立設定目錄 ${ELIANA_ETC}"
sudo mkdir -p "${ELIANA_ETC}/keys"
sudo chown -R "$(id -un):$(id -gn)" "${ELIANA_ETC}"
chmod 700 "${ELIANA_ETC}" "${ELIANA_ETC}/keys"

if [ ! -f "${ELIANA_ETC}/eliana.yaml" ]; then
    cp deploy/eliana.yaml "${ELIANA_ETC}/eliana.yaml"
    log "已複製 eliana.yaml → ${ELIANA_ETC}/"
fi
if [ ! -f "${ELIANA_ETC}/env.local" ]; then
    cp deploy/env.example "${ELIANA_ETC}/env.local"
    chmod 600 "${ELIANA_ETC}/env.local"
    warn "已建立 ${ELIANA_ETC}/env.local（範本）— 請填入真實機敏值後 chmod 600"
fi

# 資料目錄（錢包帳本等）
mkdir -p "${ELIANA_HOME}/data"

# --------------------------------------------------------------------------- #
# 4. 防火牆埠
# --------------------------------------------------------------------------- #
log "步驟 4/5：開放 Integration_App 埠 ${APP_PORT}"
if command -v firewall-cmd >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port=${APP_PORT}/tcp || warn "firewall 設定失敗"
    sudo firewall-cmd --reload || true
    log "已開放 ${APP_PORT}/tcp"
else
    warn "找不到 firewall-cmd，請自行確認埠 ${APP_PORT} 可存取"
fi

# --------------------------------------------------------------------------- #
# 5. PYTHONPATH 提示（六引擎接線用）
# --------------------------------------------------------------------------- #
log "步驟 5/5：環境準備完成"
cat <<EOF

重要：六個引擎要能被 run_server.py 匯入，需讓它們在 PYTHONPATH 上。
建議把六個引擎程式碼放在 ${ELIANA_HOME} 下，並於啟動前設定：

  export PYTHONPATH="${ELIANA_HOME}:\${PYTHONPATH}"

各引擎的匯入路徑（run_server.py 使用）：
  - bounty-hunter   : app.bounty.*          （放 ${ELIANA_HOME}/app/bounty/）
  - digital-wallet  : eliana_digital_wallet.*（放 ${ELIANA_HOME}/eliana_digital_wallet/）
  - learning-engine : src.*                  （放 ${ELIANA_HOME}/src/）
  - core-infra      : eliana_core.*
  - personality     : app.personality.*

下一步（見 deploy/RUNBOOK.md）：
  1) 填機敏值：nano ${ELIANA_ETC}/env.local ; source ${ELIANA_ETC}/env.local
  2) 起本地服務：Ollama / ChromaDB / Electrum
  3) 產 SSH 金鑰並佈署到 Kali（deploy/deploy.sh 會協助）
  4) 啟動驗證（掃描預設 dry-run，安全）：
       source ${VENV_DIR}/bin/activate
       export PYTHONPATH="${ELIANA_HOME}:\${PYTHONPATH}"
       python run_server.py --config ${ELIANA_ETC}/eliana.yaml
  5) 煙霧測試：./deploy/smoke_test.sh

EOF
