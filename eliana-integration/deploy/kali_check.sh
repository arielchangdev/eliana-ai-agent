#!/usr/bin/env bash
#
# Kali Linux (<WEAPON_HOST_IP>) 端檢查腳本
# 用途：確認安全工具就緒、Eliana 專用帳號與 SSH 授權設定正確
#
# 用法（在 Kali 上執行）：
#   chmod +x kali_check.sh
#   ./kali_check.sh

set -uo pipefail

log()  { printf '\033[1;34m[kali]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------- #
# 1. 安全工具
# --------------------------------------------------------------------------- #
log "檢查安全工具是否安裝"
for tool in nmap nuclei sqlmap; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "  $tool: $(command -v $tool)"
    else
        warn "  $tool 未安裝（sudo apt install $tool）"
    fi
done

# --------------------------------------------------------------------------- #
# 2. SSH 服務
# --------------------------------------------------------------------------- #
log "檢查 SSH 服務"
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    ok "  SSH 服務運行中"
else
    warn "  SSH 服務未運行（sudo systemctl enable --now ssh）"
fi

# --------------------------------------------------------------------------- #
# 3. Eliana 帳號與授權金鑰
# --------------------------------------------------------------------------- #
ELIANA_USER="eliana"
log "檢查 Eliana 專用帳號 (${ELIANA_USER})"
if id "${ELIANA_USER}" >/dev/null 2>&1; then
    ok "  帳號 ${ELIANA_USER} 存在"
    AUTH_KEYS="/home/${ELIANA_USER}/.ssh/authorized_keys"
    if [ -f "${AUTH_KEYS}" ]; then
        ok "  authorized_keys 存在（$(wc -l < "${AUTH_KEYS}") 把金鑰）"
    else
        warn "  找不到 ${AUTH_KEYS}（需從 RHEL 佈署公鑰）"
    fi
else
    warn "  帳號 ${ELIANA_USER} 不存在（sudo useradd -m ${ELIANA_USER}）"
fi

log "Kali 端檢查完成"
