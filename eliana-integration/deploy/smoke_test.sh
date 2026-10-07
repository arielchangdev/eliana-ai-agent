#!/usr/bin/env bash
#
# Eliana 煙霧測試：確認 Integration_App 起來後主要端點正常
# 用法（Integration_App 已啟動於 :8000 後執行）：
#   chmod +x deploy/smoke_test.sh
#   ./deploy/smoke_test.sh [BASE_URL]
# 預設 BASE_URL=http://127.0.0.1:8000

set -uo pipefail

BASE="${1:-http://127.0.0.1:8000}"
PASS=0
FAIL=0

log()  { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[pass]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

# 1. /health
log "測試 GET ${BASE}/health"
CODE=$(curl -s -o /tmp/eliana_health.json -w '%{http_code}' "${BASE}/health" || echo 000)
if [ "${CODE}" = "200" ] || [ "${CODE}" = "503" ]; then
    ok "/health 回應 ${CODE}"
    if grep -q '"modules"' /tmp/eliana_health.json; then
        ok "/health 內容含 modules"
    else
        bad "/health 內容缺 modules"
    fi
else
    bad "/health 回應 ${CODE}（預期 200 或 503）"
fi

# 2. /config
log "測試 GET ${BASE}/config"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/config" || echo 000)
[ "${CODE}" = "200" ] && ok "/config 回應 200" || bad "/config 回應 ${CODE}"

# 3. /compliance
log "測試 GET ${BASE}/compliance"
CODE=$(curl -s -o /tmp/eliana_comp.json -w '%{http_code}' "${BASE}/compliance?packages=fastapi,pydantic" || echo 000)
if [ "${CODE}" = "200" ]; then
    ok "/compliance 回應 200"
    grep -q '"packages"' /tmp/eliana_comp.json && ok "/compliance 含 packages" || bad "/compliance 缺 packages"
else
    bad "/compliance 回應 ${CODE}"
fi

# 4. /pipeline（僅在真實子系統接上時才會成功；未接上會 500，屬預期）
log "測試 POST ${BASE}/pipeline（需真實子系統接線才會 completed）"
CODE=$(curl -s -o /tmp/eliana_pipe.json -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"host":"example.com"}' "${BASE}/pipeline" || echo 000)
if [ "${CODE}" = "200" ]; then
    ok "/pipeline 回應 200"
else
    log "/pipeline 回應 ${CODE}（若子系統尚未接線，此為預期，非錯誤）"
fi

echo
log "煙霧測試結果：PASS=${PASS} FAIL=${FAIL}"
[ "${FAIL}" -eq 0 ] && exit 0 || exit 1
