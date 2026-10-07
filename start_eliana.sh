#!/usr/bin/env bash
set -e
export PYTHONPATH=/opt/eliana
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
source /etc/eliana/env.local
cd /opt/eliana
echo "PYTHONPATH=$PYTHONPATH"
echo "RPC pw set? ${ELIANA_WALLET__RPC_PASSWORD:+yes}"
python3 eliana-integration/run_server.py --config /etc/eliana/eliana.yaml "$@"
