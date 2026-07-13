#!/usr/bin/env bash
# Quick health check for the Elastic Stack. Run: ./verify.sh
set -euo pipefail
cd "$(dirname "$0")"

# Load ELASTIC_PASSWORD / ES_PORT from .env
set -a; source .env; set +a

echo "== Containers =="
docker compose ps

echo
echo "== Cluster health (should say 'green' or 'yellow') =="
# --insecure because we call the HTTPS endpoint from the host without the CA on hand.
# A single-node lab reports 'yellow' (replicas unassigned) — that is expected and fine.
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
  "https://localhost:${ES_PORT}/_cluster/health?pretty" | grep -E '"status"|"number_of_nodes"'

echo
echo "Kibana:  http://<ELK01-IP>:${KIBANA_PORT:-5601}   (log in as user 'elastic')"
