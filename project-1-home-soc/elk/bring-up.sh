#!/usr/bin/env bash
# Bring up the Elastic Stack on ELK01. Run from this folder: ./bring-up.sh
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "No .env found. Copy the template and edit it first:"
  echo "    cp .env.example .env && nano .env"
  exit 1
fi

# Elasticsearch needs this kernel setting or it refuses to start.
CURRENT="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if [ "$CURRENT" -lt 262144 ]; then
  echo "Raising vm.max_map_count (needs sudo)…"
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf >/dev/null
fi

echo "Starting the stack…"
docker compose up -d

echo
echo "Watching setup + Elasticsearch come up (Ctrl-C to stop watching; containers keep running)…"
docker compose logs -f setup es01
