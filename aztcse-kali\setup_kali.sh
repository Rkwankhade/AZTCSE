#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "[AZTCSE] Updating Kali packages"
sudo apt update

echo "[AZTCSE] Installing required tools"
sudo apt install -y python3 python3-venv python3-pip curl git docker.io docker-compose-plugin

echo "[AZTCSE] Enabling Docker"
sudo systemctl enable docker
sudo systemctl start docker

echo "[AZTCSE] Creating Python virtual environment"
python3 -m venv .venv
source .venv/bin/activate

echo "[AZTCSE] Installing Python dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
fi

echo "[AZTCSE] Starting Neo4j container"
sudo docker compose up -d neo4j

echo "[AZTCSE] Verifying command line engine"
python -m scripts.aztcse_cli full-cycle samples/cloud_inventory.json

echo
echo "[AZTCSE] Setup complete"
echo "Run API:"
echo "  source .venv/bin/activate"
echo "  uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
echo
echo "Open:"
echo "  http://127.0.0.1:8000/docs"
