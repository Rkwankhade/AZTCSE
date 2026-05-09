# Autonomous Zero-Trust Cloud Security Engine (AZTCSE)

This project implements the original idea from `Rishi_advance_cloud.docx` as a Kali Linux-ready prototype.

Core modules included:

- Cloud Attack Surface Graph (CASG)
- AI-powered attack path simulator
- Dynamic context-aware risk scoring
- Autonomous response engine
- Zero Trust enforcement layer
- Cloud digital twin for safe what-if testing

The project is defensive and runs in dry-run mode by default. It plans remediations and prints the cloud commands that would be used, instead of changing a real AWS account automatically.

## Kali Linux Commands

From Kali terminal:

```bash
git clone <your-repo-url> aztcse-kali
cd aztcse-kali
chmod +x setup_kali.sh
./setup_kali.sh
```

If you are using this folder directly instead of Git:

```bash
cd aztcse-kali
chmod +x setup_kali.sh
./setup_kali.sh
```

Start Neo4j:

```bash
sudo docker compose up -d neo4j
```

Start the API:

```bash
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open in browser:

```text
http://127.0.0.1:8000/docs
```

Run the full engine from command line:

```bash
source .venv/bin/activate
python -m scripts.aztcse_cli full-cycle samples/cloud_inventory.json
```

Run only the attack simulator:

```bash
python -m scripts.aztcse_cli simulate samples/cloud_inventory.json
```

Run only risk scoring:

```bash
python -m scripts.aztcse_cli risk samples/cloud_inventory.json
```

Generate autonomous response commands:

```bash
python -m scripts.aztcse_cli respond samples/cloud_inventory.json
```

Run digital twin what-if testing:

```bash
python -m scripts.aztcse_cli twin samples/cloud_inventory.json --scenario isolate-public
```

## Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Default mode:

```bash
AZTCSE_DRY_RUN=true
```

Keep dry-run enabled for college/demo use unless you intentionally connect the project to a controlled AWS lab account.

## API Examples

Health check:

```bash
curl http://127.0.0.1:8000/health
```

## One-Block Kali Command

```bash
cd aztcse-kali
chmod +x setup_kali.sh
./setup_kali.sh
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Full autonomous cycle:

```bash
curl -X POST http://127.0.0.1:8000/full-cycle \
  -H "Content-Type: application/json" \
  --data @samples/cloud_inventory.json
```

## Project Structure

```text
app/
  main.py
  core/
    attack_surface_graph.py
    attack_simulator.py
    digital_twin.py
    models.py
    response_engine.py
    risk_engine.py
    zero_trust.py
scripts/
  aztcse_cli.py
samples/
  cloud_inventory.json
tests/
  test_engine.py
```

## College Demonstration Flow

1. Show the cloud inventory as input.
2. Build the Cloud Attack Surface Graph.
3. Simulate possible attack paths.
4. Score risks dynamically.
5. Generate autonomous dry-run response commands.
6. Apply a digital twin scenario to prove risk reduction.
7. Explain how real AWS integration can be enabled in a lab account.
