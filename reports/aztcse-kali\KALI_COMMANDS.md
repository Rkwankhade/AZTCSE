# Kali Linux Commands for AZTCSE

Run these commands inside Kali Linux from the project folder:

```bash
chmod +x setup_kali.sh
./setup_kali.sh
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Then open:

```text
http://127.0.0.1:8000/docs
```

Command line demonstration:

```bash
source .venv/bin/activate
python -m scripts.aztcse_cli full-cycle samples/cloud_inventory.json
python -m scripts.aztcse_cli simulate samples/cloud_inventory.json
python -m scripts.aztcse_cli risk samples/cloud_inventory.json
python -m scripts.aztcse_cli respond samples/cloud_inventory.json
python -m scripts.aztcse_cli twin samples/cloud_inventory.json --scenario isolate-public
```
