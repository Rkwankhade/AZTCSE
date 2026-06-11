import json, os, sys, asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "modules"))

app = FastAPI(title="AZTCSE Defense API", version="3.1.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:8000","http://localhost:3000","https://aztcse-ui.vercel.app"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "710215922764")

def load_latest_json(pattern: str):
    files = sorted(BASE_DIR.glob(pattern), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files: return None
    with open(files[0]) as f: return json.load(f)

@app.get("/health")
def health():
    return {"status":"ok","account_id":ACCOUNT_ID,"region":AWS_REGION,"timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/api/forensics")
def get_forensics():
    data = load_latest_json("forensic_report_*.json")
    if data: return data
    raise HTTPException(status_code=404, detail="No forensic report found. Run the forensic module first.")

@app.post("/api/forensics/refresh")
async def refresh_forensics(background_tasks: BackgroundTasks):
    async def _fetch():
        try:
            from modules.forensic.forensic import run_forensic_investigation
            await run_forensic_investigation(ACCOUNT_ID, region=AWS_REGION, hours=72)
        except Exception as e: print(f"[BG forensics] {e}")
    background_tasks.add_task(_fetch)
    return {"status":"refresh_started"}

@app.get("/api/attack-sim")
def get_attack_sim():
    data = load_latest_json("attack_sim_advanced_*.json") or load_latest_json("attack_sim_extended_*.json")
    if data: return data
    raise HTTPException(status_code=404, detail="No attack sim report found.")

@app.get("/api/attack-sim/stats")
def get_attack_sim_stats():
    data = load_latest_json("attack_sim_advanced_*.json") or load_latest_json("attack_sim_extended_*.json")
    if not data: raise HTTPException(status_code=404, detail="No report found.")
    paths = data.get("attack_paths", [])
    summary = data.get("summary", {})
    return {"total_paths":summary.get("total_paths",len(paths)),"confirmed_on_aws":summary.get("confirmed_on_aws",0),
            "priority_breakdown":summary.get("priority_breakdown",{}),"top_paths":paths[:5],
            "generated_at":data.get("report_metadata",{}).get("generated_at")}

@app.get("/api/honeypot")
def get_honeypot():
    data = load_latest_json("honeypot_report.json")
    if data: return data
    return {"generated_at":datetime.now(timezone.utc).isoformat(),"deployed_resources":{},
            "total_events":0,"events":[],"summary":{"honeypot_triggered":False,"unique_ips":[]}}

@app.post("/api/honeypot/deploy")
async def deploy_honeypot(background_tasks: BackgroundTasks):
    async def _deploy():
        try:
            from modules.honeypot.honeypot import HoneypotEngine
            engine = HoneypotEngine(region=AWS_REGION, account_id=ACCOUNT_ID)
            await engine.deploy_s3_honeypot()
            await engine.deploy_iam_honeypot()
            engine.export_report()
        except Exception as e: print(f"[BG honeypot] {e}")
    background_tasks.add_task(_deploy)
    return {"status":"deploying"}

@app.post("/api/honeypot/check")
async def check_honeypot():
    try:
        from modules.honeypot.honeypot import HoneypotEngine
        engine = HoneypotEngine(region=AWS_REGION, account_id=ACCOUNT_ID)
        existing = load_latest_json("honeypot_report.json")
        if existing and existing.get("deployed_resources"):
            engine.deployed_resources = existing["deployed_resources"]
        await engine.check_cloudtrail_for_honeypot_access(hours=24)
        return engine.export_report()
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/zerotrust")
async def get_zerotrust():
    try:
        import boto3
        iam = boto3.client("iam", region_name=AWS_REGION)
        users = iam.list_users().get("Users", [])
        identities = []
        for u in users[:20]:
            name = u["UserName"]
            try: has_mfa = len(iam.list_mfa_devices(UserName=name).get("MFADevices",[])) > 0
            except: has_mfa = False
            try:
                keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata",[])
                old_key = any((datetime.now(timezone.utc)-k["CreateDate"].replace(tzinfo=timezone.utc)).days>90 for k in keys)
            except: old_key = False
            risk = 0.0; flags = []
            if not has_mfa: risk += 0.4; flags.append("No MFA")
            if old_key: risk += 0.2; flags.append("Stale key >90d")
            status = "denied" if risk>=0.6 else "pending" if risk>=0.3 else "verified"
            identities.append({"identity_id":u["UserId"],"name":name,"arn":u["Arn"],
                "mfa_verified":has_mfa,"risk_score":round(risk,2),"status":status,"anomaly_flags":flags,
                "created":u["CreateDate"].isoformat()})
        denied=sum(1 for i in identities if i["status"]=="denied")
        pending=sum(1 for i in identities if i["status"]=="pending")
        return {"total_identities":len(identities),"verified":len(identities)-denied-pending,
                "denied":denied,"pending":pending,"identities":identities,
                "fetched_at":datetime.now(timezone.utc).isoformat()}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/summary")
def get_summary():
    forensic = load_latest_json("forensic_report_*.json")
    attack   = load_latest_json("attack_sim_advanced_*.json") or load_latest_json("attack_sim_extended_*.json")
    honeypot = load_latest_json("honeypot_report.json")
    f = (forensic or {}).get("summary",{})
    a = (attack   or {}).get("summary",{})
    h = (honeypot or {}).get("summary",{})
    crit = f.get("severity_breakdown",{}).get("CRITICAL",0) + a.get("priority_breakdown",{}).get("CRITICAL",0)
    high = f.get("severity_breakdown",{}).get("HIGH",0)     + a.get("priority_breakdown",{}).get("HIGH",0)
    risk = min(0.5+crit*0.1+high*0.05, 1.0)
    return {"risk_score":round(risk*100),"critical_findings":crit,"high_findings":high,
            "assets_monitored":14,"attack_paths_found":a.get("total_paths",0),
            "confirmed_on_aws":a.get("confirmed_on_aws",0),"forensic_events_scanned":f.get("total_scanned",0),
            "forensic_suspicious":f.get("suspicious",0),"anomalies_detected":f.get("anomalies",0),
            "honeypot_triggered":h.get("honeypot_triggered",False),
            "account_id":ACCOUNT_ID,"region":AWS_REGION,
            "last_updated":datetime.now(timezone.utc).isoformat()}
