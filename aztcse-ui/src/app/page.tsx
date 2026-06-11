"use client";
import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://localhost:8001";
const NAV = [
  { id:"attack",    label:"Attack Surface" },
  { id:"ai",        label:"AI Simulation"  },
  { id:"forensics", label:"Forensics"      },
  { id:"zerotrust", label:"Zero Trust"     },
  { id:"honeypot",  label:"Honeypot"       },
];

function pad(n: number) { return String(n).padStart(2,"0"); }
function ts() { const d=new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }

function useFetch<T>(url: string) {
  const [data,    setData]    = useState<T|null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string|null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { const r=await fetch(url); if(!r.ok) throw new Error(`${r.status}`); setData(await r.json()); }
    catch(e:unknown){ setError(e instanceof Error?e.message:String(e)); }
    finally { setLoading(false); }
  }, [url]);
  useEffect(()=>{ load(); },[load]);
  return { data, loading, error, reload:load };
}

type R = Record<string,unknown>;

const S = {
  dash:    { display:"flex", height:"640px", background:"#060b14", fontFamily:"'JetBrains Mono','Courier New',monospace", fontSize:"12px", color:"#c8dae8", overflow:"hidden", borderRadius:"10px", border:"1px solid rgba(0,200,255,0.12)" } as React.CSSProperties,
  sidebar: { width:"180px", background:"#0b1623", borderRight:"1px solid rgba(0,200,255,0.12)", display:"flex", flexDirection:"column" as const, flexShrink:0 },
  navItem: (a:boolean) => ({ display:"flex", alignItems:"center", gap:"8px", padding:"9px 12px", cursor:"pointer", borderLeft:`2px solid ${a?"#00c8ff":"transparent"}`, color:a?"#00c8ff":"#4a6a80", background:a?"rgba(0,200,255,0.07)":"transparent", fontSize:"10px" } as React.CSSProperties),
  main:    { flex:1, display:"flex", flexDirection:"column" as const, overflow:"hidden" },
  topbar:  { height:"40px", background:"#0b1623", borderBottom:"1px solid rgba(0,200,255,0.12)", display:"flex", alignItems:"center", padding:"0 14px", gap:"10px", flexShrink:0 },
  content: { flex:1, overflowY:"auto" as const, padding:"14px" },
  card:    { background:"#0b1623", border:"1px solid rgba(0,200,255,0.12)", borderRadius:"6px", padding:"12px", marginBottom:"10px" },
  ctitle:  { fontSize:"9px", color:"#4a6a80", letterSpacing:"1.5px", textTransform:"uppercase" as const, marginBottom:"8px" },
  grid2:   { display:"grid", gridTemplateColumns:"1fr 1fr", gap:"10px" },
  grid3:   { display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:"10px", marginBottom:"10px" },
  mval:    (c:string) => ({ fontSize:"22px", fontWeight:700, color:c }),
  mlbl:    { fontSize:"9px", color:"#4a6a80", marginTop:"2px" },
  brow:    { display:"flex", alignItems:"center", gap:"8px", marginBottom:"7px" },
  blbl:    { width:"140px", fontSize:"10px", color:"#4a6a80", flexShrink:0 },
  btrk:    { flex:1, height:"5px", background:"rgba(255,255,255,.06)", borderRadius:"3px", overflow:"hidden" },
  bval:    { fontSize:"10px", width:"36px", textAlign:"right" as const, flexShrink:0 },
  tbl:     { width:"100%", borderCollapse:"collapse" as const, fontSize:"10px" },
  th:      { textAlign:"left" as const, color:"#4a6a80", padding:"4px 6px", borderBottom:"1px solid rgba(0,200,255,0.12)", fontSize:"9px" },
  td:      { padding:"5px 6px", borderBottom:"1px solid rgba(255,255,255,.03)" },
  sev:     (l:string) => ({ padding:"2px 6px", borderRadius:"2px", fontSize:"9px", fontWeight:700, background:l==="CRITICAL"?"rgba(255,68,85,.2)":l==="HIGH"?"rgba(255,170,0,.15)":"rgba(0,200,255,.12)", color:l==="CRITICAL"?"#ff4455":l==="HIGH"?"#ffaa00":"#00c8ff" }),
  ztnode:  (s:string) => ({ display:"flex", alignItems:"center", gap:"8px", padding:"8px 10px", borderRadius:"5px", border:`1px solid ${s==="verified"?"rgba(0,232,122,.3)":s==="denied"?"rgba(255,68,85,.35)":"rgba(0,200,255,0.2)"}`, background:"#0b1623", marginBottom:"6px", cursor:"pointer" } as React.CSSProperties),
  zts:     (s:string) => ({ marginLeft:"auto", fontSize:"9px", fontWeight:700, color:s==="verified"?"#00e87a":s==="denied"?"#ff4455":"#ffaa00" }),
  btn:     (d?:boolean,g?:boolean) => ({ padding:"7px 14px", borderRadius:"4px", border:`1px solid ${d?"rgba(255,68,85,.4)":g?"rgba(0,232,122,.4)":"rgba(0,200,255,0.2)"}`, background:d?"rgba(255,68,85,.1)":g?"rgba(0,232,122,.1)":"rgba(0,200,255,.08)", color:d?"#ff4455":g?"#00e87a":"#00c8ff", cursor:"pointer", fontFamily:"inherit", fontSize:"10px" } as React.CSSProperties),
  loader:  { color:"#4a6a80", fontSize:"10px", padding:"20px", textAlign:"center" as const },
  err:     { color:"#ff4455", fontSize:"10px", padding:"10px", background:"rgba(255,68,85,.08)", borderRadius:"4px", marginBottom:"8px" },
};

function Bar({label,value,color,max=100}:{label:string;value:number;color:string;max?:number}) {
  return (
    <div style={S.brow}>
      <span style={S.blbl}>{label}</span>
      <div style={S.btrk}><div style={{height:"100%",borderRadius:"3px",background:color,width:`${Math.min((value/max)*100,100)}%`,transition:"width 1s ease"}}/></div>
      <span style={{...S.bval,color}}>{value}</span>
    </div>
  );
}

function Loader(){ return <div style={S.loader}>Loading live data from AWS...</div>; }
function Err({msg}:{msg:string}){ return <div style={S.err}>⚠ {msg} — is the backend running? (uvicorn api:app --port 8001)</div>; }

function AttackPanel({summary}:{summary:R|null}) {
  const {data:sim,loading,error} = useFetch<R>(`${API}/api/attack-sim/stats`);
  const paths = (sim?.top_paths as R[]) || [];
  const pb    = (sim?.priority_breakdown as Record<string,number>) || {};
  const total = Object.values(pb).reduce((a,b)=>a+b,0)||1;
  return (
    <>
      <div style={S.grid3}>
        <div style={S.card}><div style={S.mval("#ff4455")}>{String(summary?.critical_findings??"…")}</div><div style={S.mlbl}>CRITICAL FINDINGS</div></div>
        <div style={S.card}><div style={S.mval("#ffaa00")}>{String(summary?.risk_score??"…")}</div><div style={S.mlbl}>RISK SCORE</div></div>
        <div style={S.card}><div style={S.mval("#00c8ff")}>{String(summary?.attack_paths_found??0)}</div><div style={S.mlbl}>ATTACK PATHS</div></div>
      </div>
      {loading&&<Loader/>}{error&&<Err msg={error}/>}
      {sim&&<>
        <div style={S.card}>
          <div style={S.ctitle}>Top Attack Paths (Real AWS Data)</div>
          <table style={S.tbl}>
            <thead><tr><th style={S.th}>PATH ID</th><th style={S.th}>OBJECTIVE</th><th style={S.th}>STEPS</th><th style={S.th}>SUCCESS %</th><th style={S.th}>SEVERITY</th><th style={S.th}>VALIDATED</th></tr></thead>
            <tbody>{paths.map((p,i)=>(
              <tr key={i}>
                <td style={S.td}>{String(p.path_id)}</td>
                <td style={S.td}>{String(p.scenario_name??p.objective)}</td>
                <td style={S.td}>{String(p.step_count)}</td>
                <td style={S.td}>{(Number(p.overall_success_probability)*100).toFixed(0)}%</td>
                <td style={S.td}><span style={S.sev(String(p.criticality))}>{String(p.criticality)}</span></td>
                <td style={{...S.td,color:p.validated_on_aws?"#00e87a":"#4a6a80"}}>{p.validated_on_aws?"✓ YES":"—"}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div style={S.card}>
          <div style={S.ctitle}>Priority Breakdown</div>
          <Bar label="CRITICAL" value={pb.CRITICAL||0} color="#ff4455" max={total}/>
          <Bar label="HIGH"     value={pb.HIGH||0}     color="#ffaa00" max={total}/>
          <Bar label="MEDIUM"   value={pb.MEDIUM||0}   color="#00c8ff" max={total}/>
          <Bar label="LOW"      value={pb.LOW||0}       color="#00e87a" max={total}/>
        </div>
      </>}
    </>
  );
}

function ForensicsPanel() {
  const {data,loading,error,reload} = useFetch<R>(`${API}/api/forensics`);
  const [refreshing,setRefreshing]  = useState(false);
  async function doRefresh(){ setRefreshing(true); await fetch(`${API}/api/forensics/refresh`,{method:"POST"}); setTimeout(()=>{reload();setRefreshing(false);},5000); }
  const summary  = (data?.summary as R)||{};
  const bd       = (summary.severity_breakdown as Record<string,number>)||{};
  const events   = (data?.events  as R[])||[];
  const profiles = (data?.threat_profiles as R[])||[];
  const anomalies= (data?.anomalies as string[])||[];
  return (
    <>
      {loading&&<Loader/>}{error&&<Err msg={error}/>}
      <div style={S.grid3}>
        <div style={S.card}><div style={S.mval("#ff4455")}>{bd.CRITICAL??0}</div><div style={S.mlbl}>CRITICAL EVENTS</div></div>
        <div style={S.card}><div style={S.mval("#ffaa00")}>{bd.HIGH??0}</div><div style={S.mlbl}>HIGH EVENTS</div></div>
        <div style={S.card}><div style={S.mval("#00c8ff")}>{Number(summary.total_scanned??0)}</div><div style={S.mlbl}>EVENTS SCANNED</div></div>
      </div>
      {anomalies.length>0&&<div style={{...S.card,borderColor:"rgba(255,68,85,.3)"}}>
        <div style={S.ctitle}>Behavioral Anomalies</div>
        {anomalies.map((a,i)=><div key={i} style={{color:"#ff4455",fontSize:"10px",lineHeight:"1.8"}}>{a}</div>)}
      </div>}
      <div style={S.card}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"8px"}}>
          <div style={S.ctitle}>Threat Actor Profiles (Live CloudTrail)</div>
          <button style={S.btn()} onClick={doRefresh} disabled={refreshing}>{refreshing?"Refreshing…":"↻ Refresh"}</button>
        </div>
        <table style={S.tbl}>
          <thead><tr><th style={S.th}>SOURCE IP</th><th style={S.th}>EVENTS</th><th style={S.th}>SEVERITY</th><th style={S.th}>TOP ACTIONS</th></tr></thead>
          <tbody>{profiles.map((p,i)=>(
            <tr key={i}>
              <td style={{...S.td,color:"#ff4455"}}>{String(p.ip)}</td>
              <td style={S.td}>{String(p.event_count)}</td>
              <td style={S.td}><span style={S.sev(String(p.highest_severity))}>{String(p.highest_severity)}</span></td>
              <td style={{...S.td,color:"#4a6a80"}}>{(p.top_actions as string[]).slice(0,3).join(", ")}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div style={S.card}>
        <div style={S.ctitle}>Recent Suspicious Events</div>
        <table style={S.tbl}>
          <thead><tr><th style={S.th}>TIMESTAMP</th><th style={S.th}>EVENT</th><th style={S.th}>SOURCE IP</th><th style={S.th}>IDENTITY</th><th style={S.th}>SEV</th></tr></thead>
          <tbody>{events.slice(0,10).map((e,i)=>(
            <tr key={i}>
              <td style={{...S.td,color:"#4a6a80"}}>{String(e.timestamp).slice(0,19)}</td>
              <td style={S.td}>{String(e.event)}</td>
              <td style={{...S.td,color:"#ff4455"}}>{String(e.source_ip)}</td>
              <td style={{...S.td,color:"#4a6a80"}}>{String(e.user_identity).split("/").pop()}</td>
              <td style={S.td}><span style={S.sev(String(e.severity))}>{String(e.severity)}</span></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </>
  );
}

function ZeroTrustPanel() {
  const {data,loading,error,reload} = useFetch<R>(`${API}/api/zerotrust`);
  const [local,setLocal] = useState<Record<string,string>>({});
  const identities = (data?.identities as R[])||[];
  function toggle(id:string,cur:string){ const n:Record<string,string>={verified:"denied",denied:"verified",pending:"verified"}; setLocal(p=>({...p,[id]:n[cur]||"verified"})); }
  return (
    <>
      {loading&&<Loader/>}{error&&<Err msg={error}/>}
      <div style={S.grid3}>
        <div style={S.card}><div style={S.mval("#00e87a")}>{Number(data?.verified??0)}</div><div style={S.mlbl}>VERIFIED</div></div>
        <div style={S.card}><div style={S.mval("#ff4455")}>{Number(data?.denied??0)}</div><div style={S.mlbl}>DENIED</div></div>
        <div style={S.card}><div style={S.mval("#ffaa00")}>{Number(data?.pending??0)}</div><div style={S.mlbl}>PENDING MFA</div></div>
      </div>
      <div style={S.card}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"8px"}}>
          <div style={S.ctitle}>Live IAM Identities — Click to Toggle</div>
          <button style={S.btn()} onClick={reload}>↻ Refresh</button>
        </div>
        {identities.map((id,i)=>{
          const status = local[String(id.identity_id)]||String(id.status);
          return (
            <div key={i} style={S.ztnode(status)} onClick={()=>toggle(String(id.identity_id),status)}>
              <div style={{width:"28px",height:"28px",borderRadius:"4px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"13px",background:status==="verified"?"rgba(0,232,122,.12)":status==="denied"?"rgba(255,68,85,.12)":"rgba(255,170,0,.12)",flexShrink:0}}>
                {status==="verified"?"✓":status==="denied"?"✗":"?"}
              </div>
              <div style={{flex:1}}>
                <div style={{fontSize:"10px"}}>{String(id.name)}</div>
                <div style={{fontSize:"9px",color:"#4a6a80"}}>{id.mfa_verified?"✓ MFA":"✗ No MFA"} | Risk: {String(id.risk_score)}{(id.anomaly_flags as string[]).length>0?` | ${(id.anomaly_flags as string[]).join(", ")}`:""}  </div>
              </div>
              <div style={S.zts(status)}>{status.toUpperCase()}</div>
            </div>
          );
        })}
      </div>
      <div style={S.card}>
        <div style={S.ctitle}>Policy Coverage</div>
        <Bar label="MFA Coverage"        value={identities.filter(i=>i.mfa_verified).length}           color="#00e87a" max={Math.max(identities.length,1)}/>
        <Bar label="Low Risk"            value={identities.filter(i=>Number(i.risk_score)<0.3).length}  color="#00c8ff" max={Math.max(identities.length,1)}/>
        <Bar label="High Risk"           value={identities.filter(i=>Number(i.risk_score)>=0.6).length} color="#ff4455" max={Math.max(identities.length,1)}/>
      </div>
    </>
  );
}

function HoneypotPanel() {
  const {data,loading,error,reload} = useFetch<R>(`${API}/api/honeypot`);
  const [deploying,setDeploying] = useState(false);
  const [checking,setChecking]   = useState(false);
  const [hits,setHits]           = useState<Record<number,number>>({});
  const [intel,setIntel]         = useState<string[]>([]);
  const HP_IPS = ["185.220.101.47","194.165.16.11","103.21.244.0","45.129.56.200"];
  const TRAPS  = ["Fake Admin Portal (8080)","Fake DB Server (5432)","Fake S3 Bucket","SSH Tarpit (2222)"];
  const SUBS   = ["10.0.1.200:8080 | Decoy: banking-admin","10.0.2.100:5432 | Decoy: postgres-backup","s3://corp-data-backup-2024 | Logging: ON","0.0.0.0:2222 | Slowloris mode"];
  async function deploy(){ setDeploying(true); await fetch(`${API}/api/honeypot/deploy`,{method:"POST"}); setTimeout(()=>{reload();setDeploying(false);},3000); }
  async function check(){ setChecking(true); const r=await fetch(`${API}/api/honeypot/check`,{method:"POST"}); if(r.ok) reload(); setChecking(false); }
  function simHit(i:number){ setHits(p=>({...p,[i]:(p[i]||0)+1})); const ip=HP_IPS[Math.floor(Math.random()*4)]; setIntel(p=>[`${ts()} [TRAP:${TRAPS[i].split(" ")[0]}] Hit from ${ip}`,...p.slice(0,7)]); }
  const events  = (data?.events as R[])||[];
  const summary = (data?.summary as R)||{};
  const total   = Object.values(hits).reduce((a,b)=>a+b,0)+events.length;
  return (
    <>
      {loading&&<Loader/>}{error&&<Err msg={error}/>}
      <div style={S.grid3}>
        <div style={S.card}><div style={S.mval("#ffaa00")}>4</div><div style={S.mlbl}>ACTIVE TRAPS</div></div>
        <div style={S.card}><div style={S.mval("#ff4455")}>{total}</div><div style={S.mlbl}>TOTAL HITS</div></div>
        <div style={S.card}><div style={S.mval(summary.honeypot_triggered?"#ff4455":"#00e87a")}>{summary.honeypot_triggered?"TRIGGERED":"ARMED"}</div><div style={S.mlbl}>AWS STATUS</div></div>
      </div>
      <div style={S.card}>
        <div style={{display:"flex",gap:"8px",marginBottom:"10px"}}>
          <button style={S.btn()} onClick={deploy} disabled={deploying}>{deploying?"Deploying…":"Deploy to AWS"}</button>
          <button style={S.btn()} onClick={check}  disabled={checking}>{checking?"Checking…":"Check CloudTrail"}</button>
          <button style={S.btn()} onClick={reload}>↻ Refresh</button>
        </div>
        <div style={S.ctitle}>Honeypot Traps — Click to Simulate Hit</div>
        {TRAPS.map((t,i)=>(
          <div key={i} style={{border:"1px solid rgba(0,200,255,0.12)",borderRadius:"5px",padding:"10px 12px",marginBottom:"8px",cursor:"pointer"}} onClick={()=>simHit(i)}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:"4px"}}>
              <span style={{fontSize:"11px"}}>{t}</span>
              <span style={{fontSize:"18px",fontWeight:700,color:"#ffaa00"}}>{hits[i]||0}</span>
            </div>
            <div style={{fontSize:"9px",color:"#4a6a80"}}>{SUBS[i]}</div>
          </div>
        ))}
      </div>
      {events.length>0&&<div style={S.card}>
        <div style={S.ctitle}>Real AWS Honeypot Events</div>
        <table style={S.tbl}>
          <thead><tr><th style={S.th}>TIMESTAMP</th><th style={S.th}>RESOURCE</th><th style={S.th}>SOURCE IP</th><th style={S.th}>ACTION</th></tr></thead>
          <tbody>{events.map((e,i)=>(
            <tr key={i}>
              <td style={{...S.td,color:"#4a6a80"}}>{String(e.timestamp).slice(0,19)}</td>
              <td style={S.td}>{String(e.resource_type)}</td>
              <td style={{...S.td,color:"#ff4455"}}>{String(e.source_ip)}</td>
              <td style={S.td}>{String(e.action)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>}
      <div style={S.card}>
        <div style={S.ctitle}>Capture Log</div>
        <div style={{fontSize:"10px",lineHeight:"1.9",maxHeight:"100px",overflowY:"auto",color:"#4a6a80"}}>
          {intel.length===0?"Click traps to simulate hits.":intel.map((m,i)=><div key={i} style={{color:"#ffaa00"}}>{m}</div>)}
        </div>
      </div>
    </>
  );
}

function AIPanel({summary}:{summary:R|null}) {
  const {data:sim} = useFetch<R>(`${API}/api/attack-sim`);
  const [log,setLog]       = useState<{m:string;c:string}[]>([]);
  const [prog,setProg]     = useState(0);
  const [status,setStatus] = useState("Select a simulation to run...");
  const SIM:Record<string,string[]> = {
    phishing:   ["[AI] Generating spear-phishing templates...","[AI] Personalizing 500 targets from LinkedIn...","[RESULT] 73% click rate — credentials harvested","[DEFENSE] Email gateway flagged 127 messages"],
    credential: ["[AI] Loading 2.3M combo list...","[AI] Rate-limiting bypass active...","[RESULT] 61% success on reused passwords","[DEFENSE] CAPTCHA lockout triggered"],
    ransomware: ["[AI] Deploying ransomware payload to staging...","[AI] Scanning for backup targets...","[RESULT] 22% of assets encrypted before containment","[DEFENSE] EDR isolated 3 hosts in 4.2s"],
    sqli:       ["[AI] Fuzzing 10,000 payloads on /api/accounts...","[AI] UNION-based injection confirmed...","[RESULT] Schema extracted — 14 tables exposed","[DEFENSE] WAF blocked 9,847/10,000 payloads"],
    defend:     ["[DEFENSE] Deploying WAF rule updates...","[DEFENSE] Rotating IAM credentials...","[DEFENSE] Enabling GuardDuty threat intel...","[DEFENSE] Risk score reduced by 12 points"],
  };
  function run(type:string){ const msgs=SIM[type]; setLog([]); setProg(0); setStatus(type==="defend"?"Deploying defenses...":`Running ${type.toUpperCase()}...`); msgs.forEach((m,i)=>setTimeout(()=>{ setLog(p=>[...p,{m:`${ts()} ${m}`,c:m.includes("DEFENSE")?"#00e87a":m.includes("RESULT")?"#ffaa00":"#4a6a80"}]); setProg(Math.round((i+1)/msgs.length*100)); if(i===msgs.length-1)setStatus("Simulation complete."); },i*700)); }
  const paths = (sim?.attack_paths as R[])||[];
  return (
    <>
      <div style={S.card}>
        <div style={S.ctitle}>Simulation Control</div>
        <div style={{display:"flex",gap:"8px",flexWrap:"wrap" as const,marginBottom:"10px"}}>
          <button style={S.btn(true)}   onClick={()=>run("phishing")}>Phishing Sim</button>
          <button style={S.btn(true)}   onClick={()=>run("credential")}>Credential Stuffing</button>
          <button style={S.btn(true)}   onClick={()=>run("ransomware")}>Ransomware Chain</button>
          <button style={S.btn(true)}   onClick={()=>run("sqli")}>SQLi Exploit</button>
          <button style={S.btn(false,true)} onClick={()=>run("defend")}>Deploy Defense</button>
        </div>
        <div style={{fontSize:"10px",color:status.includes("Deploying")?"#00e87a":status.includes("Running")?"#ff4455":"#4a6a80",marginBottom:"6px"}}>{status}</div>
        <div style={{height:"8px",background:"rgba(255,255,255,.05)",borderRadius:"4px",overflow:"hidden",marginBottom:"6px"}}>
          <div style={{height:"100%",background:"linear-gradient(90deg,#00c8ff,#00e87a)",borderRadius:"4px",width:`${prog}%`,transition:"width .4s ease"}}/>
        </div>
        <div style={{fontSize:"10px",lineHeight:"1.9",maxHeight:"90px",overflowY:"auto",color:"#4a6a80"}}>
          {log.length===0?"Select an attack above.":log.map((l,i)=><div key={i} style={{color:l.c}}>{l.m}</div>)}
        </div>
      </div>
      <div style={S.card}>
        <div style={S.ctitle}>Real Attack Paths from Your AWS Account</div>
        {paths.length===0?<div style={{color:"#4a6a80",fontSize:"10px"}}>No simulation report found.</div>:(
          <table style={S.tbl}>
            <thead><tr><th style={S.th}>PATH ID</th><th style={S.th}>SCENARIO</th><th style={S.th}>SUCCESS %</th><th style={S.th}>SEVERITY</th><th style={S.th}>VALIDATED</th></tr></thead>
            <tbody>{paths.slice(0,5).map((p,i)=>(
              <tr key={i}>
                <td style={S.td}>{String(p.path_id)}</td>
                <td style={{...S.td,maxWidth:"160px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(p.scenario_name??p.objective)}</td>
                <td style={S.td}>{(Number(p.overall_success_probability)*100).toFixed(0)}%</td>
                <td style={S.td}><span style={S.sev(String(p.criticality))}>{String(p.criticality)}</span></td>
                <td style={{...S.td,color:p.validated_on_aws?"#00e87a":"#4a6a80"}}>{p.validated_on_aws?"✓ YES":"—"}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </div>
      <div style={S.grid2}>
        <div style={S.card}><div style={S.ctitle}>Attack Success Rates</div><Bar label="Phishing (AI)" value={73} color="#ff4455"/><Bar label="Credential Stuffing" value={61} color="#ffaa00"/><Bar label="Exploit Chains" value={38} color="#00c8ff"/><Bar label="Ransomware" value={22} color="#00e87a"/></div>
        <div style={S.card}><div style={S.ctitle}>Defense Effectiveness</div><Bar label="WAF Block Rate" value={89} color="#00e87a"/><Bar label="IDS Detection" value={77} color="#00e87a"/><Bar label="Containment" value={65} color="#00c8ff"/><Bar label="Patch Coverage" value={54} color="#ffaa00"/></div>
      </div>
    </>
  );
}

export default function Home() {
  const [active,setActive] = useState("attack");
  const [clock,setClock]   = useState("--:--:--");
  const [uptime,setUptime] = useState("00:00:00");
  const startRef           = useRef(Date.now());
  const {data:summary}     = useFetch<R>(`${API}/api/summary`);
  useEffect(()=>{ const t=setInterval(()=>{ const d=new Date(); setClock(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`); const up=Math.floor((Date.now()-startRef.current)/1000); setUptime(`${pad(Math.floor(up/3600))}:${pad(Math.floor((up%3600)/60))}:${pad(up%60)}`); },1000); return()=>clearInterval(t); },[]);
  return (
    <div style={S.dash}>
      <div style={S.sidebar}>
        <div style={{padding:"14px 12px",borderBottom:"1px solid rgba(0,200,255,0.12)"}}>
          <div style={{color:"#00c8ff",fontSize:"11px",letterSpacing:"3px",fontWeight:700}}>AZTCSE</div>
          <div style={{color:"#4a6a80",fontSize:"9px",marginTop:"2px"}}>BANKING DEFENSE v3.1</div>
          <div style={{color:"#00e87a",fontSize:"8px",marginTop:"4px"}}>● {summary?`AWS: ${String(summary.account_id)}`:"Connecting..."}</div>
        </div>
        <div style={{padding:"10px 0"}}>
          {NAV.map(n=>(
            <div key={n.id} style={S.navItem(active===n.id)} onClick={()=>setActive(n.id)}>
              <span style={{width:"6px",height:"6px",borderRadius:"50%",background:"currentColor",flexShrink:0,boxShadow:active===n.id?"0 0 6px currentColor":"none"}}/>
              {n.label}
            </div>
          ))}
        </div>
        <div style={{marginTop:"auto",padding:"10px 12px",borderTop:"1px solid rgba(0,200,255,0.12)"}}>
          <div style={{fontSize:"9px",color:"#4a6a80",marginBottom:"4px"}}>ENGINE</div>
          <div style={{fontSize:"10px"}}><span style={{display:"inline-block",width:"6px",height:"6px",borderRadius:"50%",background:"#00e87a",marginRight:"5px",verticalAlign:"middle"}}/>RUNNING</div>
          <div style={{fontSize:"9px",color:"#4a6a80",marginTop:"4px"}}>UP: {uptime}</div>
          <div style={{fontSize:"9px",color:"#4a6a80",marginTop:"2px"}}>{summary?String(summary.region):"..."}</div>
        </div>
      </div>
      <div style={S.main}>
        <div style={S.topbar}>
          <div style={{color:"#4a6a80",fontSize:"10px",flex:1}}>PROJECT 1A / <span style={{color:"#00c8ff"}}>{active.toUpperCase()}</span>{summary&&<span style={{color:"#4a6a80"}}> / {String(summary.account_id)}</span>}</div>
          <span style={{padding:"3px 8px",borderRadius:"3px",fontSize:"9px",fontWeight:700,background:"rgba(255,68,85,.15)",color:"#ff4455",border:"1px solid rgba(255,68,85,.3)"}}>{summary?`${summary.critical_findings} CRITICAL`:"LOADING..."}</span>
          <span style={{padding:"3px 8px",borderRadius:"3px",fontSize:"9px",fontWeight:700,background:"rgba(0,232,122,.1)",color:"#00e87a",border:"1px solid rgba(0,232,122,.25)"}}>{summary?String(summary.region):"..."}</span>
          <div style={{color:"#4a6a80",fontSize:"10px"}}>{clock}</div>
        </div>
        <div style={S.content}>
          {active==="attack"    && <AttackPanel    summary={summary}/>}
          {active==="ai"        && <AIPanel        summary={summary}/>}
          {active==="forensics" && <ForensicsPanel/>}
          {active==="zerotrust" && <ZeroTrustPanel/>}
          {active==="honeypot"  && <HoneypotPanel/>}
        </div>
      </div>
    </div>
  );
}
