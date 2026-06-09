"use client";
import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const NODES = [
  { id: 'igw', x: 310, y: 30, label: 'INTERNET GATEWAY', sub: 'igw-0f4e2a', color: '#00d4ff', bg: '#0a1a2a', border: '#00d4ff' },
  { id: 'dmz', x: 120, y: 130, label: 'PUBLIC SUBNET', sub: 'DMZ / 10.0.1.0/24', color: '#00d4ff', bg: '#0a1a2a', border: '#00d4ff' },
  { id: 'vpc', x: 500, y: 130, label: 'VPC PEERING', sub: 'pcx-0a3b7f', color: '#00d4ff', bg: '#0a1a2a', border: '#00d4ff' },
  { id: 'ec2', x: 120, y: 240, label: '⚠ EC2 COMPROMISED', sub: 'i-0abcd1234ef5', color: '#ff4040', bg: '#1a0505', border: '#ff4040' },
  { id: 's3',  x: 500, y: 240, label: 'S3 SENSITIVE DATA', sub: 'corp-prod-secrets', color: '#ffaa00', bg: '#141000', border: '#ffaa00' },
];

const LOGS = [
  { type: 'sys',  msg: '[SYSTEM] AZTCSE v3.1 engine initialized — ap-south-1' },
  { type: 'info', msg: '[INFO] Mapping AWS trust relationships and IAM policies...' },
  { type: 'info', msg: '[INFO] CloudTrail ingestion active — 14 assets indexed' },
  { type: 'warn', msg: '[WARN] Unrestricted SG on EC2 i-0abcd1234ef5 (0.0.0.0/0:22)' },
  { type: 'warn', msg: '[ALERT] Privilege escalation path detected via IAM PassRole' },
  { type: 'crit', msg: '[CRITICAL] Lateral movement confirmed — EC2 → S3 exfiltration active' },
];

const LOG_COLORS: Record<string, string> = {
  sys: '#4a8a6a', info: '#2a7aaa', warn: '#cc8800', crit: '#ff4040',
};

const NAV = ['Attack Surface', 'AI Simulation', 'Forensics', 'Zero Trust', 'Honeypot'];

function pad(n: number) { return String(n).padStart(2, '0'); }

export default function Dashboard() {
  const [logs, setLogs] = useState<{ type: string; msg: string; ts: string }[]>([]);
  const [active, setActive] = useState(0);
  const [risk, setRisk] = useState(87);
  const [crits, setCrits] = useState(3);
  const [dotPos, setDotPos] = useState({ x: 310, y: 30 });
  const [time, setTime] = useState('');
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setTime(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let i = 0;
    const addLog = () => {
      if (i >= LOGS.length) return;
      const d = new Date();
      const ts = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      setLogs(prev => [...prev, { ...LOGS[i], ts }]);
      i++;
      if (i < LOGS.length) setTimeout(addLog, 1400);
    };
    setTimeout(addLog, 600);
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => {
    const t = setInterval(() => setRisk(84 + Math.floor(Math.random() * 6)), 3000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      const t2 = setInterval(() => setCrits(c => c + 1), 8000);
      return () => clearInterval(t2);
    }, 4000);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const paths = [
      { x1: 310, y1: 70, x2: 120, y2: 130 },
      { x1: 120, y1: 170, x2: 120, y2: 240 },
      { x1: 210, y1: 260, x2: 500, y2: 260 },
    ];
    let phase = 0, prog = 0;
    let raf: number;
    const animate = () => {
      prog += 0.012;
      if (prog > 1) { prog = 0; phase = (phase + 1) % paths.length; }
      const p = paths[phase];
      setDotPos({ x: p.x1 + (p.x2 - p.x1) * prog, y: p.y1 + (p.y2 - p.y1) * prog });
      raf = requestAnimationFrame(animate);
    };
    const t = setTimeout(() => { raf = requestAnimationFrame(animate); }, 1200);
    return () => { clearTimeout(t); cancelAnimationFrame(raf); };
  }, []);

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#060a0f', color: '#e2e8f0', fontFamily: "'JetBrains Mono', 'Courier New', monospace", overflow: 'hidden' }}>

      {/* Sidebar */}
      <motion.div initial={{ x: -60, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ duration: 0.4 }}
        style={{ width: 200, background: '#080d14', borderRight: '1px solid #0f2030', padding: '16px 12px', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid #0f2030' }}>
          <div style={{ width: 28, height: 28, border: '1.5px solid #00d4ff', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2L14 5V11L8 14L2 11V5L8 2Z" stroke="#00d4ff" strokeWidth="1.5"/><circle cx="8" cy="8" r="2" fill="#00d4ff"/></svg>
          </div>
          <span style={{ fontSize: 12, fontWeight: 700, color: '#00d4ff', letterSpacing: 3 }}>AZTCSE</span>
        </div>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
          {NAV.map((n, i) => (
            <motion.button key={n} whileHover={{ x: 3 }} onClick={() => setActive(i)}
              style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', borderRadius: 6, fontSize: 10, cursor: 'pointer', border: active === i ? '1px solid rgba(0,212,255,0.25)' : '1px solid transparent', background: active === i ? 'rgba(0,212,255,0.07)' : 'transparent', color: active === i ? '#00d4ff' : '#4a6a8a', textAlign: 'left' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: active === i ? '#00d4ff' : '#2a4a6a', boxShadow: active === i ? '0 0 6px #00d4ff' : 'none', flexShrink: 0 }}/>
              {n}
            </motion.button>
          ))}
        </nav>
        <div style={{ paddingTop: 12, borderTop: '1px solid #0f2030' }}>
          <div style={{ fontSize: 9, color: '#2a4a6a', letterSpacing: 1, marginBottom: 6 }}>ENGINE STATUS</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: '#00d4ff' }}>
            <motion.div animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 2 }}
              style={{ width: 6, height: 6, borderRadius: '50%', background: '#00d4ff' }}/>
            RUNNING
          </div>
        </div>
      </motion.div>

      {/* Main */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Topbar */}
        <motion.div initial={{ y: -30, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ duration: 0.4, delay: 0.1 }}
          style={{ height: 44, background: '#080d14', borderBottom: '1px solid #0f2030', display: 'flex', alignItems: 'center', padding: '0 16px', justifyContent: 'space-between', flexShrink: 0 }}>
          <span style={{ fontSize: 10, color: '#4a6a8a', letterSpacing: 1 }}>LIVE ATTACK PATH — AWS ap-south-1</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: 10, color: '#2a4a6a' }}>{time}</span>
            <motion.div animate={{ opacity: [1, 0.6, 1] }} transition={{ repeat: Infinity, duration: 1.5 }}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: '#ff4040', background: 'rgba(255,40,40,0.08)', border: '1px solid rgba(255,40,40,0.25)', padding: '4px 10px', borderRadius: 20 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff4040' }}/>
              CRITICAL THREAT DETECTED
            </motion.div>
          </div>
        </motion.div>

        {/* Content */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 190px', gridTemplateRows: '1fr 160px', overflow: 'hidden' }}>

          {/* Graph */}
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.6, delay: 0.2 }}
            style={{ position: 'relative', overflow: 'hidden', background: '#060a0f' }}>
            {/* scanlines */}
            <div style={{ position: 'absolute', inset: 0, backgroundImage: 'repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,0.01) 2px,rgba(0,212,255,0.01) 4px)', pointerEvents: 'none', zIndex: 1 }}/>
            <svg width="100%" height="100%" viewBox="0 0 660 320" style={{ display: 'block' }}>
              <defs>
                <marker id="a-red" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#ff4040"/></marker>
                <marker id="a-cyan" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#00d4ff"/></marker>
                <marker id="a-amber" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#ffaa00"/></marker>
              </defs>
              {/* grid */}
              {Array.from({length:11},(_,i)=>(i+1)*60).map(x=><line key={`v${x}`} x1={x} y1={0} x2={x} y2={320} stroke="#0a1520" strokeWidth="0.5"/>)}
              {Array.from({length:5},(_,i)=>(i+1)*60).map(y=><line key={`h${y}`} x1={0} y1={y} x2={660} y2={y} stroke="#0a1520" strokeWidth="0.5"/>)}
              {/* edges */}
              <line x1="280" y1="70" x2="170" y2="130" stroke="#00d4ff" strokeWidth="1" strokeDasharray="5,3" markerEnd="url(#a-cyan)"/>
              <line x1="380" y1="70" x2="500" y2="130" stroke="#00d4ff" strokeWidth="1" markerEnd="url(#a-cyan)"/>
              <line x1="170" y1="170" x2="170" y2="230" stroke="#ff4040" strokeWidth="1.5" strokeDasharray="4,3" markerEnd="url(#a-red)"/>
              <path d="M250,255 C360,255 360,255 460,255" stroke="#ffaa00" strokeWidth="1.5" strokeDasharray="5,3" fill="none" markerEnd="url(#a-amber)"/>
              {/* nodes */}
              {NODES.map(n=>(
                <g key={n.id}>
                  <rect x={n.x-80} y={n.y} width={160} height={40} rx={4} fill={n.bg} stroke={n.border} strokeWidth={n.id==='ec2'||n.id==='s3'?1.5:1}/>
                  <text x={n.x} y={n.y+16} fill={n.color} fontFamily="'JetBrains Mono',monospace" fontSize={9} textAnchor="middle" fontWeight="700">{n.label}</text>
                  <text x={n.x} y={n.y+30} fill={n.color==='#00d4ff'?'#2a5a7a':n.color==='#ff4040'?'#7a2a2a':'#6a5000'} fontFamily="'JetBrains Mono',monospace" fontSize={8} textAnchor="middle">{n.sub}</text>
                </g>
              ))}
              {/* attacker dot */}
              <circle cx={dotPos.x} cy={dotPos.y} r={4} fill="#ff4040" opacity={0.9}/>
              <circle cx={dotPos.x} cy={dotPos.y} r={8} fill="none" stroke="#ff4040" strokeWidth={0.5} opacity={0.4}/>
            </svg>
          </motion.div>

          {/* Metrics panel */}
          <motion.div initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ duration: 0.4, delay: 0.3 }}
            style={{ background: '#080d14', borderLeft: '1px solid #0f2030', padding: 12, display: 'flex', flexDirection: 'column', gap: 8, overflow: 'hidden' }}>
            <div style={{ fontSize: 9, color: '#2a4a6a', letterSpacing: 1, marginBottom: 2 }}>THREAT METRICS</div>
            {[
              { label: 'CRITICAL ALERTS', value: String(crits), color: '#ff4040', sub: '↑ last hour' },
              { label: 'RISK SCORE', value: String(risk), color: '#ffaa00', sub: 'HIGH SEVERITY' },
              { label: 'ASSETS MONITORED', value: '14', color: '#00d4ff', sub: 'ap-south-1' },
            ].map(m=>(
              <div key={m.label} style={{ background: '#0a1520', border: '1px solid #0f2030', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 9, color: '#4a6a8a', letterSpacing: 1, marginBottom: 4 }}>{m.label}</div>
                <div style={{ fontSize: 22, fontWeight: 700, color: m.color }}>{m.value}</div>
                <div style={{ fontSize: 9, color: '#4a6a8a', marginTop: 2 }}>{m.sub}</div>
              </div>
            ))}
          </motion.div>

          {/* Terminal */}
          <motion.div initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ duration: 0.4, delay: 0.4 }}
            style={{ gridColumn: '1/3', background: '#040709', borderTop: '1px solid #0f2030', padding: '10px 14px', overflowY: 'auto' }} ref={logRef}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, paddingBottom: 6, borderBottom: '1px solid #0f2030' }}>
              <svg width="10" height="10" viewBox="0 0 10 10"><rect width="10" height="10" rx="2" fill="none" stroke="#4a6a8a" strokeWidth="1"/><path d="M2 3l2 2-2 2M5 7h3" stroke="#4a6a8a" strokeWidth="1" strokeLinecap="round"/></svg>
              <span style={{ fontSize: 10, color: '#4a6a8a', letterSpacing: 1 }}>AUTONOMOUS ENGINE FEED</span>
            </div>
            <AnimatePresence>
              {logs.map((l, i) => (
                <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.3 }}
                  style={{ fontSize: 10, lineHeight: 1.8, color: LOG_COLORS[l.type] }}>
                  {l.ts} {l.msg}
                </motion.div>
              ))}
            </AnimatePresence>
            {logs.length > 0 && (
              <motion.span animate={{ opacity: [1, 0, 1] }} transition={{ repeat: Infinity, duration: 1 }}
                style={{ display: 'inline-block', width: 6, height: 11, background: '#00d4ff', verticalAlign: 'middle', marginLeft: 2 }}/>
            )}
          </motion.div>

        </div>
      </div>
    </div>
  );
}
