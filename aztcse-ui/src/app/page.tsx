"use client";
import { useState } from "react";

const modules = [
  { id: "attack", label: "Attack Surface", emoji: "🎯" },
  { id: "ai", label: "AI Simulation", emoji: "🤖" },
  { id: "forensics", label: "Forensics", emoji: "🔍" },
  { id: "zerotrust", label: "Zero Trust", emoji: "🔐" },
  { id: "honeypot", label: "Honeypot", emoji: "🍯" },
];

const content = {
  attack: {
    title: "Attack Surface Analyzer",
    description: "Maps all exposed endpoints, open ports, and vulnerable services across the banking infrastructure. Identifies lateral movement paths and prioritizes remediation.",
    status: "3 Critical Findings",
    metrics: [72, 89, 94],
  },
  ai: {
    title: "AI Threat Simulation",
    description: "Simulates AI-driven cyberattacks including adaptive phishing, credential stuffing, and automated exploit chains targeting financial systems.",
    status: "Simulation Running",
    metrics: [85, 76, 91],
  },
  forensics: {
    title: "Digital Forensics",
    description: "Analyzes attack artifacts, reconstructs timelines of incidents, and extracts indicators of compromise from banking transaction logs and network captures.",
    status: "2 Incidents Logged",
    metrics: [67, 93, 88],
  },
  zerotrust: {
    title: "Zero Trust Architecture",
    description: "Enforces least-privilege access, continuous verification, and micro-segmentation across all internal banking services and API gateways.",
    status: "Policy Active",
    metrics: [95, 87, 99],
  },
  honeypot: {
    title: "Honeypot Network",
    description: "Deploys decoy banking assets to detect, trap, and analyze attacker behavior. Feeds threat intelligence back into the defense simulation.",
    status: "4 Traps Active",
    metrics: [78, 82, 90],
  },
};

export default function Home() {
  const [active, setActive] = useState("attack");
  const mod = content[active as keyof typeof content];

  return (
    <main style={{ minHeight: "100vh", background: "#0a0f1e", color: "#e2e8f0", fontFamily: "monospace" }}>
      <div style={{ background: "#0d1b2a", borderBottom: "1px solid #1e3a5f", padding: "20px 32px" }}>
        <h1 style={{ margin: 0, fontSize: "22px", color: "#38bdf8", letterSpacing: "2px" }}>
          🏦 CYBERWAR BANKING DEFENSE — PROJECT 1A
        </h1>
        <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#64748b" }}>
          AZTCSE Defense Simulation Dashboard
        </p>
      </div>

      <div style={{ display: "flex", height: "calc(100vh - 73px)" }}>
        <div style={{ width: "220px", background: "#0d1b2a", borderRight: "1px solid #1e3a5f", padding: "24px 0" }}>
          {modules.map((m) => (
            <button
              key={m.id}
              onClick={() => setActive(m.id)}
              style={{
                display: "block", width: "100%", textAlign: "left",
                padding: "12px 24px", border: "none", cursor: "pointer",
                background: active === m.id ? "#1e3a5f" : "transparent",
                color: active === m.id ? "#38bdf8" : "#94a3b8",
                borderLeft: active === m.id ? "3px solid #38bdf8" : "3px solid transparent",
                fontSize: "13px", fontFamily: "monospace",
              }}
            >
              {m.emoji} {m.label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, padding: "40px" }}>
          <div style={{ background: "#0d1b2a", border: "1px solid #1e3a5f", borderRadius: "8px", padding: "32px", maxWidth: "700px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ margin: 0, color: "#38bdf8", fontSize: "18px" }}>{mod.title}</h2>
              <span style={{ background: "#1e3a5f", color: "#7dd3fc", padding: "4px 12px", borderRadius: "20px", fontSize: "11px" }}>
                {mod.status}
              </span>
            </div>
            <p style={{ color: "#94a3b8", lineHeight: "1.8", fontSize: "14px" }}>{mod.description}</p>

            <div style={{ marginTop: "24px" }}>
              {["Threat Level", "Defense Coverage", "Response Time"].map((label, i) => (
                <div key={label} style={{ marginBottom: "14px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "#64748b", marginBottom: "4px" }}>
                    <span>{label}</span>
                    <span>{mod.metrics[i]}%</span>
                  </div>
                  <div style={{ background: "#1e293b", borderRadius: "4px", height: "6px" }}>
                    <div style={{ background: "#38bdf8", width: `${mod.metrics[i]}%`, height: "6px", borderRadius: "4px" }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
