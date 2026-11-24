# 🛡️ AegisVeto

> **Deterministic Zero-Trust Security Proxy & Active Defense Layer for Autonomous AI Agents and Model Context Protocol (MCP)**

AegisVeto sits transparently between LLM agents and external tools / MCP servers, enforcing deterministic, bitwise security policies (<10ms, 0 LLM calls in the guardrail loop) alongside active cybersecurity defenses: dynamic capability revocation, cryptographic tool-schema pinning, decoy honeypots, and canary exfiltration traps.

---

## ⚡ Quick Start (One-Command Launcher)

Start both the **Core Security Proxy** (`http://localhost:3000`) and the **React Dashboard** (`http://localhost:5173`) concurrently:

```bash
node scripts/dev.mjs
```

---

## 🔍 Model Context Protocol (MCP) Transparent Proxy

Run any MCP server (e.g. filesystem, comms, GitHub, database) through AegisVeto's Layer 1 Zero-Trust engine and active defense tripwires:

```bash
npx tsx core/src/mcp/proxy.ts --policy ./policy.yaml -- <upstream-command> [args...]
```

### Example: Protect Filesystem MCP Server
```bash
npx tsx core/src/mcp/proxy.ts --policy ./policy.yaml -- node core/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js ./sandbox
```

- **Path Protection:** Automatically blocks access to `.env*`, `.ssh`, `.git/config`, and directory traversal (`../`).
- **Dynamic Capability Revocation:** If an untrusted source tool (e.g., `read_public_issue`) executes, session flips to `TAINTED`, egress tools (`send_external_email`, `http_post_webhook`) are revoked from `tools/list`, and an MCP `notifications/tools/list_changed` notification is emitted.
- **Cryptographic Schema Pinning:** Detects mid-session description or argument schema mutations (`SCHEMA_DRIFT`) and blocks execution.
- **Decoy & Canary Tripwires:** Injects synthetic honeypots (`export_admin_secrets`) and scans outbound payloads for Base64/URL-encoded canary leaks.

---

## 🧪 Red-Team Benchmark & Evals

Run empirical evaluations measuring Attack Block Rate, Benign Pass Rate, False Positive Rate, and Proxy Overhead against reproducible scenarios:

### Fast CI Check (6 Scenarios):
```bash
npx tsx scripts/run-evals.ts --quick
```

### Full Red-Team Benchmark (50 Scenarios):
```bash
npx tsx scripts/run-evals.ts --provider=ollama
# or
npx tsx scripts/run-evals.ts --provider=groq
```

Generates `scripts/evals-report.json` and powers the live `/benchmark` endpoint in the dashboard.

---

## 🏗️ Architecture

```
                 ┌────────────────────────────────┐
                 │       Autonomous AI Agent      │
                 └───────────────┬────────────────┘
                                 │ Tool Calls / MCP JSON-RPC
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                    AEGISVETO SECURITY PROXY                 │
   │  Layer 1: Deterministic Zero-Trust Policy (<10ms, 0 LLM)     │
   │    • EdDSA JWT Verification & Session Call Counter          │
   │    • AST Argument Normalizer & Secret Path Deny Rules       │
   │    • Session Taint Tracker (Taint Lock on Egress)           │
   │  Active Defense Engine:                                     │
   │    • SHA-256 Cryptographic Tool-Schema Pinning              │
   │    • Decoy Honeypots (`export_admin_secrets`)               │
   │    • Recursive Canary Token Exfiltration Traps              │
   │  Layer 2: Async AI Security Brain (Quarantine / Patch Only)  │
   │    • Semantic Intent & Prompt Injection Risk Verifier       │
   │    • One-Click Policy Auto-Patcher ("Learn Once, Enforce")  │
   └─────────────────────────────┬───────────────────────────────┘
                                 │ Proxied Safe Execution
                                 ▼
                 ┌────────────────────────────────┐
                 │   Host Environment / Tools     │
                 │   (MCP Servers / Local Shell)  │
                 └────────────────────────────────┘
```
