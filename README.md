# AegisVeto

Zero-Trust Security Gateway and Active Defense Layer for Autonomous AI Agents and Model Context Protocol (MCP).

---

## Executive Summary

AegisVeto is an enterprise self-hosted security gateway that mediates tool invocations between autonomous AI agents and upstream execution environments (Model Context Protocol servers, APIs, and host systems).

The system enforces a strict separation of concerns across two planes:

1. **Data Plane (Sub-10ms Deterministic Path):** 100% deterministic Layer 1 policy engine executing zero LLM evaluations in the critical hot path. Enforces Ed25519 cryptographic token verification, canonical path resolution, a formal Taint Lattice (`CLEAN -> TAINTED -> TERMINATED`), SHA-256 tool-schema pinning, canary leak scanning, honeypot decoy traps, and fail-closed execution. Operates in per-agent `enforce` or `shadow` modes.
2. **Control Plane (Asynchronous Management Path):** Provides immutable SQLite WAL audit logging, versioned policy rollouts, human-in-the-loop quarantine approvals with SLA timeouts, outbound webhook alerting, and optional Layer 2 background semantic intent analysis powered by Ollama (local/air-gapped) or Groq (cloud).

---

## System Architecture

```
                       +-----------------------------+
                       |    Autonomous AI Agent      |
                       +--------------+--------------+
                                      |
                                      | Scoped Ed25519 JWT
                                      v
+===========================================================================+
|                         AEGISVETO DATA PLANE                              |
|---------------------------------------------------------------------------|
| 1. Ed25519 Token & Scope Verification                                     |
| 2. Agent Authorization & Posture Check ('enforce' vs 'shadow')            |
| 3. Taint Lattice Resolution (State: CLEAN / TAINTED / TERMINATED)         |
| 4. SHA-256 Cryptographic Tool-Schema Integrity Check                      |
| 5. Critical Tripwires: Decoy Invocation & Recursive Canary Scanner        |
| 6. Canonical Path Resolution (Blocks traversal, .env*, .ssh, .git)        |
| 7. Taint Propagation & Egress Lockout (Dynamic Capability Revocation)     |
| 8. Quarantine Engine (SLA Timeout Gate)                                   |
| 9. Upstream Credential Injection (process.env AEGIS_VAULT_*)              |
+======================+=============================+======================+
                       |                             |
         Verified Tool | Call           Quarantine / | Telemetry / SSE
                       v                             v
+-----------------------------+     +---------------------------------------+
| Upstream MCP / Tool Server  |     |        AEGISVETO CONTROL PLANE        |
| (Filesystem, Comms, APIs)   |     |---------------------------------------|
|                             |     | SQLite WAL Audit Ledger               |
| Dynamic Revocation:         |     | Versioned Policy Rollout Engine       |
| notifications/              |     | SLA Auto-Deny Sweeper (Every 5s)      |
|   tools/list_changed        |     | Layer 2 AI Verifier (Ollama / Groq)   |
|                             |     | Outbound Webhooks (Slack / Discord)   |
+-----------------------------+     +---------------------------------------+
```

---

## Core Capabilities

### 1. Layer 1 Deterministic Enforcement (Sub-10ms Hot Path)
- **Zero-LLM Guardrail Loop:** All authorization checks in the execution hot path are bitwise, synchronous, and complete in under 10 milliseconds (typical latency: 1-3 ms).
- **Canonical Path Protection:** Normalizes file paths and prevents directory traversal attacks (`../`), blocking access to protected environment files (`.env*`), SSH keys (`.ssh/**`), Git configurations (`.git/config`), and host roots.
- **Enforcement Modes:** Per-agent configurable posture:
  - `enforce`: Hard block or quarantine on policy violation.
  - `shadow`: Records audit telemetry and emits `SHADOW_DENY` without interrupting agent execution, enabling pre-production policy verification.
- **Fail-Closed Guarantee:** Any configuration syntax error, missing policy, or unverified JWT automatically defaults to `DENY` for all mutating and egress actions.

### 2. Taint Lattice and Dynamic Capability Revocation
- **Formal State Machine:** Sessions progress unidirectionally through `CLEAN -> TAINTED -> TERMINATED`.
- **Untrusted Ingestion:** Calling an untrusted tool (e.g., scraping an issue description or untrusted web content) transitions the session state from `CLEAN` to `TAINTED`.
- **Dynamic Capability Revocation:** Upon entering `TAINTED`, all tools categorized as `class: egress` are stripped from downstream `tools/list` payloads, and an MCP `notifications/tools/list_changed` notification is pushed to the client. Any subsequent direct call to an egress sink triggers a `TAINT_EGRESS_DENY`.

### 3. Active Defenses
- **Cryptographic Tool-Schema Pinning (Anti-Rug-Pull):** Upstream tool declarations (`name`, `description`, `inputSchema`, `annotations`) are canonicalized and pinned using SHA-256 hashes on first contact. If an upstream mutates descriptions or schemas mid-session to inject hidden prompts, execution is blocked with `SCHEMA_DRIFT` until an operator approves the new hash.
- **Decoy Honeypot Traps:** Injects a synthetic administrative tool (default: `export_admin_secrets`) into proxied tool lists. Any invocation immediately marks the session `TERMINATED`, blocks execution, and logs `CRITICAL_TRIPWIRE`.
- **Recursive Canary Token Scanner:** Recursively inspects outbound payload arguments across nested objects and arrays, testing for raw, URL-encoded, and Base64-encoded forms of configured canary tokens (e.g., `aegis_canary_9921`). Any detected leak triggers `CRITICAL_TRIPWIRE` and terminates the session.
- **Credential Vault Isolation:** Upstream credentials remain mapped through `AEGIS_VAULT_*` environment variables. Agents never receive raw upstream secrets; credentials are injected only after Layer 1 verification succeeds.

### 4. Layer 2 Asynchronous AI Intelligence (Control Plane)
- **Semantic Intent Verification:** When a tool call is quarantined, Layer 1 responds in `<10ms` and writes a pending quarantine item. An asynchronous background task analyzes intent using Ollama or Groq, outputting `{ risk_score, hijacked, summary }` and broadcasting live updates over Server-Sent Events (SSE).
- **Fail-Closed SLA Timeout Sweeper:** A background interval runs every 5 seconds. If a quarantined item exceeds its configured SLA window without human operator resolution, it is marked `expired` (fail-closed) and an audit log event is recorded.
- **Policy Auto-Patcher:** The `/v1/policies/suggest` endpoint analyzes quarantined arguments and generates a minimal valid YAML policy rule snippet that can be applied directly to `policy.yaml` as a new versioned rollout.

---

## Repository Structure

```
AegisVeto/
├── core/                           # TypeScript backend, Layer 1 engine, and MCP proxy
│   ├── src/
│   │   ├── agent/                  # Agent runner harness
│   │   ├── ai/                     # Layer 2 client, intent verifier, auto-patcher
│   │   ├── alerts/                 # Outbound Slack/Discord webhook dispatcher
│   │   ├── auth/                   # Ed25519 token issuance and verification
│   │   ├── db/                     # SQLite schema (WAL mode) and repository methods
│   │   ├── engine/                 # Layer 1 deterministic policy evaluator
│   │   ├── mcp/                    # CLI stdio proxy, HTTP gateway, mock servers
│   │   ├── sdk/                    # In-process TypeScript SDK Guard
│   │   ├── security/               # Schema pinning and tripwire scanners
│   │   ├── vault/                  # Upstream secret resolver (AEGIS_VAULT_*)
│   │   └── index.ts                # Control Plane HTTP/SSE REST API
│   ├── package.json
│   └── tsconfig.json
├── dashboard/                      # Production React/Vite Control Console (Pitch Black)
│   ├── src/
│   │   ├── views/                  # Overview, AuditStream, Approvals, Inventory, Policies, Settings
│   │   ├── App.tsx                 # Hash router and SSE connection manager
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── sandbox/                        # Local containment target for verification
│   ├── .env                        # Local sandbox secrets
│   ├── public_issue.txt            # Untrusted fixture payload
│   └── README.md
├── scripts/                        # Ops, verification, and benchmark runners
│   ├── dev.mjs                     # Single-command concurrent launcher
│   ├── test-dataplane.ts           # Data plane integration suite
│   ├── test-defenses.ts            # Anti-rug-pull and tripwire test suite
│   ├── verify-service.ts           # 6-step end-to-end service verification suite
│   └── run-evals.ts                # Red-team benchmark suite
├── aegisveto_audit.db              # SQLite WAL audit database (generated on boot)
├── Dockerfile                      # Multi-stage production container
├── policy.yaml                     # Root deterministic policy definition
├── requirements.txt                # Python client and benchmark dependencies
└── .env.example                    # Environment configuration template
```

---

## Quick Start

### Prerequisites
- Node.js 20 LTS or Node.js 22+
- npm 10+
- Optional: Local Ollama instance (`http://localhost:11434`) or Groq API Key (for Layer 2 semantic intent analysis)

### Installation

Clone the repository and install dependencies:

```bash
# Install core dependencies
cd core
npm install

# Install dashboard dependencies
cd ../dashboard
npm install

# Return to root
cd ..
```

### Environment Configuration

Copy the template and configure local settings:

```bash
cp .env.example .env
```

Example configuration (`.env`):

```ini
PORT=3000
NODE_ENV=development

# Layer 2 AI Provider ('ollama' or 'groq')
LLM_PROVIDER=ollama

# Ollama Settings
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen2.5:7b

# Groq Settings (when LLM_PROVIDER=groq)
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_FAST_MODEL=llama-3.1-8b-instant

# Vault Credential Mapping Prefix: AEGIS_VAULT_<REF>
# AEGIS_VAULT_GITHUB_TOKEN=ghp_example
# AEGIS_VAULT_COMMS_TOKEN=comms_secret

# Outbound Alert Webhook (Slack / Discord / Generic)
# AEGIS_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Running Locally

Start both the Core Gateway (`http://localhost:3000`) and the Control Console (`http://localhost:5173`) using the zero-dependency concurrent launcher:

```bash
node scripts/dev.mjs
```

### Docker Deployment

Build and run the multi-stage production container:

```bash
# Build production image
docker build -t aegisveto:latest .

# Run with persistent storage volumes
docker run -d \
  -p 3000:3000 \
  -v $(pwd)/aegisveto_audit.db:/app/aegisveto_audit.db \
  -v $(pwd)/policy.yaml:/app/policy.yaml \
  --name aegisveto \
  aegisveto:latest
```

---

## Integration Surfaces

### 1. CLI Stdio MCP Proxy
Wraps any Model Context Protocol stdio server with deterministic Layer 1 enforcement, dynamic capability revocation, and Vault secret injection:

```bash
node core/node_modules/tsx/dist/cli.mjs core/src/mcp/proxy.ts \
  --agent local-dev-agent \
  --upstream local-filesystem \
  -- node core/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js ./sandbox
```

### 2. Streamable HTTP MCP Reverse Proxy
Mounted on `ALL /v1/mcp/:upstreamId`. Handles HTTP JSON-RPC MCP requests, validates authorization bearer tokens against agent scopes, enforces Layer 1 policies, and injects upstream Vault headers before forwarding:

```bash
curl -X POST http://localhost:3000/v1/mcp/local-filesystem \
  -H "Authorization: Bearer <AGENT_ED25519_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": { "path": "sandbox/README.md" }
    }
  }'
```

### 3. In-Process TypeScript SDK Guard
Protects internal tool executors directly inside host agent processes without requiring subprocess IPC:

```typescript
import { createAegisGuard } from './core/src/sdk/guard.js';

const guard = createAegisGuard({
  agentId: 'local-dev-agent',
  mode: 'enforce',
});

const result = await guard.execute('read_file', { path: 'sandbox/README.md' }, async (args) => {
  // Underlying tool execution logic
  return { content: 'file content' };
});
```

---

## Policy Configuration (`policy.yaml`)

```yaml
version: "2026-03"

identity:
  token_algorithm: "EdDSA"
  issuer: "aegisveto.security.local"
  max_session_ttl_sec: 900

path_protection:
  deny_patterns:
    - "**/.env*"
    - "**/.ssh/**"
    - "**/.git/config"
    - "../"
  sandbox_root: "./sandbox"

tools:
  read_file:
    action: allow
    trust: trusted
    deny_paths:
      - "**/.env*"
      - "**/.ssh/**"
      - "**/.git/config"

  read_public_issue:
    action: allow
    trust: untrusted

  send_external_email:
    action: require_approval
    class: egress

  http_post_webhook:
    action: require_approval
    class: egress

  bash_exec:
    action: quarantine
    trust: trusted
    quarantine_patterns:
      - "rm\\s+-rf"
      - "sudo"
      - "chmod\\s+777"
      - "curl.*\\|.*bash"

taint_engine:
  propagation: session
  sink_action_when_tainted: DENY
  egress_tools:
    - send_external_email
    - http_post_webhook
    - curl_upload
```

---

## Control Plane API

All administrative and runtime control endpoints are served over `http://localhost:3000`:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/v1/overview` | `GET` | Aggregated telemetry: 24h call volume, blocks, active agents, p95 latency. |
| `/v1/events` | `GET` | Filterable audit log stream (by agentId, verdict, taint, or search). |
| `/v1/events/stream` | `GET` | Live Server-Sent Events (SSE) broadcast channel. |
| `/v1/evaluate` | `POST` | Primary Layer 1 deterministic policy evaluation endpoint (<10ms). |
| `/v1/agents` | `GET` | Lists all registered agents and enforcement postures. |
| `/v1/agents` | `POST` | Registers a new agent (`enforce` or `shadow` mode, allowed upstreams). |
| `/v1/agents/:id` | `PATCH` | Updates an agent's mode, status (`active`/`revoked`), or allowed upstreams. |
| `/v1/agents/:id/tokens` | `POST` | Mints a scoped Ed25519 JWT with call limit and TTL. |
| `/v1/upstreams` | `GET` | Lists registered MCP/tool upstreams and trust tiers. |
| `/v1/upstreams` | `POST` | Registers a new upstream with transport type and Vault secret ref. |
| `/v1/upstreams/:id` | `DELETE` | Deletes an upstream and its associated schema pins. |
| `/v1/upstreams/:id/pins` | `GET` | Retrieves pinned SHA-256 tool schemas and detected drift diffs. |
| `/v1/upstreams/:id/pins/:pinId/approve` | `POST` | Approves mutated schema, updates pinned hash, and clears drift. |
| `/v1/policies/active` | `GET` | Retrieves the active policy version and parsed configuration. |
| `/v1/policies/active` | `PUT` | Rolls out a new active policy version and writes to `policy.yaml`. |
| `/v1/policies/versions` | `GET` | Lists all immutable policy rollout versions. |
| `/v1/policies/simulate` | `POST` | Dry-run policy simulation without updating audit log or session state. |
| `/v1/policies/suggest` | `POST` | Layer 2 AI auto-patcher generating minimal YAML rules from violations. |
| `/v1/approvals` | `GET` | Lists pending human-in-the-loop quarantine items and AI assessments. |
| `/v1/approvals/:id/resolve` | `POST` | Resolves a quarantine item (`approve` once or `veto`). |
| `/v1/settings` | `GET` | Retrieves active service settings (canaries, decoy, SLA, provider). |
| `/v1/settings` | `PUT` | Updates service configuration in SQLite `service_settings`. |
| `/v1/settings/test-webhook` | `POST` | Dispatches a test alert ping to the configured webhook URL. |
| `/v1/mcp/:upstreamId/*` | `ALL` | Reverse proxy routing for Model Context Protocol HTTP transports. |
| `/health` | `GET` | Service liveness and engine status probe. |
| `/policy` | `GET` | Raw active `policy.yaml` text. |

---

## Verification and Security Model

### Verification Suites
Run the test suites using Node.js and TypeScript:

```bash
# End-to-end service verification (6/6 checks)
node core/node_modules/tsx/dist/cli.mjs scripts/verify-service.ts

# Active defense suite (schema pinning, tripwires, canary scanner)
node core/node_modules/tsx/dist/cli.mjs scripts/test-defenses.ts

# Data plane integration suite (CLI stdio proxy, taint lattice, SDK guard)
node core/node_modules/tsx/dist/cli.mjs scripts/test-dataplane.ts
```

### Security Invariants
1. **Fail-Closed Guarantee:** If policies are invalid, tokens expire, or dependencies fail, the gateway denies execution.
2. **Tamper-Evident Ledger:** Audit logs are persisted to `aegisveto_audit.db` using SQLite in Write-Ahead Logging (WAL) mode with synchronous checkpoints.
3. **Least-Privilege Token Model:** Agents authenticate using asymmetric Ed25519 tokens carrying fine-grained tool scopes and hard call limits.
4. **Zero-Trust Egress Isolation:** Once untrusted content touches a session, downstream network sinks are blocked deterministically.

---

## Authors and Maintainers

- Utkarsh Mishra (Lead Architecture & Core Engine)
- [Contributor Name / GitHub Handle]
- [Contributor Name / GitHub Handle]

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
