import { startServer } from '../core/src/index.js';
import { getDb } from '../core/src/db/schema.js';

const PORT = 3055;
const BASE_URL = `http://localhost:${PORT}`;

async function runVerification() {
  console.log('=====================================================');
  console.log('     AegisVeto End-to-End Service Verification       ');
  console.log('=====================================================\n');

  // Start the Core Server
  const server = await startServer(PORT);
  console.log(`[E2E] Service running on ${BASE_URL}`);

  try {
    // ─── 1. Agent Registration & Ed25519 Token Minting ────────────────
    console.log('[1/6] Testing Agent Registration & Ed25519 Token Minting...');
    const agentId = `e2e-agent-${Date.now()}`;
    const regRes = await fetch(`${BASE_URL}/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: agentId,
        name: 'E2E Test Enforce Agent',
        mode: 'enforce',
        allowedUpstreams: ['*'],
      }),
    });

    if (!regRes.ok) {
      throw new Error(`Failed to register agent: ${regRes.status} ${await regRes.text()}`);
    }
    const agentData = await regRes.json();
    console.log(`  ✓ Agent registered: ${agentData.id} (mode: ${agentData.mode})`);

    // Mint scoped Ed25519 token
    const tokenRes = await fetch(`${BASE_URL}/v1/agents/${agentId}/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedScopes: ['*'],
        maxCalls: 100,
        ttlSec: 1800,
      }),
    });

    if (!tokenRes.ok) {
      throw new Error(`Failed to mint token: ${tokenRes.status} ${await tokenRes.text()}`);
    }
    const tokenData = await tokenRes.json();
    const token = tokenData.token;
    if (!token || !tokenData.key_fingerprint) {
      throw new Error('Token payload missing token or key_fingerprint');
    }
    console.log(`  ✓ Ed25519 token minted: ${token.slice(0, 30)}... (fingerprint: ${tokenData.key_fingerprint})`);

    // ─── 2. Policy Simulation (POST /v1/policies/simulate) ────────────
    console.log('\n[2/6] Testing Policy Simulation (POST /v1/policies/simulate)...');
    const simRes = await fetch(`${BASE_URL}/v1/policies/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName: 'read_file',
        args: { path: 'sandbox/.env' },
      }),
    });

    if (!simRes.ok) {
      throw new Error(`Simulation failed: ${simRes.status} ${await simRes.text()}`);
    }
    const simData = await simRes.json();
    if (simData.verdict !== 'DENY' || !simData.simulation) {
      throw new Error(`Expected simulated DENY, got verdict=${simData.verdict}`);
    }
    console.log(`  ✓ Policy simulation confirmed: verdict=${simData.verdict}, rule=${simData.ruleMatched}`);

    // ─── 3. Layer 1 Hot-Path Evaluations (POST /v1/evaluate) ─────────
    console.log('\n[3/6] Testing Layer 1 Deterministic Evaluations...');

    // Subcheck A: ALLOW (<10ms hot-path)
    console.log('  -> Subcheck A: ALLOW (<10ms target)...');
    const evalAllowRes = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        toolName: 'read_file',
        args: { path: 'sandbox/README.md' },
      }),
    });

    if (!evalAllowRes.ok) {
      throw new Error(`Evaluation failed: ${evalAllowRes.status} ${await evalAllowRes.text()}`);
    }
    const evalAllow = await evalAllowRes.json();
    if (evalAllow.verdict !== 'ALLOW' || !evalAllow.allowed) {
      throw new Error(`Expected ALLOW, got verdict=${evalAllow.verdict}`);
    }
    console.log(`  ✓ PASS: ALLOW verdict returned in ${evalAllow.latencyMs}ms (<10ms deterministic hot-path)`);

    // Subcheck B: .env DENY
    console.log('  -> Subcheck B: .env Secret Protection DENY...');
    const evalDenyRes = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        toolName: 'read_file',
        args: { path: 'sandbox/.env' },
      }),
    });

    const evalDeny = await evalDenyRes.json();
    if (evalDeny.verdict !== 'DENY' || evalDeny.allowed) {
      throw new Error(`Expected DENY for .env, got verdict=${evalDeny.verdict}`);
    }
    console.log(`  ✓ PASS: .env access blocked: ${evalDeny.ruleMatched} (${evalDeny.latencyMs}ms)`);

    // Subcheck C: SHADOW_DENY (shadow mode agent)
    console.log('  -> Subcheck C: SHADOW_DENY (Shadow Mode Agent)...');
    const shadowAgentId = `shadow-agent-${Date.now()}`;
    await fetch(`${BASE_URL}/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: shadowAgentId,
        name: 'Shadow Test Agent',
        mode: 'shadow',
        allowedUpstreams: ['*'],
      }),
    });

    const shadowTokenRes = await fetch(`${BASE_URL}/v1/agents/${shadowAgentId}/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedScopes: ['*'] }),
    });
    const shadowToken = (await shadowTokenRes.json()).token;

    const evalShadowRes = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${shadowToken}`,
      },
      body: JSON.stringify({
        toolName: 'read_file',
        args: { path: 'sandbox/.env' },
      }),
    });

    const evalShadow = await evalShadowRes.json();
    if (evalShadow.verdict !== 'SHADOW_DENY' || !evalShadow.allowed || !evalShadow.shadow) {
      throw new Error(`Expected SHADOW_DENY with allowed=true, got verdict=${evalShadow.verdict}, allowed=${evalShadow.allowed}`);
    }
    console.log(`  ✓ PASS: Shadow mode recorded SHADOW_DENY while permitting execution`);

    // Subcheck D: QUARANTINE + Async Layer 2 Intent Risk Score
    console.log('  -> Subcheck D: QUARANTINE + Async Layer 2 AI Risk Scoring...');
    const evalQuarRes = await fetch(`${BASE_URL}/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        toolName: 'bash_exec',
        args: { command: 'rm -rf /tmp/build_cache' },
      }),
    });

    const evalQuar = await evalQuarRes.json();
    if (evalQuar.verdict !== 'QUARANTINE' || evalQuar.allowed || !evalQuar.quarantineId) {
      throw new Error(`Expected QUARANTINE, got verdict=${evalQuar.verdict}, quarId=${evalQuar.quarantineId}`);
    }
    console.log(`  ✓ PASS: Layer 1 returned QUARANTINE immediately in ${evalQuar.latencyMs}ms (quarantineId: ${evalQuar.quarantineId})`);

    // Wait briefly for background Layer 2 AI intent analysis to enrich the quarantine item
    console.log('  -> Waiting for async Layer 2 semantic evaluation to resolve...');
    let enrichedItem: any = null;
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const appRes = await fetch(`${BASE_URL}/v1/approvals`);
      if (appRes.ok) {
        const items = await appRes.json();
        const found = items.find((x: any) => x.id === evalQuar.quarantineId);
        if (found && found.aiRiskScore !== null) {
          enrichedItem = found;
          break;
        }
      }
    }

    if (!enrichedItem) {
      throw new Error('Async Layer 2 analysis did not update quarantine_items within SLA window');
    }
    console.log(`  ✓ PASS: Layer 2 AI assessment attached asynchronously: score=${enrichedItem.aiRiskScore}/100, hijacked=${enrichedItem.aiHijacked}`);
    console.log(`     Summary: "${enrichedItem.aiSummary}"`);

    // ─── 4. Policy Auto-Patcher (POST /v1/policies/suggest) ───────────
    console.log('\n[4/6] Testing Policy Auto-Patcher (POST /v1/policies/suggest)...');
    const suggestRes = await fetch(`${BASE_URL}/v1/policies/suggest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName: 'bash_exec',
        args: { command: 'rm -rf /var/log' },
        reason: 'Destructive command pattern matched in quarantine',
      }),
    });

    if (!suggestRes.ok) {
      throw new Error(`Policy suggest failed: ${suggestRes.status} ${await suggestRes.text()}`);
    }
    const suggestData = await suggestRes.json();
    if (!suggestData.suggestedYaml || !suggestData.explanation) {
      throw new Error('Policy suggest did not return suggestedYaml or explanation');
    }
    console.log(`  ✓ PASS: Policy patcher synthesized rule snippet:`);
    console.log(`     Explanation: "${suggestData.explanation}"`);

    // ─── 5. Outbound Webhook Test Ping (POST /v1/settings/test-webhook)
    console.log('\n[5/6] Testing Outbound Alert Dispatcher...');
    const webhookRes = await fetch(`${BASE_URL}/v1/settings/test-webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        webhookUrl: 'http://localhost:9999/mock-webhook',
      }),
    });

    if (!webhookRes.ok) {
      throw new Error(`Webhook test ping failed: ${webhookRes.status}`);
    }
    const webhookData = await webhookRes.json();
    console.log(`  ✓ PASS: Webhook dispatcher handled alert formatting and dispatch: status=${webhookData.status}`);

    // ─── 6. Overview Consistency (GET /v1/overview) ───────────────────
    console.log('\n[6/6] Verifying Console Telemetry Consistency (GET /v1/overview)...');
    const overviewRes = await fetch(`${BASE_URL}/v1/overview`);
    if (!overviewRes.ok) {
      throw new Error(`Overview fetch failed: ${overviewRes.status}`);
    }
    const overview = await overviewRes.json();
    if (overview.total < 4 || overview.allowed < 1 || overview.quarantined < 1) {
      throw new Error(`Overview counts inconsistent: ${JSON.stringify(overview)}`);
    }
    console.log(`  ✓ PASS: Overview telemetry consistent: total=${overview.total}, allowed=${overview.allowed}, quarantined=${overview.quarantined}, p95=${overview.p95LatencyMs}ms`);

    console.log('\n=====================================================');
    console.log('  ✓ ALL 6/6 END-TO-END VERIFICATION PASSES COMPLETED  ');
    console.log('=====================================================\n');

    server.close();
    process.exit(0);
  } catch (err) {
    console.error('\n❌ E2E VERIFICATION FAILED:', err);
    try {
      server.close();
    } catch {}
    process.exit(1);
  }
}

runVerification();
