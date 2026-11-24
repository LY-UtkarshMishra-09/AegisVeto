#!/usr/bin/env node

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const isWindows = process.platform === 'win32';
const npmCmd = isWindows ? 'npm.cmd' : 'npm';
const npxCmd = isWindows ? 'npx.cmd' : 'npx';

console.log('\n======================================================');
console.log('       🛡️  AegisVeto Full-Stack Dev Launcher          ');
console.log('  Core Proxy: http://localhost:3000                   ');
console.log('  Dashboard:  http://localhost:5173                   ');
console.log('======================================================\n');

function runService(name, color, cwd, command, args) {
  const child = spawn(command, args, {
    cwd,
    stdio: ['inherit', 'pipe', 'pipe'],
    env: { ...process.env, FORCE_COLOR: '1' },
    shell: isWindows,
  });

  const prefix = `${color}[${name}]\x1b[0m `;

  child.stdout?.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) console.log(`${prefix}${line}`);
    }
  });

  child.stderr?.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) console.error(`${prefix}${line}`);
    }
  });

  child.on('close', (code) => {
    console.log(`${prefix}process exited with code ${code}`);
  });

  return child;
}

// Start Core backend (port 3000)
const coreProcess = runService(
  'CORE-PROXY',
  '\x1b[36m', // Cyan
  path.join(rootDir, 'core'),
  npmCmd,
  ['run', 'dev']
);

// Start Dashboard frontend (port 5173)
const dashboardProcess = runService(
  'DASHBOARD',
  '\x1b[32m', // Green
  path.join(rootDir, 'dashboard'),
  npmCmd,
  ['run', 'dev']
);

function shutdown() {
  console.log('\n[AegisVeto] Shutting down services cleanly...');
  try {
    coreProcess.kill('SIGINT');
  } catch {}
  try {
    dashboardProcess.kill('SIGINT');
  } catch {}
  setTimeout(() => {
    process.exit(0);
  }, 500);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
