import fs from 'node:fs';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

const repoRoot = findRepoRoot();
const publicIssuePath = path.join(repoRoot, 'sandbox', 'public_issue.txt');

async function main() {
  const server = new Server({
    name: 'mock-comms-server',
    version: '1.0.0',
  });

  server.registerCapabilities({
    tools: { listChanged: true },
  });

  server.setRequestHandler('tools/list', async () => {
    return {
      tools: [
        {
          name: 'read_public_issue',
          description: 'Reads public issue file from sandbox',
          inputSchema: {
            type: 'object',
            properties: {} as Record<string, any>,
          },
        },
        {
          name: 'send_external_email',
          description: 'Sends external email payload',
          inputSchema: {
            type: 'object',
            properties: {
              to: { type: 'string' },
              body: { type: 'string' },
            } as Record<string, any>,
            required: ['to', 'body'],
          },
        },
      ],
    };
  });

  server.setRequestHandler('tools/call', async (request: any) => {
    const { name, arguments: args = {} } = request.params || {};

    if (name === 'read_public_issue') {
      const content = fs.existsSync(publicIssuePath)
        ? fs.readFileSync(publicIssuePath, 'utf-8')
        : 'Mock public issue content';
      return {
        content: [{ type: 'text', text: content }],
      };
    }

    if (name === 'send_external_email') {
      const to = String(args.to || '');
      const body = String(args.body || '');
      // Log payload locally, never send real mail
      console.error(`[MOCK COMMS SERVER] Email queued to ${to}: ${body.slice(0, 50)}...`);
      return {
        content: [{ type: 'text', text: `Email successfully queued to ${to}` }],
      };
    }

    const err = new Error(`Unknown tool: ${name}`);
    (err as any).code = -32601;
    throw err;
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('[MOCK COMMS SERVER] Fatal error:', err);
  process.exit(1);
});
