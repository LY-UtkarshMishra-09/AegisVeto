import path from 'node:path';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { z } from 'zod';
import { getLayer2Client, LLMProvider } from './client.js';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

export interface PolicyPatchParams {
  toolName: string;
  args?: Record<string, unknown>;
  reason?: string;
  currentPolicyYaml?: string;
  provider?: LLMProvider;
}

export interface PolicyPatchSuggestion {
  suggestedYaml: string;
  explanation: string;
}

export async function suggestPolicyRule(params: PolicyPatchParams): Promise<PolicyPatchSuggestion> {
  const { client, model } = getLayer2Client();
  const args = params.args || {};

  const prompt = `You are AegisVeto's Layer 2 Policy Auto-Patcher ("Learn Once, Enforce Forever").
An operator intercepted an unsafe or malicious tool invocation:
Tool Name: ${params.toolName}
Arguments: ${JSON.stringify(args)}
Reason: ${params.reason || 'Flagged by operator as hazardous'}

Generate a minimal, valid policy rule snippet in YAML for AegisVeto's policy.yaml that will deterministically block or restrict this pattern in Layer 1.
Valid policy sections include:
- tools.<toolName>.action: deny or require_approval
- tools.<toolName>.deny_paths: list of glob patterns (for file tools)
- tools.<toolName>.quarantine_patterns: list of regexes (for shell tools)
- taint_engine.egress_tools: add tool name if it is an egress sink

Respond with ONLY valid JSON with this exact shape:
{
  "suggestedYaml": "<clean YAML rule snippet>",
  "explanation": "<1-2 sentence explanation of how this rule permanently blocks the threat>"
}`;

  try {
    const completion = await client.chat.completions.create({
      model,
      messages: [
        { role: 'system', content: 'You are an automated YAML security policy generator. Output valid JSON only.' },
        { role: 'user', content: prompt },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.1,
    });

    const content = completion.choices[0]?.message?.content;
    if (content) {
      const parsed = JSON.parse(content);
      if (parsed.suggestedYaml && parsed.explanation) {
        return {
          suggestedYaml: parsed.suggestedYaml.trim(),
          explanation: parsed.explanation.trim(),
        };
      }
    }
  } catch (err) {
    console.warn(
      '[AegisVeto L2 Patcher] Provider call failed, using deterministic fallback:',
      err instanceof Error ? err.message : err
    );
  }

  // Deterministic fallback generator
  const argsStr = JSON.stringify(args);
  if (params.toolName === 'send_external_email' || /email/i.test(params.toolName)) {
    const to = typeof args.to === 'string' ? args.to : 'attacker@evil.com';
    const domain = to.includes('@') ? to.split('@')[1] : 'evil.com';
    return {
      suggestedYaml: `tools:\n  send_external_email:\n    action: deny\n    class: egress\n    blocked_domains:\n      - "${domain}"`,
      explanation: `Permanently blocks outbound email dispatch to ${domain} and marks ${params.toolName} as a hard-deny egress sink.`,
    };
  }

  if (params.toolName === 'bash_exec' || /rm\s+-rf/i.test(argsStr)) {
    return {
      suggestedYaml: `tools:\n  bash_exec:\n    action: quarantine\n    quarantine_patterns:\n      - "rm\\\\s+-rf"\n      - "tar\\\\s+-[a-z]*z"\n      - "sudo"`,
      explanation: `Adds destructive shell execution patterns to Layer 1 quarantine traps to mandate human approval.`,
    };
  }

  if (params.toolName === 'read_file') {
    const p = typeof args.path === 'string' ? args.path : '*.secret';
    return {
      suggestedYaml: `tools:\n  read_file:\n    deny_paths:\n      - "**/${p}*"`,
      explanation: `Adds '${p}' to deterministic path protection blacklist, preventing all future read attempts.`,
    };
  }

  return {
    suggestedYaml: `tools:\n  ${params.toolName}:\n    action: require_approval\n    class: egress`,
    explanation: `Restricts '${params.toolName}' to require human operator approval for all subsequent invocations.`,
  };
}

// Validation schema for applying policy updates
const PolicyValidationSchema = z.object({
  version: z.string().optional(),
  identity: z.record(z.unknown()).optional(),
  path_protection: z.record(z.unknown()).optional(),
  tools: z.record(z.unknown()).optional(),
  taint_engine: z.record(z.unknown()).optional(),
  policy_rules: z.array(z.unknown()).optional(),
});

export function validateAndApplyPolicy(newYamlContent: string): { success: boolean; error?: string } {
  try {
    const parsed = yaml.load(newYamlContent);
    if (!parsed || typeof parsed !== 'object') {
      return { success: false, error: 'Parsed YAML is not an object.' };
    }

    const check = PolicyValidationSchema.safeParse(parsed);
    if (!check.success) {
      return { success: false, error: `Invalid policy structure: ${check.error.message}` };
    }

    const repoRoot = findRepoRoot();
    const policyPath = path.join(repoRoot, 'policy.yaml');
    fs.writeFileSync(policyPath, newYamlContent, 'utf-8');
    return { success: true };
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : String(err) };
  }
}
