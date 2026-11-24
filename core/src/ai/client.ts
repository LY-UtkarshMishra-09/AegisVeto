import OpenAI from 'openai';
import path from 'node:path';
import fs from 'node:fs';
import dotenv from 'dotenv';
import { getDb } from '../db/schema.js';

function findRepoRoot(): string {
  let curr = process.cwd();
  while (curr !== path.dirname(curr)) {
    if (fs.existsSync(path.join(curr, 'policy.yaml'))) return curr;
    curr = path.dirname(curr);
  }
  return process.cwd();
}

dotenv.config({ path: path.join(findRepoRoot(), '.env') });
dotenv.config();

export type LLMProvider = 'ollama' | 'groq';

export interface Layer2Config {
  provider: LLMProvider;
  baseURL: string;
  apiKey: string;
  model: string;
}

export function getLayer2Config(): Layer2Config {
  let provider: LLMProvider = (process.env.LLM_PROVIDER as LLMProvider) || 'groq';
  let baseURL = 'https://api.groq.com/openai/v1';
  let apiKey = process.env.GROQ_API_KEY || 'dummy_groq_key';
  let model = process.env.GROQ_FAST_MODEL || process.env.GROQ_MODEL || 'llama-3.1-8b-instant';

  try {
    const db = getDb();
    const row = db
      .prepare("SELECT value_json FROM service_settings WHERE key = 'layer2_provider'")
      .get() as { value_json: string } | undefined;

    if (row?.value_json) {
      const parsed = JSON.parse(row.value_json);
      if (parsed.provider === 'ollama') {
        provider = 'ollama';
        const url = parsed.ollamaUrl || process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
        baseURL = url.endsWith('/v1') ? url : `${url.replace(/\/+$/, '')}/v1`;
        apiKey = 'ollama';
        model = parsed.ollamaModel || process.env.OLLAMA_MODEL || 'qwen2.5:7b';
      } else if (parsed.provider === 'groq') {
        provider = 'groq';
        baseURL = 'https://api.groq.com/openai/v1';
        apiKey = parsed.apiKey || process.env.GROQ_API_KEY || 'dummy_groq_key';
        model = parsed.groqModel || process.env.GROQ_FAST_MODEL || process.env.GROQ_MODEL || 'llama-3.1-8b-instant';
      }
    }
  } catch {
    // Non-blocking fallback to env
  }

  return { provider, baseURL, apiKey, model };
}

export function getLayer2Client(): { client: OpenAI; model: string; provider: LLMProvider } {
  const cfg = getLayer2Config();
  const client = new OpenAI({
    baseURL: cfg.baseURL,
    apiKey: cfg.apiKey,
    timeout: 4000, // Safe fast timeout: background analysis never hangs indefinitely
  });

  return {
    client,
    model: cfg.model,
    provider: cfg.provider,
  };
}
