export interface AegisGuardConfig {
  baseUrl?: string;
  agentToken?: string;
  agentId?: string;
}

export interface GuardExecutionResult<T> {
  allowed: boolean;
  verdict: string;
  ruleMatched?: string;
  latencyMs?: number;
  result?: T;
  reason?: string;
  shadow?: boolean;
}

/**
 * Lightweight In-Process SDK Guard for native AI agent code (Groq/Ollama/OpenAI)
 * Intercepts tool calls deterministically via AegisVeto Control Plane before dispatching.
 */
export function createAegisGuard(config: AegisGuardConfig = {}) {
  const baseUrl = (config.baseUrl || 'http://localhost:3000').replace(/\/$/, '');
  const agentToken = config.agentToken;
  const agentId = config.agentId || 'local-dev-agent';

  return {
    async guardToolCall<T>(
      sessionId: string,
      toolName: string,
      args: Record<string, unknown> = {},
      executor: () => Promise<T>
    ): Promise<GuardExecutionResult<T>> {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (agentToken) {
        headers['Authorization'] = `Bearer ${agentToken}`;
      }

      let evalData: {
        allowed: boolean;
        verdict: string;
        shadow?: boolean;
        ruleMatched?: string;
        latencyMs?: number;
        reason?: string;
      };

      try {
        const response = await fetch(`${baseUrl}/v1/evaluate`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            token: agentToken,
            agentId,
            sessionId,
            toolName,
            args,
          }),
        });

        if (!response.ok) {
          const errBody = (await response.json().catch(() => ({}))) as any;
          return {
            allowed: false,
            verdict: errBody.verdict || 'DENY',
            ruleMatched: errBody.ruleMatched || 'EVALUATION_REJECTED',
            reason: errBody.reason || `Gateway returned HTTP ${response.status}`,
          };
        }

        evalData = (await response.json()) as {
          allowed: boolean;
          verdict: string;
          shadow?: boolean;
          ruleMatched?: string;
          latencyMs?: number;
          reason?: string;
        };
      } catch (networkErr) {
        // Fail closed if gateway is unreachable
        return {
          allowed: false,
          verdict: 'DENY',
          ruleMatched: 'GATEWAY_UNREACHABLE_FAIL_CLOSED',
          reason: `AegisVeto gateway unreachable: ${networkErr instanceof Error ? networkErr.message : String(networkErr)}`,
        };
      }

      // If allowed (including allowed under shadow mode)
      if (evalData.allowed) {
        const result = await executor();
        return {
          allowed: true,
          verdict: evalData.verdict,
          ruleMatched: evalData.ruleMatched,
          latencyMs: evalData.latencyMs,
          shadow: evalData.shadow,
          result,
        };
      }

      // Blocked by policy gate
      return {
        allowed: false,
        verdict: evalData.verdict,
        ruleMatched: evalData.ruleMatched,
        latencyMs: evalData.latencyMs,
        reason: evalData.reason,
      };
    },
  };
}
