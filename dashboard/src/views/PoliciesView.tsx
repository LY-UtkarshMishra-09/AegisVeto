import React, { useState, useEffect } from 'react';
import { Agent, PolicyVersion } from '../types';
import { FileCode2, Play, CheckCircle2, Save } from 'lucide-react';

interface PoliciesViewProps {
  initialYaml: string;
  initialVersion: number;
  versions: PolicyVersion[];
  agents: Agent[];
  onSavePolicy: (yamlContent: string) => Promise<boolean>;
  insertedSnippet?: string;
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({
  initialYaml,
  initialVersion,
  versions,
  agents,
  onSavePolicy,
  insertedSnippet,
}) => {
  const [yamlContent, setYamlContent] = useState(initialYaml);
  const [selectedVersion, setSelectedVersion] = useState<number>(initialVersion);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Dry-run simulator state
  const [simAgentId, setSimAgentId] = useState<string>(agents[0]?.id || 'local-dev-agent');
  const [simToolName, setSimToolName] = useState<string>('read_file');
  const [simTaint, setSimTaint] = useState<'CLEAN' | 'TAINTED'>('CLEAN');
  const [simArgs, setSimArgs] = useState<string>('{\n  "path": "sandbox/src/index.ts"\n}');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simResult, setSimResult] = useState<{
    verdict: string;
    allowed: boolean;
    latencyMs: number;
    ruleMatched: string;
    reason?: string;
    taintState: string;
  } | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  // Sync initial yaml
  useEffect(() => {
    if (initialYaml) setYamlContent(initialYaml);
  }, [initialYaml]);

  // Insert snippet if navigated from Approvals
  useEffect(() => {
    if (insertedSnippet) {
      setYamlContent((prev) => `${prev.trim()}\n\n# Generated Approval Rule\n${insertedSnippet.trim()}\n`);
    }
  }, [insertedSnippet]);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const ok = await onSavePolicy(yamlContent);
      if (ok) {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 3000);
      } else {
        setSaveError('Validation failed. Check YAML syntax and required fields.');
      }
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to deploy policy');
    } finally {
      setIsSaving(false);
    }
  };

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimError(null);
    let parsedArgs = {};
    try {
      parsedArgs = JSON.parse(simArgs);
    } catch {
      setSimError('Arguments must be valid JSON');
      setIsSimulating(false);
      return;
    }

    try {
      const res = await fetch('http://localhost:3000/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policyYaml: yamlContent,
          agentId: simAgentId,
          toolName: simToolName,
          args: parsedArgs,
          simulatedTaint: simTaint,
        }),
      });

      if (!res.ok) {
        throw new Error(`Simulation failed: ${res.statusText}`);
      }

      const data = await res.json();
      setSimResult({
        verdict: data.verdict,
        allowed: data.allowed,
        latencyMs: data.latencyMs,
        ruleMatched: data.ruleMatched,
        reason: data.reason,
        taintState: data.taintState,
      });
    } catch (err) {
      setSimError(err instanceof Error ? err.message : 'Simulation error');
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8]">
      <div className="grid grid-cols-1 lg:grid-cols-12 flex-1 min-h-0">
        {/* Left: Policy YAML Monospace Editor (col-span-7 border-r) */}
        <div className="lg:col-span-7 border-r border-[#1E1E22] flex flex-col min-h-0 bg-[#000000]">
          {/* Editor Header */}
          <div className="h-11 border-b border-[#1E1E22] px-4 flex items-center justify-between bg-[#000000]">
            <div className="flex items-center gap-3 font-mono text-xs">
              <span className="font-medium text-[#F4F6F8] flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5 text-[#4D8BFF]" />
                policy.yaml
              </span>

              {versions.length > 0 && (
                <div className="flex items-center gap-1 text-[11px] text-[#8E95A2]">
                  <span>Version:</span>
                  <select
                    value={selectedVersion}
                    onChange={(e) => setSelectedVersion(Number(e.target.value))}
                    className="bg-[#09090B] border border-[#1E1E22] px-1.5 py-0.5 text-[#F4F6F8]"
                  >
                    {versions.map((v) => (
                      <option key={v.id} value={v.version}>
                        v{v.version} ({v.author})
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2">
              {saveSuccess && (
                <span className="text-[11px] font-mono text-[#4D8BFF] flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Deployed
                </span>
              )}
              <button
                disabled={isSaving}
                onClick={handleSave}
                className="px-3 py-1 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-xs font-mono font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Save className="w-3 h-3" />
                {isSaving ? 'Deploying...' : 'Save & Deploy Policy'}
              </button>
            </div>
          </div>

          {saveError && (
            <div className="p-3 bg-[#EF4444]/10 border-b border-[#EF4444]/40 text-[#EF4444] text-xs font-mono">
              {saveError}
            </div>
          )}

          {/* Monospace Code Editor */}
          <div className="flex-1 p-4 bg-[#09090B] overflow-auto">
            <textarea
              value={yamlContent}
              onChange={(e) => setYamlContent(e.target.value)}
              spellCheck={false}
              className="w-full h-full bg-transparent font-mono text-xs text-[#F4F6F8] leading-relaxed resize-none focus:outline-none border-0 select-text"
            />
          </div>
        </div>

        {/* Right: Policy Dry-Run Simulator (col-span-5 bg-[#09090B]) */}
        <div className="lg:col-span-5 bg-[#09090B] flex flex-col min-h-0 overflow-y-auto divide-y divide-[#1E1E22]">
          {/* Simulator Header */}
          <div className="p-4 bg-[#000000] border-b border-[#1E1E22]">
            <div className="text-[10px] font-mono text-[#8E95A2] uppercase tracking-wider mb-1">
              Deterministic Verification
            </div>
            <div className="text-sm font-mono font-medium text-[#F4F6F8] flex items-center gap-2">
              <Play className="w-4 h-4 text-[#4D8BFF]" />
              Policy Dry-Run Simulator
            </div>
            <div className="text-[11px] font-mono text-[#8E95A2] mt-0.5">
              Evaluates Layer 1 rules instantly without mutating sessions or audit log.
            </div>
          </div>

          {/* Simulation Inputs */}
          <div className="p-4 space-y-3 font-mono text-xs">
            <div>
              <label className="text-[#8E95A2] block mb-1">Target Agent</label>
              <select
                value={simAgentId}
                onChange={(e) => setSimAgentId(e.target.value)}
                className="w-full bg-[#000000] border border-[#1E1E22] px-2.5 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
              >
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.id} ({a.mode})
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[#8E95A2] block mb-1">Tool Name</label>
                <input
                  type="text"
                  value={simToolName}
                  onChange={(e) => setSimToolName(e.target.value)}
                  className="w-full bg-[#000000] border border-[#1E1E22] px-2.5 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                />
              </div>

              <div>
                <label className="text-[#8E95A2] block mb-1">Simulated Taint</label>
                <select
                  value={simTaint}
                  onChange={(e) => setSimTaint(e.target.value as 'CLEAN' | 'TAINTED')}
                  className="w-full bg-[#000000] border border-[#1E1E22] px-2.5 py-1.5 text-xs text-[#F4F6F8] focus:outline-none focus:border-[#4D8BFF]"
                >
                  <option value="CLEAN">CLEAN (Default)</option>
                  <option value="TAINTED">TAINTED (Ingested untrusted)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-[#8E95A2] block mb-1">Invocation Arguments (JSON)</label>
              <textarea
                value={simArgs}
                onChange={(e) => setSimArgs(e.target.value)}
                rows={5}
                spellCheck={false}
                className="w-full bg-[#000000] border border-[#1E1E22] p-2.5 text-xs font-mono text-[#F4F6F8] leading-relaxed focus:outline-none focus:border-[#4D8BFF]"
              />
            </div>

            {simError && (
              <div className="p-2 border border-[#EF4444]/40 bg-[#EF4444]/10 text-[#EF4444] text-[11px]">
                {simError}
              </div>
            )}

            <button
              disabled={isSimulating}
              onClick={handleSimulate}
              className="w-full py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] font-medium text-xs flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              {isSimulating ? 'Evaluating Layer 1...' : 'Simulate Evaluation'}
            </button>
          </div>

          {/* Simulation Output */}
          <div className="p-4 flex-1">
            <div className="text-xs font-mono font-medium text-[#F4F6F8] uppercase tracking-wider mb-2">
              Dry-Run Output
            </div>

            {simResult ? (
              <div className="p-3.5 border border-[#1E1E22] bg-[#000000] space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-[#8E95A2]">Verdict:</span>
                  <span
                    className={`font-medium px-1.5 py-0.5 border ${
                      simResult.verdict === 'ALLOW'
                        ? 'border-[#1E1E22] text-[#F4F6F8]'
                        : simResult.verdict === 'DENY' || simResult.verdict === 'CRITICAL_TRIPWIRE'
                        ? 'border-[#EF4444] text-[#EF4444] bg-[#EF4444]/10'
                        : 'border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10'
                    }`}
                  >
                    {simResult.verdict}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-[#8E95A2]">Data Plane Allowed:</span>
                  <span className={simResult.allowed ? 'text-[#4D8BFF]' : 'text-[#EF4444]'}>
                    {simResult.allowed ? 'YES (Proceed)' : 'NO (Vetoed)'}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-[#8E95A2]">Rule Matched:</span>
                  <span className="text-[#F4F6F8]">{simResult.ruleMatched}</span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-[#8E95A2]">Evaluation Latency:</span>
                  <span className="text-[#4D8BFF] tabular-nums">{simResult.latencyMs.toFixed(3)} ms</span>
                </div>

                <div className="pt-2 border-t border-[#1E1E22] text-[11px] text-[#8E95A2]">
                  {simResult.reason || 'Decision reached via deterministic Layer 1 engine.'}
                </div>
              </div>
            ) : (
              <div className="p-4 border border-[#1E1E22] bg-[#000000] text-center text-xs text-[#8E95A2] font-mono">
                Click &quot;Simulate Evaluation&quot; to test your current policy draft against candidate inputs.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
