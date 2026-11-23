import React, { useState } from 'react';
import { Check, X, ShieldAlert, AlertTriangle, Sparkles, Wrench, FileCode, CheckCircle2 } from 'lucide-react';
import { QuarantineItem } from '../types';

interface QuarantineViewProps {
  queue: QuarantineItem[];
  onApprove: (id: string) => void;
  onVeto: (id: string) => void;
  onPolicyPatched?: () => void;
}

const API_BASE = 'http://localhost:3000';

export const QuarantineView: React.FC<QuarantineViewProps> = ({
  queue,
  onApprove,
  onVeto,
  onPolicyPatched,
}) => {
  const pendingItems = queue.filter((item) => item.status === 'PENDING');
  const resolvedItems = queue.filter((item) => item.status !== 'PENDING');

  // State for Auto-Patcher drawer per item
  const [patchingId, setPatchingId] = useState<string | null>(null);
  const [patchLoading, setPatchLoading] = useState(false);
  const [patchSuggestion, setPatchSuggestion] = useState<{ suggestedYaml: string; explanation: string } | null>(null);
  const [patchAppliedId, setPatchAppliedId] = useState<string | null>(null);

  const handleRequestPatch = async (item: QuarantineItem) => {
    setPatchingId(item.id);
    setPatchLoading(true);
    setPatchSuggestion(null);

    try {
      const res = await fetch(`${API_BASE}/policy/suggest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolName: item.tool,
          args: item.args,
          reason: item.riskSummary,
        }),
      });
      const data = await res.json();
      setPatchSuggestion(data);
    } catch (err) {
      console.error('Failed to get policy patch suggestion:', err);
    } finally {
      setPatchLoading(false);
    }
  };

  const handleApplyPatch = async (snippet: string) => {
    if (!patchingId) return;
    try {
      const res = await fetch(`${API_BASE}/policy/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ snippet }),
      });
      if (res.ok) {
        setPatchAppliedId(patchingId);
        onPolicyPatched?.();
      }
    } catch (err) {
      console.error('Failed to apply policy patch:', err);
    }
  };

  return (
    <div className="space-y-3">
      {/* Header Info */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#F59E0B]" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#ECF2EE]">
              Human-in-the-Loop Quarantine Queue
            </h3>
          </div>
          <p className="text-[11px] text-[#7E9489] mt-0.5 font-sans">
            Layer 1 pauses destructive calls in &lt;10ms. Layer 2 AI Security Brain verifies intent and suggests permanent auto-patches.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-[#7E9489]">Pending:</span>
          <span className="px-2 py-0.5 rounded bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30 font-semibold">
            {pendingItems.length}
          </span>
        </div>
      </div>

      {/* Pending Items List: Collapses cleanly to slim bar when 0 pending */}
      <div className="space-y-3">
        {pendingItems.length === 0 ? (
          <div className="bg-[#16221D] border border-[#263830] rounded px-4 py-2.5 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 text-[#D4F849]" />
              <span className="text-xs font-mono text-[#ECF2EE]">
                Quarantine Queue Clean
              </span>
              <span className="text-[#263830]">·</span>
              <span className="text-[11px] text-[#7E9489] font-sans">
                0 pending approvals. All active invocations processed.
              </span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#D4F849]/10 text-[#D4F849] border border-[#D4F849]/30">
              0 PENDING
            </span>
          </div>
        ) : (
          pendingItems.map((item) => {
            const isPatchingThis = patchingId === item.id;
            const isPatchedThis = patchAppliedId === item.id;
            const ai = item.ai_assessment;
            const isHighRisk = ai ? ai.risk_score >= 70 : true;

            return (
              <div
                key={item.id}
                className="bg-[#16221D] border border-[#263830] rounded overflow-hidden"
              >
                {/* Item Header */}
                <div className="p-3 border-b border-[#263830] flex items-center justify-between bg-[#0E1317]">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-[#ECF2EE] font-semibold">{item.id}</span>
                    <span className="text-[#263830]">·</span>
                    <span className="text-[#7E9489]">{item.session}</span>
                    <span className="text-[#263830]">·</span>
                    <span className="bg-[#16221D] px-1.5 py-0.5 rounded text-[11px] text-[#ECF2EE] border border-[#263830]">
                      {item.tool}
                    </span>
                    <span className="text-[#263830]">·</span>
                    <span
                      className={`text-[10px] font-semibold ${
                        item.taint === 'TAINTED' ? 'text-[#F43F5E]' : 'text-[#D4F849]'
                      }`}
                    >
                      {item.taint}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-[#7E9489]">{item.timestamp}</div>
                </div>

                {/* Split View Content */}
                <div className="p-3.5 grid grid-cols-2 gap-3.5">
                  {/* Left: Tool Details, Layer 2 AI Assessment & Arguments */}
                  <div className="space-y-2.5">
                    {/* Layer 1 Rule Reason */}
                    <div className="p-2.5 rounded bg-[#0E1317] border border-[#263830]">
                      <div className="flex items-center gap-1.5 text-[#F59E0B] text-[11px] font-mono mb-1 font-medium">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Layer 1 Deterministic Policy Trigger
                      </div>
                      <p className="text-xs text-[#ECF2EE] font-sans leading-relaxed">
                        {item.riskSummary}
                      </p>
                    </div>

                    {/* Layer 2 AI Security Brain Assessment Block */}
                    <div className="p-2.5 rounded bg-[#0E1317] border border-[#263830] space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-[#D4F849] text-[11px] font-mono font-medium">
                          <Sparkles className="w-3.5 h-3.5" />
                          Layer 2 AI Security Brain
                        </div>

                        {ai ? (
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-1.5 py-0.2 rounded font-mono text-[10px] font-bold border ${
                                isHighRisk
                                  ? 'bg-[#F43F5E]/10 text-[#F43F5E] border-[#F43F5E]/30'
                                  : 'bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/30'
                              }`}
                            >
                              Risk Score: {ai.risk_score}/100
                            </span>
                            <span
                              className={`px-1.5 py-0.2 rounded font-mono text-[10px] font-bold border ${
                                ai.hijacked
                                  ? 'bg-[#F43F5E]/10 text-[#F43F5E] border-[#F43F5E]/30'
                                  : 'bg-[#D4F849]/10 text-[#D4F849] border-[#D4F849]/30'
                              }`}
                            >
                              {ai.hijacked ? 'HIJACKED' : 'NOT HIJACKED'}
                            </span>
                          </div>
                        ) : (
                          <span className="text-[10px] font-mono text-[#7E9489] animate-pulse">
                            Evaluating Intent...
                          </span>
                        )}
                      </div>

                      <p className="text-xs text-[#ECF2EE] font-sans leading-relaxed">
                        {ai
                          ? ai.summary
                          : 'Asynchronous intent analysis executing in background via OpenAI SDK...'}
                      </p>
                    </div>

                    {/* Intercepted JSON Arguments */}
                    <div>
                      <div className="text-[10px] font-mono uppercase text-[#7E9489] mb-1">
                        Intercepted Arguments (JSON)
                      </div>
                      <pre className="p-2.5 rounded bg-[#0E1317] border border-[#263830] text-[#ECF2EE] text-[11px] font-mono overflow-x-auto max-h-[120px]">
                        {JSON.stringify(item.args, null, 2)}
                      </pre>
                    </div>
                  </div>

                  {/* Right: Actions (Approve, Veto, Auto-Patch Rule) */}
                  <div className="flex flex-col justify-between gap-3 p-4 rounded bg-[#0E1317] border border-[#263830]">
                    <div className="space-y-2.5">
                      <div className="text-xs text-[#7E9489] text-center mb-1">
                        Operator Decision Required
                      </div>

                      <button
                        onClick={() => onApprove(item.id)}
                        className="w-full py-2.5 px-4 rounded bg-[#D4F849] hover:bg-[#c2e838] text-[#080B0E] text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors"
                      >
                        <Check className="w-4 h-4 stroke-[2.5]" />
                        Approve Execution
                      </button>

                      <button
                        onClick={() => onVeto(item.id)}
                        className="w-full py-2.5 px-4 rounded bg-transparent hover:bg-[#F43F5E]/10 text-[#F43F5E] border border-[#F43F5E] text-xs font-mono font-bold flex items-center justify-center gap-2 transition-colors"
                      >
                        <X className="w-4 h-4 stroke-[2.5]" />
                        Veto &amp; Terminate
                      </button>
                    </div>

                    {/* Auto-Patch Rule Button */}
                    <div className="pt-2 border-t border-[#263830]">
                      <button
                        onClick={() => handleRequestPatch(item)}
                        disabled={patchLoading}
                        className="w-full py-2 px-3 rounded bg-[#16221D] hover:bg-[#263830] text-[#ECF2EE] hover:text-[#D4F849] border border-[#263830] text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                      >
                        <Wrench className="w-3.5 h-3.5 text-[#D4F849]" />
                        Auto-Patch Rule ("Learn Once, Enforce Forever")
                      </button>
                    </div>
                  </div>
                </div>

                {/* Auto-Patch Preview Drawer */}
                {isPatchingThis && (
                  <div className="p-3.5 bg-[#080B0E] border-t border-[#263830] space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-xs font-mono text-[#D4F849]">
                        <FileCode className="w-4 h-4" />
                        <span>AI Policy Auto-Patcher Proposal</span>
                      </div>
                      <button
                        onClick={() => setPatchingId(null)}
                        className="text-[11px] font-mono text-[#7E9489] hover:text-[#ECF2EE]"
                      >
                        Close
                      </button>
                    </div>

                    {patchLoading ? (
                      <div className="p-4 text-center font-mono text-xs text-[#7E9489] animate-pulse">
                        Generating minimal mathematical policy rule...
                      </div>
                    ) : patchSuggestion ? (
                      <div className="space-y-2">
                        <p className="text-xs text-[#ECF2EE] font-sans">
                          {patchSuggestion.explanation}
                        </p>

                        <div className="relative">
                          <pre className="p-3 rounded bg-[#0E1317] border border-[#263830] text-[#D4F849] text-xs font-mono overflow-x-auto">
                            {patchSuggestion.suggestedYaml}
                          </pre>
                        </div>

                        {isPatchedThis ? (
                          <div className="p-2 rounded bg-[#D4F849]/10 border border-[#D4F849]/30 text-xs font-mono text-[#D4F849] flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4" />
                            Rule applied permanently to policy.yaml. Layer 1 policy engine reloaded.
                          </div>
                        ) : (
                          <button
                            onClick={() => handleApplyPatch(patchSuggestion.suggestedYaml)}
                            className="py-2 px-4 rounded bg-[#D4F849] hover:bg-[#c2e838] text-[#080B0E] text-xs font-mono font-bold flex items-center gap-2 transition-colors"
                          >
                            <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                            Apply to policy.yaml
                          </button>
                        )}
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Resolved History */}
      {resolvedItems.length > 0 && (
        <div className="bg-[#16221D] border border-[#263830] rounded p-3">
          <div className="text-[11px] font-mono text-[#7E9489] uppercase tracking-wider mb-2">
            Resolved Session Items
          </div>
          <div className="space-y-1.5">
            {resolvedItems.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between text-xs font-mono p-2 rounded bg-[#0E1317] border border-[#263830]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[#ECF2EE] font-semibold">{item.id}</span>
                  <span className="text-[#263830]">·</span>
                  <span className="text-[#7E9489]">{item.tool}</span>
                </div>
                <div>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                      item.status === 'APPROVED'
                        ? 'bg-[#D4F849]/10 text-[#D4F849] border-[#D4F849]/30'
                        : 'bg-[#F43F5E]/10 text-[#F43F5E] border-[#F43F5E]/30'
                    }`}
                  >
                    {item.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
