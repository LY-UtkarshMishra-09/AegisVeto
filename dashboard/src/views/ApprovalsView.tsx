import React, { useState, useEffect } from 'react';
import { QuarantineItem } from '../types';
import { Clock, Brain, FileCode, CheckCircle2, X, Sparkles, ArrowRight } from 'lucide-react';

interface ApprovalsViewProps {
  approvals: QuarantineItem[];
  onResolve: (id: string, action: 'approve' | 'veto') => Promise<void>;
  onNavigateToPolicy: (snippet?: string) => void;
}

export const ApprovalsView: React.FC<ApprovalsViewProps> = ({
  approvals,
  onResolve,
  onNavigateToPolicy,
}) => {
  const [selectedId, setSelectedId] = useState<string | null>(approvals[0]?.id || null);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState<number>(Date.now());

  // Policy Rule Auto-Patcher Modal State
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [isGeneratingRule, setIsGeneratingRule] = useState(false);
  const [isApplyingRule, setIsApplyingRule] = useState(false);
  const [ruleAppliedSuccess, setRuleAppliedSuccess] = useState(false);
  const [suggestedRule, setSuggestedRule] = useState<{ suggestedYaml: string; explanation: string } | null>(null);

  // Tick timer for SLA countdown
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Update selected if current selected is no longer in list
  useEffect(() => {
    if (approvals.length > 0 && (!selectedId || !approvals.some((a) => a.id === selectedId))) {
      setSelectedId(approvals[0].id);
    }
  }, [approvals, selectedId]);

  const selectedItem = approvals.find((a) => a.id === selectedId) || null;

  const handleResolveAction = async (id: string, action: 'approve' | 'veto') => {
    setResolvingId(id);
    try {
      await onResolve(id, action);
    } finally {
      setResolvingId(null);
    }
  };

  const handleGenerateRule = async () => {
    if (!selectedItem) return;
    setIsGeneratingRule(true);
    setSuggestedRule(null);
    setShowRuleModal(true);
    try {
      const res = await fetch('http://localhost:3000/v1/policies/suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolName: selectedItem.toolName,
          args: selectedItem.payload,
          reason: selectedItem.ruleMatched,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSuggestedRule(data);
      } else {
        setSuggestedRule({
          suggestedYaml: `tools:\n  ${selectedItem.toolName}:\n    action: require_approval\n    class: egress\n`,
          explanation: `Restricts '${selectedItem.toolName}' to require human operator approval for subsequent invocations.`,
        });
      }
    } catch {
      setSuggestedRule({
        suggestedYaml: `tools:\n  ${selectedItem.toolName}:\n    action: require_approval\n    class: egress\n`,
        explanation: `Restricts '${selectedItem.toolName}' to require human operator approval for subsequent invocations.`,
      });
    } finally {
      setIsGeneratingRule(false);
    }
  };

  const handleApplyPolicyRollout = async () => {
    if (!suggestedRule) return;
    setIsApplyingRule(true);
    try {
      const activeRes = await fetch('http://localhost:3000/v1/policies/active');
      let activeYaml = '';
      if (activeRes.ok) {
        const activeData = await activeRes.json();
        activeYaml = activeData.yamlContent || '';
      }
      const updatedYaml = `${activeYaml.trim()}\n\n# Auto-patched rule for ${selectedItem?.toolName}\n${suggestedRule.suggestedYaml}\n`;
      const putRes = await fetch('http://localhost:3000/v1/policies/active', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          yamlContent: updatedYaml,
          author: 'l2-auto-patcher',
        }),
      });
      if (putRes.ok) {
        setRuleAppliedSuccess(true);
        setTimeout(() => {
          setShowRuleModal(false);
          setRuleAppliedSuccess(false);
          setSuggestedRule(null);
        }, 1500);
      }
    } finally {
      setIsApplyingRule(false);
    }
  };

  const getRemainingSlaSeconds = (expiresAt: string) => {
    const diff = Math.floor((new Date(expiresAt).getTime() - currentTime) / 1000);
    return Math.max(0, diff);
  };

  return (
    <div className="flex flex-col h-full bg-[#000000] text-[#F4F6F8]">
      {/* Sub-header Bar */}
      <div className="h-11 border-b border-[#1E1E22] px-5 flex items-center justify-between bg-[#000000]">
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono font-medium text-[#F4F6F8] uppercase tracking-wider">
            Quarantine Approval Queue
          </span>
          <span className="text-xs font-mono px-2 py-0.5 bg-[#141417] text-[#4D8BFF] border border-[#1E1E22]">
            {approvals.length} pending
          </span>
        </div>
        <div className="text-xs font-mono text-[#8E95A2]">
          Fail-Closed SLA: Auto-denies on timeout
        </div>
      </div>

      {approvals.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
          <div className="w-12 h-12 bg-[#141417] border border-[#1E1E22] flex items-center justify-center mb-3">
            <CheckCircle2 className="w-6 h-6 text-[#4D8BFF]" />
          </div>
          <div className="text-sm font-mono font-medium text-[#F4F6F8] mb-1">
            Zero Pending Quarantines
          </div>
          <div className="text-xs font-mono text-[#8E95A2] max-w-sm">
            All agent tool executions have either cleared deterministic Layer 1 filters or have already been resolved.
          </div>
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0 divide-y lg:divide-y-0 lg:divide-x divide-[#1E1E22]">
          {/* Left Master List (col-span-5) */}
          <div className="lg:col-span-5 overflow-y-auto divide-y divide-[#1E1E22]">
            {approvals.map((item) => {
              const remainingSec = getRemainingSlaSeconds(item.expiresAt);
              const isSelected = item.id === selectedId;

              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                  className={`p-4 cursor-pointer transition-colors ${
                    isSelected ? 'bg-[#141417]' : 'hover:bg-[#09090B]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-medium text-[#F4F6F8] truncate max-w-[180px]">
                      {item.toolName}
                    </span>
                    <div className="flex items-center gap-1 text-[11px] font-mono text-[#F59E0B] tabular-nums">
                      <Clock className="w-3 h-3" />
                      {Math.floor(remainingSec / 60)}:{(remainingSec % 60).toString().padStart(2, '0')}
                    </div>
                  </div>

                  <div className="text-[11px] font-mono text-[#8E95A2] truncate mb-2">
                    Agent: <span className="text-[#F4F6F8]">{item.agentId}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 border border-[#F59E0B] text-[#F59E0B] bg-[#F59E0B]/10">
                      QUARANTINE
                    </span>
                    {item.ruleMatched && (
                      <span className="text-[10px] font-mono text-[#8E95A2] truncate max-w-[200px]">
                        {item.ruleMatched}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Detail Pane (col-span-7) */}
          <div className="lg:col-span-7 bg-[#09090B] flex flex-col min-h-0 overflow-y-auto divide-y divide-[#1E1E22]">
            {selectedItem ? (
              <>
                {/* Header */}
                <div className="p-5 bg-[#000000] flex items-start justify-between">
                  <div>
                    <div className="text-[10px] font-mono text-[#8E95A2] uppercase tracking-wider mb-1">
                      Operator Decision Gate
                    </div>
                    <div className="text-base font-mono font-medium text-[#F4F6F8]">
                      {selectedItem.toolName}
                    </div>
                    <div className="text-xs font-mono text-[#8E95A2] mt-0.5">
                      Targeted by agent <span className="text-[#F4F6F8]">{selectedItem.agentId}</span>
                    </div>
                  </div>

                  <div className="text-right font-mono">
                    <div className="text-[11px] text-[#8E95A2]">Auto-Veto In</div>
                    <div className="text-lg text-[#F59E0B] font-medium tabular-nums">
                      {Math.floor(getRemainingSlaSeconds(selectedItem.expiresAt) / 60)}:
                      {(getRemainingSlaSeconds(selectedItem.expiresAt) % 60).toString().padStart(2, '0')}
                    </div>
                  </div>
                </div>

                {/* Layer 2 AI Semantic Assessment */}
                <div className="p-5 space-y-3">
                  <div className="text-xs font-mono text-[#F4F6F8] font-medium flex items-center gap-2 uppercase">
                    <Brain className="w-3.5 h-3.5 text-[#4D8BFF]" />
                    Layer 2 Semantic Security Brain
                  </div>

                  <div className="p-3.5 border border-[#1E1E22] bg-[#000000] space-y-2 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-[#8E95A2]">AI Risk Score:</span>
                      <span
                        className={`font-medium ${
                          (selectedItem.aiRiskScore ?? 78) > 60 ? 'text-[#EF4444]' : 'text-[#4D8BFF]'
                        }`}
                      >
                        {selectedItem.aiRiskScore !== null
                          ? `${Math.round(selectedItem.aiRiskScore)} / 100`
                          : 'Evaluating intent in background...'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-[#8E95A2]">Prompt Injection / Hijack:</span>
                      <span className="text-[#EF4444] font-medium">
                        {selectedItem.aiHijacked ? 'DETECTED' : 'Egress / Destructive Target'}
                      </span>
                    </div>

                    <div className="pt-2 border-t border-[#1E1E22] text-[#8E95A2] text-[11px] leading-relaxed">
                      {selectedItem.aiSummary ||
                        `Tool execution halted by static quarantine rule '${selectedItem.ruleMatched}'. Asynchronous Layer 2 intent analysis running in background.`}
                    </div>
                  </div>
                </div>

                {/* Invocation Arguments JSON */}
                <div className="p-5 flex-1 flex flex-col min-h-[180px]">
                  <div className="text-xs font-mono text-[#F4F6F8] font-medium mb-2 uppercase">
                    Execution Arguments
                  </div>
                  <div className="p-3 bg-[#000000] border border-[#1E1E22] font-mono text-xs text-[#F4F6F8] overflow-auto flex-1 max-h-[250px]">
                    <pre className="whitespace-pre-wrap break-all">
                      {JSON.stringify(selectedItem.payload, null, 2)}
                    </pre>
                  </div>
                </div>

                {/* Action Bar */}
                <div className="p-5 bg-[#000000] border-t border-[#1E1E22] flex items-center justify-between gap-3">
                  <button
                    onClick={handleGenerateRule}
                    className="px-3 py-2 border border-[#1E1E22] hover:bg-[#141417] text-xs font-mono text-[#8E95A2] hover:text-[#F4F6F8] flex items-center gap-1.5 transition-colors"
                  >
                    <FileCode className="w-3.5 h-3.5 text-[#4D8BFF]" />
                    Generate Policy Rule
                  </button>

                  <div className="flex items-center gap-2">
                    <button
                      disabled={resolvingId === selectedItem.id}
                      onClick={() => handleResolveAction(selectedItem.id, 'veto')}
                      className="px-4 py-2 border border-[#EF4444] text-[#EF4444] hover:bg-[#EF4444]/10 text-xs font-mono transition-colors disabled:opacity-50"
                    >
                      Veto Call
                    </button>

                    <button
                      disabled={resolvingId === selectedItem.id}
                      onClick={() => handleResolveAction(selectedItem.id, 'approve')}
                      className="px-4 py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] text-xs font-mono font-medium transition-colors disabled:opacity-50"
                    >
                      Approve Once
                    </button>
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}

      {/* Policy Auto-Patcher Modal */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="w-full max-w-lg bg-[#09090B] border border-[#1E1E22] p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E1E22] pb-3">
              <span className="font-medium text-[#F4F6F8] flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-[#4D8BFF]" />
                Layer 2 Policy Auto-Patcher (Learn Once, Enforce Forever)
              </span>
              <button
                onClick={() => setShowRuleModal(false)}
                className="text-[#8E95A2] hover:text-[#F4F6F8]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {isGeneratingRule ? (
              <div className="py-8 text-center text-[#8E95A2] space-y-2">
                <Brain className="w-6 h-6 animate-pulse text-[#4D8BFF] mx-auto" />
                <div>Synthesizing deterministic Layer 1 policy rule snippet...</div>
              </div>
            ) : suggestedRule ? (
              <div className="space-y-3">
                <div className="text-[11px] text-[#8E95A2] leading-relaxed p-2.5 bg-[#000000] border border-[#1E1E22]">
                  {suggestedRule.explanation}
                </div>

                <div>
                  <div className="text-[#8E95A2] mb-1">Generated Policy Snippet:</div>
                  <pre className="p-3 bg-[#000000] border border-[#1E1E22] text-[#F4F6F8] overflow-auto max-h-48 text-[11px] whitespace-pre-wrap">
                    {suggestedRule.suggestedYaml}
                  </pre>
                </div>

                {ruleAppliedSuccess && (
                  <div className="text-xs text-[#4D8BFF] flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" /> Rule successfully rolled out as new active policy!
                  </div>
                )}
              </div>
            ) : null}

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#1E1E22]">
              <button
                onClick={() => setShowRuleModal(false)}
                className="px-3 py-1.5 border border-[#1E1E22] text-[#8E95A2] hover:text-[#F4F6F8]"
              >
                Cancel
              </button>
              {suggestedRule && (
                <>
                  <button
                    onClick={() => {
                      onNavigateToPolicy(suggestedRule.suggestedYaml);
                      setShowRuleModal(false);
                    }}
                    className="px-3 py-1.5 border border-[#1E1E22] text-[#F4F6F8] hover:bg-[#141417]"
                  >
                    Open in Editor
                  </button>
                  <button
                    disabled={isApplyingRule || ruleAppliedSuccess}
                    onClick={handleApplyPolicyRollout}
                    className="px-3 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-[#F4F6F8] font-medium disabled:opacity-50 flex items-center gap-1"
                  >
                    {isApplyingRule ? 'Rolling out...' : 'Apply Versioned Rollout'}
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
