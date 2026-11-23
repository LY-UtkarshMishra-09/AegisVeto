import React, { useState } from 'react';
import { Copy, Check, FileCode } from 'lucide-react';

interface PolicyRulesViewProps {
  policyYaml: string;
}

export const PolicyRulesView: React.FC<PolicyRulesViewProps> = ({ policyYaml }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(policyYaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="bg-[#16221D] border border-[#263830] rounded p-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-[#D4F849]" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#ECF2EE]">
              Active Security Policy (<code className="text-[#D4F849] font-mono">policy.yaml</code>)
            </h3>
          </div>
          <p className="text-[11px] text-[#7E9489] mt-0.5">
            Deterministic AST rules evaluated at tool invocation. Zero stochastic latency.
          </p>
        </div>

        <button
          onClick={handleCopy}
          className="px-3 py-1.5 bg-[#0E1317] hover:bg-[#16221D] text-[#ECF2EE] hover:text-[#D4F849] text-xs font-mono font-medium rounded border border-[#263830] flex items-center gap-1.5 transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-[#D4F849]" />
              Copied
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-[#7E9489]" />
              Copy YAML
            </>
          )}
        </button>
      </div>

      {/* Rule Breakdown Badges */}
      <div className="flex items-center gap-2 text-[11px] font-mono">
        <span className="px-2 py-0.5 rounded bg-[#0E1317] text-[#ECF2EE] border border-[#263830]">
          Path Rules: Active
        </span>
        <span className="px-2 py-0.5 rounded bg-[#F43F5E]/10 text-[#F43F5E] border border-[#F43F5E]/30">
          Secret Traps: .env*, .ssh, .git/config
        </span>
        <span className="px-2 py-0.5 rounded bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30">
          Quarantine Triggers: Destructive Shell
        </span>
        <span className="px-2 py-0.5 rounded bg-[#D4F849]/10 text-[#D4F849] border border-[#D4F849]/30">
          Lattice Sinks: Egress Blocked
        </span>
      </div>

      {/* Formatted YAML Code Container */}
      <div className="bg-[#0E1317] border border-[#263830] rounded overflow-hidden">
        <pre className="p-4 text-[#ECF2EE] text-xs font-mono overflow-x-auto leading-relaxed max-h-[560px]">
          {policyYaml}
        </pre>
      </div>
    </div>
  );
};
