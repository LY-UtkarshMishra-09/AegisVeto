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
      <div className="bg-[#111113] border border-[#27272A] rounded p-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-zinc-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Active Security Policy (<code className="text-zinc-300 font-mono">policy.yaml</code>)
            </h3>
          </div>
          <p className="text-[11px] text-zinc-400 mt-0.5">
            Deterministic AST rules evaluated at tool invocation. Zero stochastic latency.
          </p>
        </div>

        <button
          onClick={handleCopy}
          className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono font-medium rounded border border-zinc-700 flex items-center gap-1.5 transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              Copied
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-zinc-400" />
              Copy YAML
            </>
          )}
        </button>
      </div>

      {/* Rule Breakdown Badges */}
      <div className="flex items-center gap-2 text-[11px] font-mono">
        <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
          Path Rules: 5 Active
        </span>
        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
          Secret Traps: .env*, id_rsa*, credentials
        </span>
        <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
          Quarantine Triggers: Destructive Shell
        </span>
        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          Lattice Sinks: 3 Egress Blocked
        </span>
      </div>

      {/* Formatted YAML Preview */}
      <div className="bg-[#111113] border border-[#27272A] rounded overflow-hidden">
        <pre className="p-3 text-zinc-300 text-xs font-mono overflow-x-auto leading-relaxed max-h-[560px]">
          {policyYaml}
        </pre>
      </div>
    </div>
  );
};
