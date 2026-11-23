import React from 'react';
import { Shield, Activity, ShieldAlert, BarChart3, FileCode } from 'lucide-react';

export type NavTab = 'console' | 'quarantine' | 'benchmark' | 'policy';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  pendingQuarantineCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  pendingQuarantineCount,
}) => {
  const navItems = [
    {
      id: 'console' as NavTab,
      label: 'Live Console',
      icon: Activity,
    },
    {
      id: 'quarantine' as NavTab,
      label: 'Quarantine Queue',
      icon: ShieldAlert,
      badge: pendingQuarantineCount > 0 ? pendingQuarantineCount : undefined,
    },
    {
      id: 'benchmark' as NavTab,
      label: 'VS Benchmark',
      icon: BarChart3,
    },
    {
      id: 'policy' as NavTab,
      label: 'Policy Rules',
      icon: FileCode,
    },
  ];

  return (
    <aside className="w-[220px] min-w-[220px] h-screen bg-[#09090B] border-r border-[#27272A] flex flex-col justify-between select-none">
      <div>
        {/* Brand Header */}
        <div className="p-4 border-b border-[#27272A]">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-100">
              <Shield className="w-3.5 h-3.5 text-zinc-300" />
            </div>
            <span className="font-semibold tracking-tight text-sm text-zinc-100">
              AegisVeto
            </span>
          </div>

          <div className="mt-2.5 flex items-center gap-1.5 text-[11px] font-mono text-zinc-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>Proxy Active · &lt;10ms</span>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-0.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors text-left ${
                  isActive
                    ? 'bg-[#18181B] text-zinc-100 font-medium border border-[#27272A]'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-[#111113]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-zinc-200' : 'text-zinc-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="text-[10px] font-mono font-medium px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Info */}
      <div className="p-3 border-t border-[#27272A] text-[11px] text-zinc-500 font-mono">
        <div className="flex justify-between items-center text-zinc-400">
          <span>Engine</span>
          <span className="text-zinc-300">Deterministic</span>
        </div>
        <div className="flex justify-between items-center mt-1">
          <span>LLM in Guard</span>
          <span className="text-emerald-400 font-medium">None (0.00%)</span>
        </div>
      </div>
    </aside>
  );
};
