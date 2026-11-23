import React from 'react';
import { Shield, Activity, ShieldAlert, BarChart3, FileCode, PanelLeftClose, PanelLeftOpen } from 'lucide-react';

export type NavTab = 'console' | 'quarantine' | 'benchmark' | 'policy';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  pendingQuarantineCount: number;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  pendingQuarantineCount,
  isCollapsed,
  onToggleCollapse,
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
    <aside
      className={`sticky top-0 h-screen bg-[#0E1317] border-r border-[#263830] flex flex-col justify-between select-none transition-all duration-200 z-30 ${
        isCollapsed ? 'w-[64px] min-w-[64px]' : 'w-[220px] min-w-[220px]'
      }`}
    >
      <div>
        {/* Brand Header */}
        <div className={`p-3.5 border-b border-[#263830] ${isCollapsed ? 'flex flex-col items-center gap-2' : ''}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-6 h-6 rounded bg-[#16221D] border border-[#263830] flex items-center justify-center text-[#D4F849] shrink-0">
                <Shield className="w-3.5 h-3.5 fill-current" />
              </div>
              {!isCollapsed && (
                <span className="font-semibold tracking-tight text-sm text-[#ECF2EE]">
                  AegisVeto
                </span>
              )}
            </div>

            <button
              onClick={onToggleCollapse}
              title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              className="p-1 rounded text-[#7E9489] hover:text-[#ECF2EE] hover:bg-[#16221D] transition-colors"
            >
              {isCollapsed ? (
                <PanelLeftOpen className="w-4 h-4" />
              ) : (
                <PanelLeftClose className="w-4 h-4" />
              )}
            </button>
          </div>

          {/* Status pill / dot */}
          {!isCollapsed ? (
            <div className="mt-2.5 flex items-center gap-1.5 px-2 py-1 rounded bg-[#16221D] border border-[#263830] text-[11px] font-mono text-[#7E9489]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#D4F849] animate-pulse shrink-0" />
              <span className="truncate">Proxy Active · &lt;10ms</span>
            </div>
          ) : (
            <div className="mt-1" title="Proxy Active · <10ms">
              <span className="w-2 h-2 rounded-full bg-[#D4F849] animate-pulse block" />
            </div>
          )}
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                title={item.label}
                className={`relative w-full flex items-center rounded text-xs transition-colors ${
                  isCollapsed ? 'justify-center p-2.5' : 'justify-between px-3 py-2'
                } ${
                  isActive
                    ? 'bg-[#16221D] text-[#ECF2EE] font-medium border border-[#263830]'
                    : 'text-[#7E9489] hover:text-[#ECF2EE] hover:bg-[#16221D]/40'
                }`}
              >
                {/* Left Acid Lime indicator bar */}
                {isActive && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-[#D4F849]" />
                )}

                <div className={`flex items-center gap-2.5 ${isCollapsed ? 'justify-center' : ''}`}>
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#D4F849]' : 'text-[#7E9489]'}`} />
                  {!isCollapsed && <span>{item.label}</span>}
                </div>

                {item.badge !== undefined && (
                  isCollapsed ? (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#F59E0B]" />
                  ) : (
                    <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/30">
                      {item.badge}
                    </span>
                  )
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Info (hidden when collapsed) */}
      {!isCollapsed && (
        <div className="p-3 border-t border-[#263830] text-[11px] text-[#7E9489] font-mono space-y-1">
          <div className="flex justify-between items-center">
            <span>Engine</span>
            <span className="text-[#ECF2EE]">Deterministic</span>
          </div>
          <div className="flex justify-between items-center">
            <span>LLM in Guard</span>
            <span className="text-[#D4F849] font-medium">None (0.00%)</span>
          </div>
        </div>
      )}
    </aside>
  );
};
