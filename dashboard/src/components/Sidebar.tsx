import React from 'react';
import {
  Shield,
  LayoutDashboard,
  ScrollText,
  ShieldAlert,
  Cpu,
  FileCode2,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

export type NavTab = 'overview' | 'logs' | 'approvals' | 'inventory' | 'policies' | 'settings';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  pendingApprovalsCount: number;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  pendingApprovalsCount,
  isCollapsed,
  onToggleCollapse,
}) => {
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'Overview',
      icon: LayoutDashboard,
    },
    {
      id: 'logs' as NavTab,
      label: 'Audit Stream',
      icon: ScrollText,
    },
    {
      id: 'approvals' as NavTab,
      label: 'Approvals',
      icon: ShieldAlert,
      badge: pendingApprovalsCount,
    },
    {
      id: 'inventory' as NavTab,
      label: 'Inventory',
      icon: Cpu,
    },
    {
      id: 'policies' as NavTab,
      label: 'Policies',
      icon: FileCode2,
    },
    {
      id: 'settings' as NavTab,
      label: 'Settings',
      icon: Settings,
    },
  ];

  return (
    <aside
      className={`h-screen bg-[#000000] border-r border-[#1E1E22] flex flex-col transition-all duration-200 select-none z-30 ${
        isCollapsed ? 'w-16' : 'w-56'
      }`}
    >
      {/* Top Header with Shield Emblem */}
      <div className="h-12 border-b border-[#1E1E22] px-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-[#141417] border border-[#1E1E22] flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-[#F4F6F8] stroke-[1.5]" />
          </div>
          {!isCollapsed && (
            <div className="flex flex-col overflow-hidden">
              <span className="text-xs font-mono font-medium tracking-tight text-[#F4F6F8] truncate">
                AegisVeto
              </span>
              <span className="text-[10px] font-mono text-[#8E95A2] tracking-wider truncate">
                GATEWAY L1
              </span>
            </div>
          )}
        </div>

        {!isCollapsed && (
          <button
            onClick={onToggleCollapse}
            className="text-[#8E95A2] hover:text-[#F4F6F8] p-1 transition-colors"
            title="Collapse sidebar"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Nav List */}
      <nav className="p-2 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              title={isCollapsed ? item.label : undefined}
              className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-mono transition-colors relative ${
                isActive
                  ? 'bg-[#141417] text-[#F4F6F8]'
                  : 'text-[#8E95A2] hover:text-[#F4F6F8] hover:bg-[#141417]/50'
              }`}
            >
              <Icon
                className={`w-4 h-4 shrink-0 stroke-[1.5] ${
                  isActive ? 'text-[#4D8BFF]' : 'text-[#8E95A2]'
                }`}
              />

              {!isCollapsed && <span className="truncate">{item.label}</span>}

              {/* Badge */}
              {item.badge !== undefined && item.badge > 0 && (
                <span
                  className={`flex items-center justify-center text-[10px] font-mono font-medium text-[#000000] bg-[#F59E0B] rounded-full shrink-0 ${
                    isCollapsed
                      ? 'absolute top-1.5 right-1.5 w-2 h-2 p-0'
                      : 'ml-auto px-1.5 py-0.2 min-w-[18px]'
                  }`}
                >
                  {!isCollapsed && item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Wide Empty Middle Spacer */}
      <div className="flex-1" />

      {/* Collapse Toggle for Collapsed Rail */}
      {isCollapsed && (
        <div className="p-2 border-t border-[#1E1E22] flex justify-center">
          <button
            onClick={onToggleCollapse}
            className="text-[#8E95A2] hover:text-[#F4F6F8] p-1.5 transition-colors"
            title="Expand sidebar"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Bottom Proxy Status */}
      <div className="h-11 border-t border-[#1E1E22] px-3 flex items-center justify-center sm:justify-start gap-2 bg-[#000000]">
        <div className="w-2 h-2 rounded-full bg-[#4D8BFF] shrink-0" />
        {!isCollapsed && (
          <div className="text-[11px] font-mono text-[#8E95A2] truncate">
            Proxy :3000
          </div>
        )}
      </div>
    </aside>
  );
};
