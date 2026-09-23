import React from 'react';
import {
  ShieldCheck,
  Activity,
  FileText,
  Sliders,
  CheckCircle2,
  Code2,
  Layers,
  Shield,
  Zap,
  Server,
  X,
} from 'lucide-react';

export type ActiveTab = 'playground' | 'analytics' | 'logs' | 'rules' | 'testsuite' | 'integration';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  selectedApp: string;
  setSelectedApp: (app: string) => void;
  stats?: { totalRequests: number; blockRatePercent: number; avgScore: number };
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  selectedApp,
  setSelectedApp,
  stats,
  mobileOpen = false,
  onCloseMobile,
}) => {
  const apps = [
    { id: 'all-apps', label: 'All Applications' },
    { id: 'customer-portal', label: 'Customer Portal' },
    { id: 'public-api-gateway', label: 'Public API Gateway' },
    { id: 'internal-copilot', label: 'Internal Copilot' },
    { id: 'chatbot-widget', label: 'Chatbot Widget' },
    { id: 'devops-bot', label: 'DevOps Bot' },
  ];

  const navGroups = [
    {
      group: 'Security Operations',
      items: [
        { id: 'playground', label: 'Prompt Inspector', icon: ShieldCheck, tag: 'Live' },
        { id: 'analytics', label: 'Threat Telemetry', icon: Activity, tag: null },
        { id: 'logs', label: 'Audit Log Stream', icon: FileText, tag: null },
      ],
    },
    {
      group: 'Policy & Architecture',
      items: [
        { id: 'rules', label: 'Rules & Thresholds', icon: Sliders, tag: null },
        { id: 'testsuite', label: 'Evaluation Matrix', icon: CheckCircle2, tag: 'PRD' },
        { id: 'integration', label: 'Middleware SDK', icon: Code2, tag: null },
      ],
    },
  ];

  const safeRate = stats ? Math.max(0, 100 - stats.blockRatePercent) : 88;

  const handleTabClick = (tabId: ActiveTab) => {
    setActiveTab(tabId);
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-slate-900/60 backdrop-blur-xs lg:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-72 sm:w-64 bg-[#0F172A] text-slate-300 flex flex-col shrink-0 h-full border-r border-slate-800 selection:bg-blue-600 selection:text-white transition-transform duration-300 ease-in-out lg:static lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white shadow-sm ring-1 ring-blue-400/30">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-sm tracking-tight flex items-center gap-1.5">
                <span>PromptGuard</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded font-mono">
                  v1.0
                </span>
              </div>
              <div className="text-[10px] text-slate-400 font-medium tracking-tight">
                LLM Security Middleware
              </div>
            </div>
          </div>

          {/* Close button for mobile drawer */}
          <button
            onClick={onCloseMobile}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg lg:hidden transition-colors cursor-pointer"
            aria-label="Close navigation menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* App Scope Tenant Selector */}
        <div className="p-3 border-b border-slate-800/80 bg-slate-900/50">
          <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold px-1 mb-1.5 flex items-center justify-between">
            <span className="flex items-center gap-1">
              <Layers className="h-3 w-3 text-cyan-400" />
              <span>Target Application</span>
            </span>
            <span className="text-[9px] text-slate-500 font-mono font-normal">Tenant</span>
          </div>
          <select
            id="sidebar-app-select"
            value={selectedApp}
            onChange={(e) => setSelectedApp(e.target.value)}
            className="w-full bg-[#1E293B] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer font-medium"
          >
            {apps.map((app) => (
              <option key={app.id} value={app.id} className="bg-[#0F172A] text-slate-200">
                {app.label}
              </option>
            ))}
          </select>
        </div>

        {/* Navigation Groups */}
        <nav className="flex-1 p-3 space-y-4 overflow-y-auto">
          {navGroups.map((group, idx) => (
            <div key={idx} className="space-y-1">
              <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold px-2 mb-1.5">
                {group.group}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    id={`sidebar-tab-${item.id}`}
                    onClick={() => handleTabClick(item.id as ActiveTab)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors cursor-pointer text-left ${
                      isActive
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`h-4 w-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.tag && (
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${
                          isActive
                            ? 'bg-blue-700 text-white'
                            : 'bg-slate-800 text-cyan-400 border border-slate-700'
                        }`}
                      >
                        {item.tag}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Gateway Health Mini Widget */}
        <div className="p-3 border-t border-slate-800 bg-[#1E293B]/60 space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[11px] font-bold text-white uppercase tracking-tight">
                Gateway Health
              </span>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 font-bold">{safeRate}% Normal</span>
          </div>

          <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-emerald-400 rounded-full shadow-[0_0_8px_rgba(74,222,128,0.5)] transition-all duration-500"
              style={{ width: `${safeRate}%` }}
            />
          </div>

          <div className="grid grid-cols-2 gap-2 pt-1 text-center">
            <div className="bg-[#0F172A]/70 p-1.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Attacks Blocked</div>
              <div className="text-xs font-bold text-rose-400 font-mono">
                {stats?.blockRatePercent ?? 12}%
              </div>
            </div>
            <div className="bg-[#0F172A]/70 p-1.5 rounded border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Fail-Closed</div>
              <div className="text-xs font-bold text-emerald-400 font-mono">Armed</div>
            </div>
          </div>
        </div>

        {/* Bottom User / Integration Status */}
        <div className="p-3 border-t border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-slate-700 flex items-center justify-center text-[10px] font-bold text-white">
              <Server className="h-3 w-3 text-cyan-400" />
            </div>
            <div className="text-[11px]">
              <div className="text-white font-medium">Gemini 3.7 Flash</div>
              <div className="text-[10px] text-slate-400">Protected Target</div>
            </div>
          </div>
          <div className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
            Online
          </div>
        </div>
      </aside>
    </>
  );
};
