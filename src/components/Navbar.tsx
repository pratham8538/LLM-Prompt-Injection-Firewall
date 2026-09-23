import React from 'react';
import {
  ShieldCheck,
  Activity,
  FileText,
  Sliders,
  CheckCircle2,
  Code2,
  Layers,
  Sparkles,
} from 'lucide-react';

export type ActiveTab = 'playground' | 'analytics' | 'logs' | 'rules' | 'testsuite' | 'integration';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  selectedApp: string;
  setSelectedApp: (app: string) => void;
  stats?: { totalRequests: number; blockRatePercent: number; avgScore: number };
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  selectedApp,
  setSelectedApp,
  stats,
}) => {
  const apps = ['all-apps', 'customer-portal', 'public-api-gateway', 'internal-copilot', 'chatbot-widget', 'devops-bot'];

  const navItems = [
    { id: 'playground', label: 'Inspector & Playground', icon: ShieldCheck },
    { id: 'analytics', label: 'Security Analytics', icon: Activity },
    { id: 'logs', label: 'Audit Logs & Review', icon: FileText },
    { id: 'rules', label: 'Rules & Thresholds', icon: Sliders },
    { id: 'testsuite', label: 'Evaluation Matrix', icon: CheckCircle2 },
    { id: 'integration', label: 'Middleware SDK', icon: Code2 },
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-900/95 backdrop-blur border-b border-slate-800 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/20 ring-1 ring-white/20">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">
                  PromptGuard
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  Middleware Active
                </span>
              </div>
              <p className="text-xs text-slate-400 font-medium">LLM Prompt Injection Firewall</p>
            </div>
          </div>

          {/* Quick Metrics Badge */}
          {stats && (
            <div className="hidden lg:flex items-center space-x-6 text-xs text-slate-400 bg-slate-800/60 px-4 py-1.5 rounded-lg border border-slate-700/60">
              <div>
                Scanned: <span className="font-semibold text-slate-200">{stats.totalRequests}</span>
              </div>
              <div className="h-3 w-px bg-slate-700" />
              <div>
                Block Rate: <span className="font-semibold text-rose-400">{stats.blockRatePercent}%</span>
              </div>
              <div className="h-3 w-px bg-slate-700" />
              <div>
                Avg Threat: <span className="font-semibold text-amber-400">{stats.avgScore}/100</span>
              </div>
            </div>
          )}

          {/* Multi-Tenant App Selector */}
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5 bg-slate-800/80 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-300">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <label htmlFor="app-select" className="text-slate-400 font-medium">App Scope:</label>
              <select
                id="app-select"
                value={selectedApp}
                onChange={(e) => setSelectedApp(e.target.value)}
                className="bg-transparent font-medium text-slate-200 focus:outline-none cursor-pointer"
              >
                {apps.map((app) => (
                  <option key={app} value={app} className="bg-slate-900 text-slate-200">
                    {app === 'all-apps' ? '🌐 All Applications' : `📦 ${app}`}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 overflow-x-auto no-scrollbar py-2 border-t border-slate-800/60">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`tab-${item.id}`}
                onClick={() => setActiveTab(item.id as ActiveTab)}
                className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
