/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { ActiveTab, Sidebar } from './components/Sidebar';
import { Playground } from './components/Playground';
import { AnalyticsDashboard } from './components/AnalyticsDashboard';
import { AuditLogs } from './components/AuditLogs';
import { RulesAndSettings } from './components/RulesAndSettings';
import { TestSuiteRunner } from './components/TestSuiteRunner';
import { IntegrationGuide } from './components/IntegrationGuide';
import { ShieldCheck, Lock, Activity, Download, Play, CheckCircle2, Menu } from 'lucide-react';
import { DashboardStatistics } from './types';
import { getStatisticsApi } from './lib/api';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('playground');
  const [selectedApp, setSelectedApp] = useState<string>('all-apps');
  const [stats, setStats] = useState<DashboardStatistics | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const fetchStats = async () => {
    try {
      const data = await getStatisticsApi();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats', err);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const tabTitles: Record<ActiveTab, { title: string; subtitle: string; tag: string; tagColor: string }> = {
    playground: {
      title: 'Prompt Inspector & Playground',
      subtitle: 'Real-time injection detection, normalizer forensics & Gemini proxy',
      tag: 'Stage 4 Active',
      tagColor: 'bg-blue-50 text-blue-700 border-blue-200',
    },
    analytics: {
      title: 'Security Telemetry & Metrics',
      subtitle: 'Inspection volume, threat indices & mitigation rates',
      tag: 'Live Stream',
      tagColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    },
    logs: {
      title: 'Audit Logs & Review Trail',
      subtitle: 'Forensic records, masked payloads & false-positive review',
      tag: 'Audit Mode',
      tagColor: 'bg-yellow-50 text-yellow-800 border-yellow-200',
    },
    rules: {
      title: 'Rules & Threshold Tuning',
      subtitle: 'Threat score cutoffs, regex catalog & security policies',
      tag: 'Enforcing',
      tagColor: 'bg-purple-50 text-purple-700 border-purple-200',
    },
    testsuite: {
      title: 'Automated Evaluation Matrix',
      subtitle: 'Section 8 benchmark test harness (Safe, Obvious, Borderline, Encoded)',
      tag: 'PRD Ready',
      tagColor: 'bg-teal-50 text-teal-700 border-teal-200',
    },
    integration: {
      title: 'Middleware Integration SDK',
      subtitle: 'Python FastAPI, Node.js Express & LangChain integration snippets',
      tag: 'Developer SDK',
      tagColor: 'bg-slate-100 text-slate-700 border-slate-300',
    },
  };

  const currentTabInfo = tabTitles[activeTab];

  return (
    <div className="h-screen w-full bg-[#F1F5F9] flex overflow-hidden font-sans text-[#334155] antialiased selection:bg-blue-500/20 selection:text-blue-900">
      {/* Left Sidebar (Responsive Drawer on mobile, static on desktop) */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        selectedApp={selectedApp}
        setSelectedApp={setSelectedApp}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        stats={
          stats
            ? {
                totalRequests: stats.totalRequests,
                blockRatePercent: stats.blockRatePercent,
                avgScore: stats.averageThreatScore,
              }
            : undefined
        }
      />

      {/* Main Workspace */}
      <main className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* High Density Top Header */}
        <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-3 sm:px-6 shrink-0 shadow-2xs gap-2">
          {/* Header Title & Status */}
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="p-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 lg:hidden transition-colors cursor-pointer shrink-0"
              aria-label="Open navigation menu"
            >
              <Menu className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-2 min-w-0">
              <h1 className="text-xs sm:text-sm font-bold text-slate-900 uppercase tracking-tight truncate">
                {currentTabInfo.title}
              </h1>
              <span
                className={`hidden sm:inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase border whitespace-nowrap ${currentTabInfo.tagColor}`}
              >
                {currentTabInfo.tag}
              </span>
            </div>
          </div>

          {/* Quick Header Controls */}
          <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
            {stats && (
              <div className="hidden xl:flex items-center gap-3 text-xs text-slate-500 bg-slate-50 px-3 py-1 rounded-md border border-slate-200 font-medium">
                <span>
                  Scanned: <strong className="text-slate-800 font-bold">{stats.totalRequests}</strong>
                </span>
                <span className="text-slate-300">|</span>
                <span>
                  Blocked: <strong className="text-rose-600 font-bold">{stats.blockedCount}</strong>
                </span>
              </div>
            )}

            <button
              onClick={() => setActiveTab('testsuite')}
              className="px-2.5 sm:px-3 py-1.5 text-xs border border-slate-300 rounded-md font-semibold text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer shadow-2xs flex items-center gap-1.5"
            >
              <Play className="h-3 w-3 fill-current text-blue-600 shrink-0" />
              <span className="hidden sm:inline">Benchmark Matrix</span>
              <span className="sm:hidden">Matrix</span>
            </button>

            <button
              onClick={() => window.open('/api/export?format=json', '_blank')}
              className="px-2.5 sm:px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-md font-semibold shadow-2xs transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <Download className="h-3 w-3 shrink-0" />
              <span className="hidden sm:inline">Export Audit</span>
              <span className="sm:hidden">Export</span>
            </button>
          </div>
        </header>

        {/* Workspace Content Canvas */}
        <div className="p-3 sm:p-4 md:p-6 flex-1 overflow-y-auto overflow-x-hidden">
          <div className="max-w-7xl mx-auto space-y-5">
            {activeTab === 'playground' && (
              <Playground selectedApp={selectedApp} onEventLogged={fetchStats} />
            )}

            {activeTab === 'analytics' && <AnalyticsDashboard />}

            {activeTab === 'logs' && <AuditLogs selectedApp={selectedApp} />}

            {activeTab === 'rules' && <RulesAndSettings />}

            {activeTab === 'testsuite' && <TestSuiteRunner />}

            {activeTab === 'integration' && <IntegrationGuide />}
          </div>
        </div>
      </main>
    </div>
  );
}
