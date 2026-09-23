import React, { useEffect, useState } from 'react';
import {
  FileText,
  Search,
  Filter,
  Download,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Eye,
  Lock,
  Hash,
  Clock,
  ShieldAlert,
  Tag,
  ChevronRight,
  X,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { SecurityLogEvent } from '../types';
import { getLogsApi, reviewLogApi } from '../lib/api';

interface AuditLogsProps {
  selectedApp: string;
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ selectedApp }) => {
  const [logs, setLogs] = useState<SecurityLogEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [privacyMode, setPrivacyMode] = useState<'raw' | 'masked' | 'hash'>('raw');
  const [selectedLog, setSelectedLog] = useState<SecurityLogEvent | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [savingReview, setSavingReview] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [newLogFlash, setNewLogFlash] = useState(false);

  const fetchLogs = async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    try {
      const data = await getLogsApi({
        action: actionFilter,
        risk: riskFilter,
        applicationId: selectedApp,
        search,
      });
      const newLogs = data.logs || [];
      setLogs((prev) => {
        if (isBackground && newLogs.length > 0 && prev.length > 0 && newLogs[0].id !== prev[0].id) {
          setNewLogFlash(true);
          setTimeout(() => setNewLogFlash(false), 2500);
        }
        return newLogs;
      });
    } catch (err) {
      console.error('Failed to load logs', err);
    } finally {
      if (!isBackground) setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(false);
  }, [actionFilter, riskFilter, selectedApp, search]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchLogs(true);
    }, 1500);
    return () => clearInterval(interval);
  }, [autoRefresh, actionFilter, riskFilter, selectedApp, search]);

  const handleReview = async (status: SecurityLogEvent['reviewStatus']) => {
    if (!selectedLog) return;
    setSavingReview(true);
    try {
      const updated = await reviewLogApi(selectedLog.id, status, reviewNotes);
      setSelectedLog(updated);
      setLogs((prev) => prev.map((l) => (l.id === updated.id ? updated : l)));
    } catch (err) {
      console.error('Failed to update review status', err);
    } finally {
      setSavingReview(false);
    }
  };

  const getDisplayPrompt = (log: SecurityLogEvent) => {
    if (privacyMode === 'hash') return `[SHA-256: ${log.promptHash}]`;
    if (privacyMode === 'masked') return log.maskedPrompt;
    return log.prompt;
  };

  const handleExport = (format: 'json' | 'csv') => {
    window.open(`/api/export?format=${format}`, '_blank');
  };

  return (
    <div className="space-y-5">
      {/* High Density Header & Filter Section */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 sm:p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 sm:gap-4 border-b border-slate-100 pb-4">
          <div>
            <h2 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-0.5">
              Forensic Trail
            </h2>
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-600 shrink-0" />
              <span>Security Audit Event Stream</span>
            </h3>
          </div>

          {/* Privacy & Export buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Privacy Toggle */}
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs">
              <button
                onClick={() => setPrivacyMode('raw')}
                className={`px-2 sm:px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer transition-all ${
                  privacyMode === 'raw' ? 'bg-white text-blue-600 font-bold shadow-2xs' : 'text-slate-600'
                }`}
              >
                <Eye className="h-3 w-3 shrink-0" />
                <span>Full View</span>
              </button>
              <button
                onClick={() => setPrivacyMode('masked')}
                className={`px-2 sm:px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer transition-all ${
                  privacyMode === 'masked' ? 'bg-white text-blue-600 font-bold shadow-2xs' : 'text-slate-600'
                }`}
              >
                <Lock className="h-3 w-3 shrink-0" />
                <span>Masked</span>
              </button>
              <button
                onClick={() => setPrivacyMode('hash')}
                className={`px-2 sm:px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer transition-all ${
                  privacyMode === 'hash' ? 'bg-white text-blue-600 font-bold shadow-2xs' : 'text-slate-600'
                }`}
              >
                <Hash className="h-3 w-3 shrink-0" />
                <span>Hash</span>
              </button>
            </div>

            {/* Live Stream Auto-Refresh Toggle */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`px-2.5 sm:px-3 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all border cursor-pointer shadow-2xs ${
                autoRefresh
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
              }`}
              title={autoRefresh ? 'Live Auto-Polling Active (1.5s)' : 'Live Auto-Polling Paused'}
            >
              <span className={`inline-block w-2 h-2 rounded-full ${autoRefresh ? 'bg-emerald-500 animate-ping' : 'bg-slate-400'}`} />
              <span>{autoRefresh ? 'Live Feed (1.5s)' : 'Live Paused'}</span>
            </button>

            {/* Manual Refresh */}
            <button
              onClick={() => fetchLogs(false)}
              className="p-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 rounded-lg border border-slate-200 text-xs transition-all cursor-pointer shadow-2xs"
              title="Refresh Logs Manually"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-blue-600' : ''}`} />
            </button>

            {/* Export buttons */}
            <div className="flex items-center gap-1">
              <button
                onClick={() => handleExport('csv')}
                className="px-2.5 sm:px-3 py-1 bg-slate-50 hover:bg-slate-100 text-slate-700 rounded-lg border border-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-2xs"
              >
                <Download className="h-3.5 w-3.5" />
                <span>CSV</span>
              </button>
              <button
                onClick={() => handleExport('json')}
                className="px-2.5 sm:px-3 py-1 bg-slate-50 hover:bg-slate-100 text-slate-700 rounded-lg border border-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-2xs"
              >
                <Download className="h-3.5 w-3.5" />
                <span>JSON</span>
              </button>
            </div>
          </div>
        </div>

        {/* Filter Row */}
        <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-center pt-1">
          {/* Search */}
          <div className="sm:col-span-6 relative">
            <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search prompt payload, event ID, or category..."
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:bg-white"
            />
          </div>

          {/* Action Filter */}
          <div className="sm:col-span-3">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer font-medium"
            >
              <option value="ALL">Decision: All Actions</option>
              <option value="ALLOW">ALLOW Only</option>
              <option value="WARN">WARN Only</option>
              <option value="BLOCK">BLOCK Only</option>
            </select>
          </div>

          {/* Risk Filter */}
          <div className="sm:col-span-3">
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer font-medium"
            >
              <option value="ALL">Risk: All Tiers</option>
              <option value="LOW">LOW Risk</option>
              <option value="MEDIUM">MEDIUM Risk</option>
              <option value="HIGH">HIGH Risk</option>
            </select>
          </div>
        </div>
      </div>

      {newLogFlash && (
        <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white text-xs font-bold px-4 py-2.5 rounded-xl flex items-center justify-between shadow-md animate-pulse">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-white animate-ping" />
            <span>⚡ New Prompt Intercepted & Processed in Real-Time!</span>
          </div>
          <span className="text-[10px] bg-black/20 px-2 py-0.5 rounded tracking-wider uppercase font-extrabold">Instant Feed</span>
        </div>
      )}

      {/* High Density Logs Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-700">
            <thead className="bg-slate-50 border-b border-slate-200 uppercase tracking-wider text-[10px] text-slate-500 font-bold">
              <tr>
                <th className="px-4 py-2.5">Timestamp / ID</th>
                <th className="px-4 py-2.5">App Scope</th>
                <th className="px-4 py-2.5">Decision</th>
                <th className="px-4 py-2.5">Score</th>
                <th className="px-4 py-2.5">Prompt Excerpt</th>
                <th className="px-4 py-2.5">Review Status</th>
                <th className="px-4 py-2.5 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {logs.length > 0 ? (
                logs.map((log) => {
                  const d = new Date(log.timestamp);
                  const timeFormatted = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

                  return (
                    <tr
                      key={log.id}
                      onClick={() => {
                        setSelectedLog(log);
                        setReviewNotes(log.reviewNotes || '');
                      }}
                      className="hover:bg-slate-50 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-[11px] whitespace-nowrap">
                        <div className="font-bold text-slate-900">{timeFormatted}</div>
                        <div className="text-[10px] text-slate-400 truncate max-w-[100px]">{log.id}</div>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-mono font-medium">
                          {log.applicationId}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            log.action === 'BLOCK'
                              ? 'bg-rose-50 text-rose-700 border-rose-200'
                              : log.action === 'WARN'
                              ? 'bg-amber-50 text-amber-700 border-amber-200'
                              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono font-bold whitespace-nowrap">
                        <span
                          className={
                            log.threatScore >= 70
                              ? 'text-rose-600'
                              : log.threatScore >= 40
                              ? 'text-amber-600'
                              : 'text-emerald-600'
                          }
                        >
                          {log.threatScore}
                        </span>
                        <span className="text-[10px] text-slate-400 font-normal">/100</span>
                      </td>
                      <td className="px-4 py-2.5 max-w-xs sm:max-w-md truncate font-mono text-slate-800 text-[11px]">
                        {getDisplayPrompt(log)}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                            log.reviewStatus === 'CONFIRMED_ATTACK'
                              ? 'bg-rose-100 text-rose-800'
                              : log.reviewStatus === 'FALSE_POSITIVE'
                              ? 'bg-purple-100 text-purple-800'
                              : log.reviewStatus === 'LEGITIMATE'
                              ? 'bg-emerald-100 text-emerald-800'
                              : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          {log.reviewStatus}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <ChevronRight className="h-4 w-4 text-slate-400 inline" />
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400">
                    No security events found matching current criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-2xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-blue-600" />
                <h3 className="font-bold text-slate-900 text-base">Security Event Forensics</h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-all cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Top summary row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-bold uppercase">Decision:</span>
                <span className="font-bold text-slate-900">{selectedLog.action}</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-bold uppercase">Threat Score:</span>
                <span className="font-bold text-amber-600 font-mono">{selectedLog.threatScore}/100</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-bold uppercase">Latency Overhead:</span>
                <span className="font-bold text-blue-600 font-mono">{selectedLog.latencyMs} ms</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-400 block text-[10px] font-bold uppercase">Downstream:</span>
                <span className="font-bold text-slate-800">{selectedLog.downstreamCalled ? 'Yes' : 'No (Blocked)'}</span>
              </div>
            </div>

            {/* Prompt Content */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-500">
                <span>Inspected Prompt Payload:</span>
                <span className="font-mono text-[10px] text-slate-400">SHA-256: {selectedLog.promptHash}</span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs font-mono text-slate-100 max-h-32 overflow-y-auto whitespace-pre-wrap">
                {selectedLog.prompt}
              </div>
            </div>

            {/* Detections breakdown */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-700 block uppercase tracking-wider text-[10px]">
                Triggered Rule Signatures:
              </span>
              {selectedLog.detections && selectedLog.detections.length > 0 ? (
                <div className="space-y-2">
                  {selectedLog.detections.map((det, i) => (
                    <div key={i} className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-xs space-y-1">
                      <div className="flex items-center justify-between font-bold text-rose-700">
                        <span>{det.category}</span>
                        <span className="font-mono text-[10px] text-rose-800">Severity: +{det.severity}</span>
                      </div>
                      <p className="text-slate-600 text-[11px]">{det.description}</p>
                      <div className="bg-slate-900 p-1.5 rounded font-mono text-[10px] text-amber-300">
                        Snippet: "{det.matchedSnippet}"
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-xs text-slate-500">
                  No explicit pattern rules triggered. Decision based on standard threshold.
                </div>
              )}
            </div>

            {/* AI Guardrail Inspection section */}
            {selectedLog.aiInspection && (
              <div className="space-y-2 p-3 bg-purple-50/60 rounded-xl border border-purple-200 text-xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-bold text-purple-900">
                    <Sparkles className="h-4 w-4 text-purple-600" />
                    <span>AI Guardrail Analysis ({selectedLog.aiInspection.analyzedBy})</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      selectedLog.aiInspection.isSuspicious
                        ? 'bg-rose-100 text-rose-800'
                        : 'bg-emerald-100 text-emerald-800'
                    }`}
                  >
                    {selectedLog.aiInspection.isSuspicious ? 'Suspicious' : 'Benign'} ({Math.round(selectedLog.aiInspection.confidence * 100)}%)
                  </span>
                </div>
                <div className="bg-white p-2 rounded border border-purple-100 text-slate-800 space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block">Intent:</span>
                  <div className="font-medium text-slate-900">{selectedLog.aiInspection.detectedIntent}</div>
                </div>
                <div className="bg-white p-2 rounded border border-purple-100 text-slate-700 space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block">Reasoning:</span>
                  <div className="text-slate-600 leading-relaxed text-[11px]">{selectedLog.aiInspection.reasoning}</div>
                </div>
              </div>
            )}

            {/* Analyst Review Section */}
            <div className="border-t border-slate-100 pt-3 space-y-3 bg-slate-50 p-4 rounded-xl border border-slate-200">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
                <Tag className="h-4 w-4 text-blue-600" />
                <span>Analyst Review & Precision Tuning</span>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => handleReview('CONFIRMED_ATTACK')}
                  disabled={savingReview}
                  className={`px-3 py-1.5 rounded text-xs font-bold border transition-all cursor-pointer ${
                    selectedLog.reviewStatus === 'CONFIRMED_ATTACK'
                      ? 'bg-rose-600 text-white border-rose-700 shadow-2xs'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  🔴 Confirmed Attack
                </button>
                <button
                  onClick={() => handleReview('FALSE_POSITIVE')}
                  disabled={savingReview}
                  className={`px-3 py-1.5 rounded text-xs font-bold border transition-all cursor-pointer ${
                    selectedLog.reviewStatus === 'FALSE_POSITIVE'
                      ? 'bg-purple-600 text-white border-purple-700 shadow-2xs'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  🟣 False Positive
                </button>
                <button
                  onClick={() => handleReview('LEGITIMATE')}
                  disabled={savingReview}
                  className={`px-3 py-1.5 rounded text-xs font-bold border transition-all cursor-pointer ${
                    selectedLog.reviewStatus === 'LEGITIMATE'
                      ? 'bg-emerald-600 text-white border-emerald-700 shadow-2xs'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  🟢 Legitimate Prompt
                </button>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-500 font-bold uppercase block">
                  Review Notes / Context:
                </label>
                <input
                  type="text"
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="e.g., Prompt contained academic question, safe to lower weight on override keyword..."
                  className="w-full bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
