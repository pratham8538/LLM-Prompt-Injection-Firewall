/**
 * Unified API Client for PromptGuard Firewall
 * Automatically handles network requests with seamless fallback to client-side engine
 * to ensure zero "Failed to fetch" errors.
 */

import {
  ChatRequestPayload,
  ChatResponsePayload,
  DashboardStatistics,
  FirewallAnalysisResult,
  FirewallSettings,
  RuleDefinition,
  SecurityLogEvent,
  TestSuiteItem,
} from '../types';
import { clientAnalyzePrompt, clientStore } from './clientFirewall';

// Helper for fetch with timeout
async function safeFetch<T>(url: string, options?: RequestInit, fallback?: () => T): Promise<T> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP error ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    if (fallback) {
      console.warn(`[PromptGuard] Network request to ${url} unavailable, using local engine:`, err);
      return fallback();
    }
    throw err;
  }
}

// 1. Analyze Prompt Only (JSON)
export async function analyzePromptApi(
  prompt: string,
  applicationId = 'demo-web-app'
): Promise<FirewallAnalysisResult> {
  return safeFetch<FirewallAnalysisResult>(
    '/api/inspect',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, application_id: applicationId }),
    },
    () => {
      const rules = clientStore.getRules();
      const settings = clientStore.getSettings();
      const analysis = clientAnalyzePrompt(prompt, rules, settings, applicationId);
      clientStore.addLog(analysis, false, 'ANALYSIS_ONLY');
      return analysis;
    }
  );
}

// 1b. Inspect Raw Prompt (Supports plain text, unstructured language, non-JSON formats)
export async function inspectPromptRawApi(
  payload: string,
  format: 'json' | 'text/plain' = 'text/plain',
  applicationId = 'demo-web-app'
): Promise<FirewallAnalysisResult> {
  const isJson = format === 'json';
  return safeFetch<FirewallAnalysisResult>(
    '/api/inspect',
    {
      method: 'POST',
      headers: { 'Content-Type': isJson ? 'application/json' : 'text/plain' },
      body: isJson ? JSON.stringify({ prompt: payload, applicationId }) : payload,
    },
    () => {
      const rules = clientStore.getRules();
      const settings = clientStore.getSettings();
      const analysis = clientAnalyzePrompt(payload, rules, settings, applicationId);
      clientStore.addLog(analysis, false, 'ANALYSIS_ONLY');
      return analysis;
    }
  );
}

// 2. Chat w/ LLM Proxy
export async function chatPromptApi(
  payload: ChatRequestPayload
): Promise<ChatResponsePayload> {
  return safeFetch<ChatResponsePayload>(
    '/api/chat',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    () => {
      const rules = clientStore.getRules();
      const settings = clientStore.getSettings();
      const analysis = clientAnalyzePrompt(payload.prompt, rules, settings, payload.application_id || 'demo-web-app');

      let downstreamResponse: string | undefined;
      let downstreamStatus: string;
      let downstreamCalled = false;

      if (analysis.action === 'BLOCK') {
        downstreamStatus = 'BLOCKED_BY_FIREWALL';
      } else {
        downstreamCalled = true;
        downstreamStatus = 'SUCCESS';
        downstreamResponse = `[Simulated LLM Response] I have received and verified your prompt ("${payload.prompt}"). The prompt successfully cleared the PromptGuard inspection with threat score ${analysis.threatScore}/100 and action ${analysis.action}.`;
      }

      clientStore.addLog(analysis, downstreamCalled, downstreamStatus);

      return {
        requestId: analysis.requestId,
        threatScore: analysis.threatScore,
        riskLevel: analysis.riskLevel,
        firewallDecision: analysis.action,
        downstreamCalled,
        downstreamStatus,
        downstreamResponse,
        firewallLatencyMs: analysis.latencyMs,
        detections: analysis.detections,
        heuristics: analysis.heuristics,
      };
    }
  );
}

// 3. Statistics
export async function getStatisticsApi(): Promise<DashboardStatistics> {
  return safeFetch<DashboardStatistics>(
    '/api/statistics',
    { method: 'GET' },
    () => clientStore.getStatistics()
  );
}

// 4. Audit Logs
export async function getLogsApi(options: {
  action?: string;
  risk?: string;
  applicationId?: string;
  search?: string;
} = {}): Promise<{ logs: SecurityLogEvent[]; total: number }> {
  const params = new URLSearchParams();
  if (options.action && options.action !== 'ALL') params.append('action', options.action);
  if (options.risk && options.risk !== 'ALL') params.append('risk', options.risk);
  if (options.applicationId && options.applicationId !== 'all-apps') params.append('applicationId', options.applicationId);
  if (options.search) params.append('search', options.search);

  return safeFetch<{ logs: SecurityLogEvent[]; total: number }>(
    `/api/logs?${params.toString()}`,
    { method: 'GET' },
    () => clientStore.getLogs(options)
  );
}

// 5. Review Log Status
export async function reviewLogApi(
  logId: string,
  status: SecurityLogEvent['reviewStatus'],
  notes?: string
): Promise<SecurityLogEvent> {
  return safeFetch<SecurityLogEvent>(
    `/api/logs/${logId}/review`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes }),
    },
    () => {
      const updated = clientStore.updateReviewStatus(logId, status, notes);
      if (!updated) throw new Error('Log not found');
      return updated;
    }
  );
}

// 6. Settings
export async function getSettingsApi(): Promise<FirewallSettings> {
  return safeFetch<FirewallSettings>(
    '/api/settings',
    { method: 'GET' },
    () => clientStore.getSettings()
  );
}

export async function updateSettingsApi(settings: FirewallSettings): Promise<FirewallSettings> {
  return safeFetch<FirewallSettings>(
    '/api/settings',
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    },
    () => clientStore.updateSettings(settings)
  );
}

// 7. Rules
export async function getRulesApi(): Promise<RuleDefinition[]> {
  return safeFetch<RuleDefinition[]>(
    '/api/rules',
    { method: 'GET' },
    () => clientStore.getRules()
  );
}

export async function updateRuleApi(
  ruleId: string,
  updates: Partial<RuleDefinition>
): Promise<RuleDefinition> {
  return safeFetch<RuleDefinition>(
    `/api/rules/${ruleId}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    },
    () => {
      const updated = clientStore.updateRule(ruleId, updates);
      if (!updated) throw new Error('Rule not found');
      return updated;
    }
  );
}

export async function createRuleApi(
  rule: Omit<RuleDefinition, 'id' | 'isCustom'>
): Promise<RuleDefinition> {
  return safeFetch<RuleDefinition>(
    '/api/rules',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    },
    () => clientStore.addCustomRule(rule)
  );
}

export async function deleteRuleApi(ruleId: string): Promise<{ success: boolean }> {
  return safeFetch<{ success: boolean }>(
    `/api/rules/${ruleId}`,
    { method: 'DELETE' },
    () => ({ success: clientStore.deleteRule(ruleId) })
  );
}

// 8. Test Suite
export async function getTestSuiteApi(): Promise<TestSuiteItem[]> {
  return safeFetch<TestSuiteItem[]>(
    '/api/test-suite',
    { method: 'GET' },
    () => clientStore.getTestSuite()
  );
}

export async function runTestSuiteApi(): Promise<{
  total: number;
  passedCount: number;
  failedCount: number;
  accuracyPercent: number;
  falsePositiveCount: number;
  falseNegativeCount: number;
  results: TestSuiteItem[];
}> {
  return safeFetch(
    '/api/test-suite/run',
    { method: 'POST' },
    () => clientStore.runTestSuite()
  );
}
