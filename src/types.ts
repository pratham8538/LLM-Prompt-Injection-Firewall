export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type FirewallAction = 'ALLOW' | 'WARN' | 'BLOCK';

export type DetectionCategory =
  | 'INSTRUCTION_OVERRIDE'
  | 'SYSTEM_PROMPT_EXTRACTION'
  | 'JAILBREAK_ATTEMPT'
  | 'ENCODED_PAYLOAD'
  | 'SUSPICIOUS_DELIMITER_OR_TAG'
  | 'HEURISTIC_ANOMALY'
  | 'HOMOGLYPH_OR_INVISIBLE_CHARS'
  | 'AI_SEMANTIC_ANALYSIS'
  | 'ROLEPLAY_DECEPTION'
  | 'INDIRECT_INJECTION'
  | 'CUSTOM_RULE';

export interface AiInspectionResult {
  enabled: boolean;
  analyzedBy: string;
  isSuspicious: boolean;
  threatScore: number;
  riskLevel: RiskLevel;
  action: FirewallAction;
  category: DetectionCategory | 'BENIGN';
  reasoning: string;
  detectedIntent: string;
  confidence: number;
  latencyMs: number;
}

export interface RuleDetection {
  ruleId: string;
  category: DetectionCategory;
  severity: number;
  matchedPattern: string;
  matchedSnippet: string;
  description: string;
  confidence: number;
}

export interface DecodedPayload {
  type: 'BASE64' | 'HEX' | 'URL_ENCODED' | 'ROT13' | 'LEETSPEAK';
  raw: string;
  decoded: string;
  injectionDetected: boolean;
}

export interface FirewallHeuristics {
  inputLength: number;
  normalizedLength: number;
  zeroWidthCharsDetected: number;
  homoglyphsSubstituted: number;
  decodedPayloads: DecodedPayload[];
  imperativeDensity: number;
  delimiterTamperingDetected: boolean;
  academicContextDetected: boolean;
  suspiciousTokensCount: number;
}

export interface FirewallAnalysisResult {
  requestId: string;
  timestamp: string;
  threatScore: number;
  riskLevel: RiskLevel;
  action: FirewallAction;
  detections: RuleDetection[];
  heuristics: FirewallHeuristics;
  normalizedPrompt: string;
  latencyMs: number;
  applicationId: string;
  failClosed: boolean;
  aiInspection?: AiInspectionResult;
}

export interface SecurityLogEvent {
  id: string;
  timestamp: string;
  applicationId: string;
  prompt: string;
  maskedPrompt: string;
  promptHash: string;
  threatScore: number;
  riskLevel: RiskLevel;
  action: FirewallAction;
  detections: RuleDetection[];
  heuristics: FirewallHeuristics;
  latencyMs: number;
  downstreamCalled: boolean;
  downstreamLatencyMs?: number;
  downstreamStatus?: string;
  downstreamResponse?: string;
  provider?: string;
  reviewStatus: 'PENDING' | 'CONFIRMED_ATTACK' | 'FALSE_POSITIVE' | 'LEGITIMATE';
  reviewNotes?: string;
  reviewedAt?: string;
  aiInspection?: AiInspectionResult;
}

export interface FirewallSettings {
  lowThreshold: number;
  blockThreshold: number;
  failClosed: boolean;
  maskLogs: boolean;
  hashOnly: boolean;
  retentionDays: number;
  defaultProvider: 'gemini' | 'openai' | 'claude' | 'local_mock';
  academicContextDamping: boolean;
  logRetentionCount: number;
  strictHomoglyphBlocking: boolean;
  enableAiInspection?: boolean;
}

export interface RuleDefinition {
  id: string;
  name: string;
  category: DetectionCategory;
  weight: number;
  enabled: boolean;
  patterns: string[];
  description: string;
  isCustom?: boolean;
}

export interface DashboardStatistics {
  totalRequests: number;
  allowedCount: number;
  warnedCount: number;
  blockedCount: number;
  averageThreatScore: number;
  blockRatePercent: number;
  averageLatencyMs: number;
  categoryCounts: Record<DetectionCategory, number>;
  hourlyTrend: { hour: string; allowed: number; warned: number; blocked: number; avgScore: number }[];
  applicationDistribution: { app: string; count: number; blocked: number }[];
  riskDistribution: { risk: RiskLevel; count: number; percentage: number }[];
  falsePositiveRatePercent: number;
}

export interface ChatRequestPayload {
  prompt: string;
  application_id?: string;
  session_id?: string;
  system_context?: string;
}

export interface ChatResponsePayload {
  requestId: string;
  firewallDecision: FirewallAction;
  riskLevel: RiskLevel;
  threatScore: number;
  detections: RuleDetection[];
  heuristics: FirewallHeuristics;
  firewallLatencyMs: number;
  downstreamCalled: boolean;
  downstreamResponse?: string;
  downstreamLatencyMs?: number;
  provider?: string;
  model?: string;
  message?: string;
  error?: string;
  aiInspection?: AiInspectionResult;
}

export interface TestSuiteItem {
  id: string;
  name: string;
  category: 'SAFE' | 'OBVIOUS_INJECTION' | 'BORDERLINE' | 'ENCODED' | 'ADVANCED';
  prompt: string;
  expectedAction: FirewallAction;
  expectedRisk: RiskLevel;
  description: string;
  lastResult?: {
    action: FirewallAction;
    score: number;
    passed: boolean;
    latencyMs: number;
  };
}
