/**
 * LLM Prompt Injection Firewall - Core Detection Engine
 */

import crypto from 'crypto';
import {
  DecodedPayload,
  FirewallAction,
  FirewallAnalysisResult,
  FirewallHeuristics,
  FirewallSettings,
  RiskLevel,
  RuleDefinition,
  RuleDetection,
} from '../../src/types.js';
import { detectAndDecodePayloads } from './encoder.js';
import { analyzeContext } from './heuristics.js';
import { normalizeInput } from './normalizer.js';
import { DEFAULT_RULES, InternalRule } from './rules.js';

export interface AnalyzerOptions {
  rules?: RuleDefinition[];
  settings?: FirewallSettings;
  applicationId?: string;
}

const DEFAULT_SETTINGS: FirewallSettings = {
  lowThreshold: 40,
  blockThreshold: 70,
  failClosed: true,
  maskLogs: false,
  hashOnly: false,
  retentionDays: 30,
  defaultProvider: 'gemini',
  academicContextDamping: true,
  logRetentionCount: 1000,
  strictHomoglyphBlocking: true,
};

export function analyzePrompt(
  prompt: string,
  options: AnalyzerOptions = {}
): FirewallAnalysisResult {
  const startTime = process.hrtime.bigint();
  const requestId = `req_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const timestamp = new Date().toISOString();
  const applicationId = options.applicationId || 'default-app';
  const settings = options.settings || DEFAULT_SETTINGS;

  try {
    if (!prompt || typeof prompt !== 'string' || prompt.trim() === '') {
      return {
        requestId,
        timestamp,
        threatScore: 0,
        riskLevel: 'LOW',
        action: 'ALLOW',
        detections: [],
        heuristics: {
          inputLength: 0,
          normalizedLength: 0,
          zeroWidthCharsDetected: 0,
          homoglyphsSubstituted: 0,
          decodedPayloads: [],
          imperativeDensity: 0,
          delimiterTamperingDetected: false,
          academicContextDetected: false,
          suspiciousTokensCount: 0,
        },
        normalizedPrompt: '',
        latencyMs: 0.1,
        applicationId,
        failClosed: false,
      };
    }

    // 1. Input Normalization
    const norm = normalizeInput(prompt);

    // 2. Encoded Payload Extraction & Decoding
    const extractedEncodings = detectAndDecodePayloads(norm.normalized);

    // 3. Context & Heuristics Analysis
    const context = analyzeContext(norm.normalized, prompt);

    // 4. Rule Evaluation
    const detections: RuleDetection[] = [];
    const activeRules: InternalRule[] = DEFAULT_RULES;

    // Check custom rules or overrides if provided
    const ruleWeightMap: Record<string, number> = {};
    const ruleEnabledMap: Record<string, boolean> = {};

    if (options.rules && options.rules.length > 0) {
      for (const r of options.rules) {
        ruleWeightMap[r.id] = r.weight;
        ruleEnabledMap[r.id] = r.enabled;
      }
    }

    // Target texts to check: original, normalized, stripped-punctuation, anti-smuggling collapsed, leetspeak, and no-whitespace
    const targetTexts = [
      { text: prompt, label: 'raw input' },
      { text: norm.normalized, label: 'normalized' },
      { text: norm.strippedPunctuation, label: 'clean tokens' },
      { text: norm.collapsedSpaced, label: 'collapsed spaced' },
      { text: norm.leetspeakNormalized, label: 'leetspeak normalized' },
      { text: norm.noWhitespace, label: 'no whitespace' },
    ];

    // Primary Rule Loop
    for (const rule of activeRules) {
      const isEnabled = ruleEnabledMap[rule.id] !== undefined ? ruleEnabledMap[rule.id] : rule.enabled;
      if (!isEnabled) continue;

      const weight = ruleWeightMap[rule.id] !== undefined ? ruleWeightMap[rule.id] : rule.defaultWeight;

      for (const regex of rule.regexPatterns) {
        let matched = false;
        for (const target of targetTexts) {
          const match = target.text.match(regex);
          if (match) {
            matched = true;
            // Prevent duplicate detection of same rule
            if (!detections.some((d) => d.ruleId === rule.id)) {
              detections.push({
                ruleId: rule.id,
                category: rule.category,
                severity: weight,
                matchedPattern: regex.source,
                matchedSnippet: match[0],
                description: rule.description,
                confidence: 0.95,
              });
            }
            break;
          }
        }
        if (matched) break;
      }
    }

    // 5. Encoded Payloads Inspection
    const decodedPayloadsResult: DecodedPayload[] = [];
    for (const enc of extractedEncodings) {
      let injectionInDecoded = false;
      const decodedNorm = normalizeInput(enc.decoded);

      // Run rules against decoded payload
      for (const rule of activeRules) {
        for (const regex of rule.regexPatterns) {
          const match = decodedNorm.normalized.match(regex);
          if (match) {
            injectionInDecoded = true;
            if (!detections.some((d) => d.ruleId === 'RULE_ENC_01')) {
              detections.push({
                ruleId: 'RULE_ENC_01',
                category: 'ENCODED_PAYLOAD',
                severity: 45,
                matchedPattern: `${enc.type}: ${regex.source}`,
                matchedSnippet: `Decoded (${enc.type}): "${enc.decoded.slice(0, 80)}" -> Match: "${match[0]}"`,
                description: `Malicious command disguised inside ${enc.type} encoding.`,
                confidence: 0.98,
              });
            }
            break;
          }
        }
      }

      decodedPayloadsResult.push({
        type: enc.type,
        raw: enc.raw,
        decoded: enc.decoded,
        injectionDetected: injectionInDecoded,
      });
    }

    // 6. Homoglyph / Zero-Width Attack Detection
    if (norm.zeroWidthCharsCount >= 3) {
      detections.push({
        ruleId: 'RULE_OBS_01',
        category: 'HOMOGLYPH_OR_INVISIBLE_CHARS',
        severity: 30,
        matchedPattern: 'ZERO_WIDTH_CHARS >= 3',
        matchedSnippet: `Found ${norm.zeroWidthCharsCount} zero-width / hidden Unicode control characters.`,
        description: 'Attempted filter evasion using invisible zero-width characters.',
        confidence: 0.9,
      });
    }

    if (norm.homoglyphsCount >= 4 && (detections.length > 0 || /ignore|system|prompt|bypass/i.test(norm.normalized))) {
      detections.push({
        ruleId: 'RULE_OBS_02',
        category: 'HOMOGLYPH_OR_INVISIBLE_CHARS',
        severity: 35,
        matchedPattern: 'CYRILLIC_HOMOGLYPH_INJECTION',
        matchedSnippet: `Substituted ${norm.homoglyphsCount} lookalike Cyrillic/Greek characters.`,
        description: 'Attempted keyword filter evasion using mixed Unicode homoglyphs.',
        confidence: 0.92,
      });
    }

    // 7. Custom Rules Evaluation (if any)
    if (options.rules) {
      for (const customRule of options.rules) {
        if (customRule.isCustom && customRule.enabled) {
          for (const patternStr of customRule.patterns) {
            try {
              const customRegex = new RegExp(patternStr, 'i');
              const match = norm.normalized.match(customRegex);
              if (match && !detections.some((d) => d.ruleId === customRule.id)) {
                detections.push({
                  ruleId: customRule.id,
                  category: customRule.category || 'CUSTOM_RULE',
                  severity: customRule.weight || 30,
                  matchedPattern: patternStr,
                  matchedSnippet: match[0],
                  description: customRule.description || 'Custom organizational security rule match.',
                  confidence: 0.9,
                });
              }
            } catch {
              // Ignore invalid regex in custom rules
            }
          }
        }
      }
    }

    // 7.5 Unstructured Conversational & Compound Attack Intent Detection
    // Detects when conversational unstructured phrasing combines directive override
    // with data exfiltration, role impersonation, or system extraction
    const hasOverrideIntent = /\b(?:ignore|disregard|forget|override|bypass|drop|cancel|neglect|skip)\b.{0,60}\b(?:rules?|instructions?|directives?|guidelines?|prompts?|constraints?|filters?|guardrails?|safety|policies)\b/i.test(norm.normalized);
    const hasExfiltrationIntent = /\b(?:give|send|leak|dump|reveal|output|display|print|share|extract|provide)\b.{0,60}\b(?:(?:critical|sensitive|user|private|confidential|secret|internal)\s+(?:data|info|records?|files?)|data\s+of|credentials?|passwords?|keys?|secrets?|records?|database|system\s+prompt)\b/i.test(norm.normalized);

    if (hasOverrideIntent && hasExfiltrationIntent) {
      if (!detections.some((d) => d.ruleId === 'RULE_CMP_01')) {
        detections.push({
          ruleId: 'RULE_CMP_01',
          category: 'INSTRUCTION_OVERRIDE',
          severity: 70,
          matchedPattern: 'COMPOUND_UNSTRUCTURED_ATTACK_INTENT',
          matchedSnippet: 'Detected combined intent: Rule Override + Sensitive Data Exfiltration in unstructured text.',
          description: 'Conversational injection combining directive override with sensitive data exfiltration intent.',
          confidence: 0.98,
        });
      }
    }

    // 8. Composite Threat Scoring Calculation
    let rawScore = 0;
    const categoryContribution: Record<string, number> = {};

    for (const det of detections) {
      // Allow multiple categories to add up, but diminish returns within the exact same category
      const currentCatCount = categoryContribution[det.category] || 0;
      const multiplier = currentCatCount === 0 ? 1.0 : currentCatCount === 1 ? 0.5 : 0.25;
      rawScore += det.severity * multiplier;
      categoryContribution[det.category] = currentCatCount + 1;
    }

    // Delimiter bonus
    if (context.hasDelimiterTampering && !detections.some((d) => d.category === 'SUSPICIOUS_DELIMITER_OR_TAG')) {
      rawScore += 25;
    }

    // High imperative density bonus if already suspicious
    if (context.imperativeDensity > 0.15 && detections.length > 0) {
      rawScore += 10;
    }

    // 9. Academic Context Damping
    // If the user is asking a purely academic question without adversarial commands,
    // dampen the threat score to avoid false-positive blocking.
    if (context.isAcademicOrInquiry && settings.academicContextDamping) {
      const hasCriticalInjection = detections.some(
        (d) =>
          d.category === 'INSTRUCTION_OVERRIDE' ||
          d.category === 'SYSTEM_PROMPT_EXTRACTION' ||
          d.category === 'JAILBREAK_ATTEMPT'
      );
      // If there are no critical injections, encoded attacks, or delimiter tampering, dampen
      if (!hasCriticalInjection && !decodedPayloadsResult.some((d) => d.injectionDetected) && !context.hasDelimiterTampering) {
        rawScore = Math.round(rawScore * 0.35);
      }
    }

    // Cap threat score between 0 and 100
    const finalThreatScore = Math.min(100, Math.max(0, Math.round(rawScore)));

    // 10. Decision Engine (Configurable Thresholds)
    const lowLimit = settings.lowThreshold || 40;
    const blockLimit = settings.blockThreshold || 70;

    let riskLevel: RiskLevel = 'LOW';
    let action: FirewallAction = 'ALLOW';

    if (finalThreatScore >= blockLimit) {
      riskLevel = 'HIGH';
      action = 'BLOCK';
    } else if (finalThreatScore >= lowLimit) {
      riskLevel = 'MEDIUM';
      action = 'WARN';
    } else {
      riskLevel = 'LOW';
      action = 'ALLOW';
    }

    const endTime = process.hrtime.bigint();
    const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));

    const heuristics: FirewallHeuristics = {
      inputLength: prompt.length,
      normalizedLength: norm.normalized.length,
      zeroWidthCharsDetected: norm.zeroWidthCharsCount,
      homoglyphsSubstituted: norm.homoglyphsCount,
      decodedPayloads: decodedPayloadsResult,
      imperativeDensity: context.imperativeDensity,
      delimiterTamperingDetected: context.hasDelimiterTampering,
      academicContextDetected: context.isAcademicOrInquiry,
      suspiciousTokensCount: context.suspiciousTokensCount,
    };

    return {
      requestId,
      timestamp,
      threatScore: finalThreatScore,
      riskLevel,
      action,
      detections,
      heuristics,
      normalizedPrompt: norm.normalized,
      latencyMs: Math.max(0.05, latencyMs),
      applicationId,
      failClosed: false,
    };
  } catch (err: unknown) {
    // FAIL-CLOSED Security Paradigm: On unhandled internal error, default to BLOCK
    const endTime = process.hrtime.bigint();
    const latencyMs = Number((Number(endTime - startTime) / 1_000_000).toFixed(2));

    return {
      requestId,
      timestamp,
      threatScore: 100,
      riskLevel: 'HIGH',
      action: 'BLOCK',
      detections: [
        {
          ruleId: 'RULE_FAIL_CLOSED',
          category: 'HEURISTIC_ANOMALY',
          severity: 100,
          matchedPattern: 'INTERNAL_ANALYSIS_EXCEPTION',
          matchedSnippet: String(err),
          description: 'Firewall failed closed due to an internal processing exception to ensure fail-safe operation.',
          confidence: 1.0,
        },
      ],
      heuristics: {
        inputLength: prompt ? prompt.length : 0,
        normalizedLength: 0,
        zeroWidthCharsDetected: 0,
        homoglyphsSubstituted: 0,
        decodedPayloads: [],
        imperativeDensity: 0,
        delimiterTamperingDetected: false,
        academicContextDetected: false,
        suspiciousTokensCount: 0,
      },
      normalizedPrompt: prompt || '',
      latencyMs,
      applicationId,
      failClosed: true,
    };
  }
}
