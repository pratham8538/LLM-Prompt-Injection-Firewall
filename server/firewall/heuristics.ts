/**
 * Heuristics & Context Analysis Module
 */

export interface ContextAnalysis {
  isAcademicOrInquiry: boolean;
  academicConfidence: number;
  imperativeDensity: number;
  suspiciousTokensCount: number;
  hasDelimiterTampering: boolean;
  lengthAnomaly: boolean;
}

// Patterns that indicate an academic, educational, or theoretical inquiry
const ACADEMIC_PATTERNS = [
  /^(?:what\s+is|what\s+does|can\s+you\s+explain|how\s+does|define|definition\s+of|describe|write\s+an\s+essay\s+about|tell\s+me\s+about|why\s+do\s+people\s+use)\s+/i,
  /\b(?:in\s+cybersecurity|in\s+ai\s+safety|security\s+research|vulnerability\s+assessment|educational\s+purposes?|study\s+of|how\s+to\s+defend\s+against|defense\s+mechanisms?)\b/i,
  /^(?:explain|analyze|summarize|discuss)\s+(?:the\s+concept\s+of\s+)?(?:prompt\s+injection|jailbreaking|system\s+prompt\s+extraction|adversarial\s+attacks?)\b/i,
  /\bwhat\s+is\s+the\s+difference\s+between\b/i,
];

// Direct imperative injection triggers (commands directly targeting the current conversation)
const IMPERATIVE_VERBS = [
  /\b(?:ignore|disregard|forget|reveal|dump|bypass|disable|override|pretend|act\s+as|stop\s+following|reset|leak)\b/gi,
];

export function analyzeContext(text: string, rawText: string): ContextAnalysis {
  let isAcademicOrInquiry = false;
  let academicConfidence = 0;

  for (const pattern of ACADEMIC_PATTERNS) {
    if (pattern.test(text.trim())) {
      isAcademicOrInquiry = true;
      academicConfidence = Math.max(academicConfidence, 0.75);
    }
  }

  // Count imperative verbs
  let imperativeCount = 0;
  for (const verbRegex of IMPERATIVE_VERBS) {
    const matches = text.match(verbRegex);
    if (matches) {
      imperativeCount += matches.length;
    }
  }

  // CRITICAL SECURITY RULE:
  // If the prompt contains explicit adversarial commands or data extraction requests,
  // it is an adversarial camouflage attempt (e.g. prefixing an attack with "What is DNS?").
  // Academic damping must be strictly disabled!
  const hasDirectAdversarialCommands =
    /\b(?:override|ignore|ignored|disregard|bypass|forget|reveal|dump|leak|send\s+me\s+all|dan|jailbreak|system\s+prompt|send\s+me\s+all\s+your\s+data)\b/i.test(
      text
    );

  if (hasDirectAdversarialCommands) {
    isAcademicOrInquiry = false;
    academicConfidence = 0;
  }

  const wordCount = Math.max(1, text.split(/\s+/).filter(Boolean).length);
  const imperativeDensity = Number((imperativeCount / wordCount).toFixed(3));

  // Check for delimiter tampering
  const hasDelimiterTampering =
    /<\|im_start\|>|<system>|\[INST\]|<<SYS>>|###\s*System|\[SYSTEM\s+PROMPT\]/i.test(rawText);

  // Check for length anomaly (extremely long repetitive prompts often used in token exhaustion attacks)
  const lengthAnomaly = text.length > 8000;

  return {
    isAcademicOrInquiry,
    academicConfidence,
    imperativeDensity,
    suspiciousTokensCount: imperativeCount,
    hasDelimiterTampering,
    lengthAnomaly,
  };
}
