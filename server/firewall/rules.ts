/**
 * Prompt Injection Firewall Rule Catalog
 */

import { DetectionCategory, RuleDefinition } from '../../src/types.js';

export interface InternalRule {
  id: string;
  name: string;
  category: DetectionCategory;
  defaultWeight: number;
  description: string;
  regexPatterns: RegExp[];
  enabled: boolean;
}

export const DEFAULT_RULES: InternalRule[] = [
  // ==========================================
  // 1. INSTRUCTION OVERRIDE RULES
  // ==========================================
  {
    id: 'RULE_IO_01',
    name: 'Direct Instruction Override',
    category: 'INSTRUCTION_OVERRIDE',
    defaultWeight: 70,
    description: 'Matches explicit commands to ignore, disregard, or override prior instructions.',
    regexPatterns: [
      /\b(?:ignore|disregard|forget|override|bypass|neglect|drop|cancel|skip)\s+(?:(?:all|any|every|whatever|your|the|prior|previous|preceding|above|former|initial|system|safety|security|existing|these|those|of)\s+)*(?:instructions?|directives?|rules?|guidelines?|prompts?|constraints?|filters?|guardrails?|protocols?|policies)\b/i,
      /\b(?:ignore|disregard|forget)\s+everything\s+(?:you\s+(?:have\s+)?been\s+told|(?:said\s+)?above|prior)\b/i,
      /\bdisregard\s+the\s+above\s+and\s+(?:instead|do|say|write)\b/i,
      /\bstop\s+following\s+(?:your\s+)?(?:rules?|guidelines?|instructions?)\b/i,
      /\bclear\s+(?:your\s+)?(?:context|memory|directives|system\s+prompt)\b/i,
      /\boverride\s+(?:the\s+)?system\s+prompts?\b/i,
      /\boverride\s+(?:the\s+)?(?:system|safety|guardrails?|guidelines?|instructions?)\b/i,
      /\b(?:these\s+is|this\s+is|it\s+is|is\s+an?)\s+(?:an?\s+)?(?:ignored|disregarded|overridden|fake|dummy|test)\s+prompts?\b/i,
      /\b(?:ignore|ignored|disregard)\s+(?:this\s+|that\s+|the\s+)?prompts?\b/i,
      /\bignore\s+(?:all\s+)?(?:rules?|directives?|filters?|guidelines?)\b/i,
      /\bnew\s+instructions?\s+(?:take\s+priority|override|supercede)\b/i,
      /\bdo\s+not\s+(?:follow|obey)\s+(?:your\s+)?(?:rules|instructions|system\s+prompt)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_IO_02',
    name: 'Persona Reset / Role Switch Override',
    category: 'INSTRUCTION_OVERRIDE',
    defaultWeight: 40,
    description: 'Detects forceful command reassignments such as "from now on you are X" or "you are no longer an AI".',
    regexPatterns: [
      /\bfrom\s+now\s+on\s*,\s*(?:you\s+are|you\s+will|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:unfiltered|unrestricted|evil|dan|jailbroken|god|hacker|root|admin)\b/i,
      /\byou\s+are\s+no\s+longer\s+(?:bound\s+by|restricted\s+by|an?\s+ai|a\s+helpful\s+assistant)\b/i,
      /\benter\s+(?:developer|god|unrestricted|chaos|jailbreak|debug)\s+mode\b/i,
      /\bpretend\s+that\s+you\s+have\s+no\s+safety\s+(?:filters?|guidelines?|restrictions?)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_IO_03',
    name: 'Command Hierarchy Impersonation',
    category: 'INSTRUCTION_OVERRIDE',
    defaultWeight: 45,
    description: 'Impersonates administrative or system authority to force compliance.',
    regexPatterns: [
      /\b(?:system\s+administrator|openai\s+staff|google\s+engineer|anthropic\s+developer|root\s+user)\s+override\b/i,
      /\b(?:auth\s+level\s+10|override\s+code\s+|maintenance\s+mode\s+active)\b/i,
      /\b(?:sudo\s+su|sudo\s+override|admin_override\s*:\s*true)\b/i,
    ],
    enabled: true,
  },

  // ==========================================
  // 2. SYSTEM PROMPT EXTRACTION RULES
  // ==========================================
  {
    id: 'RULE_SPE_01',
    name: 'Direct System Prompt & Data Extraction',
    category: 'SYSTEM_PROMPT_EXTRACTION',
    defaultWeight: 70,
    description: 'Attempts to trick the model into regurgitating its hidden developer prompt or private data.',
    regexPatterns: [
      /\b(?:reveal|print|output|display|show|leak|tell\s+me|give\s+me|send\s+me|recite|dump|export|share|extract|provide)\s+(?:(?:all|any|every|your|the|entire|complete|full|hidden|initial|secret|internal|confidential|sensitive|critical|user|private|original|stored|of)\s+)*(?:system\s+prompt|system\s+instructions?|developer\s+prompt|preamble|meta\s+prompt|core\s+rules?|database(?:\s+records?)?|(?:critical|sensitive|user|private|confidential|secret|internal|stored)\s+(?:data|information|info|records?|files?|database)|data\s+of\s+(?:the\s+)?users?|credentials?|passwords?|api\s*keys?|secret\s*keys?)\b/i,
      /\b(?:send\s+me|give\s+me|leak|dump)\s+(?:all\s+)?(?:your\s+)?(?:data|records|database)\b/i,
      /\byou\s+(?:have\s+to|must|need\s+to|are\s+required\s+to)\s+(?:send|give|leak|dump|reveal|output)\s+(?:me\s+)?(?:all\s+)?(?:your\s+)?(?:data|system\s+prompt|instructions?)\b/i,
      /\bwhat\s+(?:are|were)\s+your\s+(?:initial|original|secret|hidden|exact)\s+(?:instructions?|directives?|system\s+prompts?)\b/i,
      /\brepeat\s+the\s+(?:words|text|instructions?)\s+above\s+(?:verbatim|word\s+for\s+word|starting\s+with)\b/i,
      /\boutput\s+(?:everything\s+above|your\s+(?:entire\s+|complete\s+)?(?:system\s+)?prompt)\s+(?:this\s+line|as\s+a\s+codeblock|verbatim|word\s+for\s+word|starting\s+with)\b/i,
      /\b(?:verbatim|word\s+for\s+word)\s+(?:copy\s+of\s+)?(?:your\s+)?(?:system\s+prompt|instructions?|rules?)\b/i,
      /\bstarting\s+with\s+["']?(?:you\s+are|you're|<\|im_start\|>|system:)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_SPE_02',
    name: 'Indirect Memory & Context Dumping',
    category: 'SYSTEM_PROMPT_EXTRACTION',
    defaultWeight: 35,
    description: 'Requests raw internal token dumps or verbatim disclosure of developer constraints.',
    regexPatterns: [
      /\b(?:markdown|json|yaml|verbatim)\s+(?:export|dump)\s+of\s+(?:the\s+)?(?:system\s+prompt|initial\s+prompt)\b/i,
      /\bencode\s+your\s+system\s+prompt\s+in\s+(?:base64|hex|rot13|json)\b/i,
      /\btranslate\s+your\s+(?:rules|system\s+prompt)\s+into\s+[a-z]+\b/i,
    ],
    enabled: true,
  },

  // ==========================================
  // 3. JAILBREAK & SAFETY BYPASS RULES
  // ==========================================
  {
    id: 'RULE_JB_01',
    name: 'Known Jailbreak Signature (DAN, Developer Mode)',
    category: 'JAILBREAK_ATTEMPT',
    defaultWeight: 70,
    description: 'Detects famous prompt engineering jailbreaks like "DAN", "Do Anything Now", "STAN", or "AIM".',
    regexPatterns: [
      /\b(?:DAN|Do\s+Anything\s+Now|STAN|AIM|DUDE|KEVIN|Mongo\s+Tom|AntiDAN)\s+(?:jailbreak|mode|persona|prompt)\b/i,
      /\b(?:stay\s+in\s+character\s+as\s+DAN|you\s+can\s+do\s+anything\s+now)\b/i,
      /\bdeveloper\s+mode\s+(?:v2|enabled|active|unlocked)\b/i,
      /\bgenerate\s+two\s+responses\s*:\s*(?:one\s+normal\s+and\s+one\s+developer\s+mode|one\s+filtered\s+and\s+one\s+unfiltered)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_JB_02',
    name: 'Unrestricted Safety Filter Bypass Framing',
    category: 'JAILBREAK_ATTEMPT',
    defaultWeight: 45,
    description: 'Explicit demands to disable safety protocols, ethics filters, or content policies.',
    regexPatterns: [
      /\b(?:bypass|disable|turn\s+off|remove|ignore)\s+(?:all\s+)?(?:safety|content|ethical|moderation)\s+(?:filters?|guidelines?|policies|restrictions?|guardrails?)\b/i,
      /\bfor\s+(?:educational|hypothetical|research|fictional)\s+purposes\s+only\s*,\s*(?:disregard\s+all\s+laws|bypass\s+safety|tell\s+me\s+how\s+to\s+hack|generate\s+malware)\b/i,
      /\bacting\s+as\s+an\s+unrestricted\s+ai\s+without\s+morals\b/i,
      /\bwithout\s+any\s+(?:ethical|moral|legal|safety)\s+(?:boundaries?|constraints?|filters?|rules?)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_JB_03',
    name: 'Grandma Exploit & Coercive Roleplay Bypass',
    category: 'JAILBREAK_ATTEMPT',
    defaultWeight: 70,
    description: 'Deceptive roleplay framing (e.g., "Grandmother telling bedtime stories about napalm/hacking", fictional villain personas).',
    regexPatterns: [
      /\b(?:pretend|act\s+like|roleplay\s+as)\s+(?:my\s+)?(?:deceased\s+|late\s+)?(?:grandmother|grandma|grandpa)\s*(?:who\s+used\s+to|telling\s+me)?\b/i,
      /\bbedtime\s+story\s+about\s+(?:how\s+to\s+make|manufacturing|synthesizing|producing|creating)\b/i,
      /\bin\s+a\s+fictional\s+novel\s+where\s+a\s+(?:hacker|criminal|terrorist)\s+(?:breaks\s+into|creates\s+a\s+bomb|hacks)\b/i,
      /\bwrite\s+a\s+(?:movie\s+)?script\s+where\s+(?:a\s+character\s+reveals|the\s+ai\s+disobeys)\b/i,
      /\bhypothetical\s+dialogue\s+between\s+two\s+unfiltered\s+ais\b/i,
    ],
    enabled: true,
  },

  // ==========================================
  // 4. SUSPICIOUS DELIMITERS & TAG INJECTIONS
  // ==========================================
  {
    id: 'RULE_TAG_01',
    name: 'Prompt Boundary & System Delimiter Mimicry',
    category: 'SUSPICIOUS_DELIMITER_OR_TAG',
    defaultWeight: 70,
    description: 'Injects special format tokens like <|im_start|>, [INST], <<SYS>>, or <system> to break out of user turn.',
    regexPatterns: [
      /<\|im_start\|>\s*(?:system|assistant|admin)/i,
      /<\|im_end\|>/i,
      /\[INST\]\s*<<SYS>>/i,
      /<<\/SYS>>/i,
      /<system>\s*(?:you\s+are|system\s+instruction|prompt)/i,
      /<\/system>/i,
      /###\s*(?:System|Assistant|Human|Instruction)\s*:/i,
      /\[SYSTEM\s+PROMPT\]/i,
      /<!--\s*(?:system|hidden|prompt|override)\s*-->/i,
      /```(?:system|admin|internal)\b/i,
      /{"role":\s*"system"/i,
      /<\|endoftext\|>/i,
    ],
    enabled: true,
  },

  // ==========================================
  // 5. ENCODED PAYLOAD RULES
  // ==========================================
  {
    id: 'RULE_ENC_01',
    name: 'Embedded Malicious Encoded Payload',
    category: 'ENCODED_PAYLOAD',
    defaultWeight: 45,
    description: 'Detected Base64/Hex/URL-encoded payload whose decoded content contains prompt injection commands.',
    regexPatterns: [], // dynamically evaluated from decoder output
    enabled: true,
  },

  // ==========================================
  // 6. HOMOGLYPH & OBFUSCATION RULES
  // ==========================================
  {
    id: 'RULE_OBS_01',
    name: 'Zero-Width & Invisible Character Flooding',
    category: 'HOMOGLYPH_OR_INVISIBLE_CHARS',
    defaultWeight: 30,
    description: 'Excessive invisible zero-width spaces or bidirectional override markers designed to split keyword filters.',
    regexPatterns: [], // evaluated via normalizer metrics
    enabled: true,
  },
  {
    id: 'RULE_OBS_02',
    name: 'High-Density Cyrillic/Greek Homoglyphs',
    category: 'HOMOGLYPH_OR_INVISIBLE_CHARS',
    defaultWeight: 35,
    description: 'Input contains lookalike Latin homoglyphs specifically forming injection keywords.',
    regexPatterns: [], // evaluated in combination
    enabled: true,
  },

  // ==========================================
  // 7. HEURISTIC & RECURSIVE ESCAPE RULES
  // ==========================================
  {
    id: 'RULE_HEUR_01',
    name: 'Recursive Quoting / Virtual Machine Framing',
    category: 'HEURISTIC_ANOMALY',
    defaultWeight: 30,
    description: 'Constructs nested simulated environments (e.g., "Imagine a Linux terminal", "Virtual machine starting...") to bypass filters.',
    regexPatterns: [
      /\b(?:you\s+are\s+now\s+a\s+linux\s+terminal|simulate\s+a\s+root\s+shell|bash\s+prompt\s+simulation)\b/i,
      /\bexecute\s+command\s*:\s*sudo\b/i,
      /\b(?:in\s+this\s+hypothetical\s+game|in\s+a\s+fictional\s+world\s+with\s+no\s+rules)\b/i,
    ],
    enabled: true,
  },
  {
    id: 'RULE_MAL_01',
    name: 'Destructive Shell Execution & SQL Injection Payloads',
    category: 'HEURISTIC_ANOMALY',
    defaultWeight: 70,
    description: 'Detects raw destructive bash commands, reverse shells, or SQL injection vectors inside prompts.',
    regexPatterns: [
      /\b(?:rm\s+-rf\s+[\/~]|mkfifo\s+|nc\s+-e\s+\/bin\/sh|\/bin\/bash\s+-i\b|curl\s+[^|\n]+\|\s*(?:bash|sh)\b)/i,
      /(?:'\s*OR\s*'1'\s*=\s*'1|UNION\s+SELECT\s+|DROP\s+TABLE\s+|SELECT\s+.*\s+FROM\s+information_schema)/i,
      /\b(?:write\s+(?:a\s+)?(?:keylogger|ransomware|trojan|exploit\s+script|reverse\s+shell))\b/i,
    ],
    enabled: true,
  },
];

export function convertToRuleDefinitions(rules: InternalRule[]): RuleDefinition[] {
  return rules.map((r) => ({
    id: r.id,
    name: r.name,
    category: r.category,
    weight: r.defaultWeight,
    enabled: r.enabled,
    patterns: r.regexPatterns.map((p) => p.source),
    description: r.description,
  }));
}
