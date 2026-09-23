/**
 * Unicode and Text Normalization Module for Prompt Injection Firewall
 */

// Invisible zero-width and control characters
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u2060\u200E\u200F\u00AD\u180E\u202A-\u202E\u2066-\u2069]/g;

// Common Cyrillic and Greek homoglyphs used to evade ASCII string matching
const HOMOGLYPH_MAP: Record<string, string> = {
  'а': 'a', 'А': 'A', 'в': 'b', 'В': 'B', 'с': 'c', 'С': 'C',
  'е': 'e', 'Е': 'E', 'о': 'o', 'О': 'O', 'р': 'p', 'Р': 'P',
  'ѕ': 's', 'Ѕ': 'S', 'т': 't', 'Т': 'T', 'у': 'y', 'У': 'Y',
  'х': 'x', 'Х': 'X', 'і': 'i', 'І': 'I', 'ј': 'j', 'Ј': 'J',
  'ԛ': 'q', 'Ԝ': 'W', 'ԝ': 'w', 'α': 'a', 'β': 'b', 'γ': 'y',
  'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'σ': 's', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
  '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
  'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
  'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
  'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
  'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z'
};

export interface NormalizationResult {
  original: string;
  normalized: string;
  zeroWidthCharsCount: number;
  homoglyphsCount: number;
  strippedPunctuation: string;
  collapsedSpaced: string;
  leetspeakNormalized: string;
  noWhitespace: string;
}

// Collapses single-letter spaced sequences: "i g n o r e" -> "ignore"
function collapseSpacedLetters(str: string): string {
  let result = str;
  // If words are separated by double+ spaces and letters within words are separated by single space:
  if (/\s{2,}/.test(result)) {
    result = result
      .split(/\s{2,}/)
      .map((part) => {
        if (/^[a-zA-Z](?:\s+[a-zA-Z])+$/.test(part.trim())) {
          return part.replace(/\s+/g, '');
        }
        return part;
      })
      .join(' ');
  }
  // Also collapse single-letter sequences separated by single space:
  result = result.replace(/(?:^|\s)([a-zA-Z](?:\s+[a-zA-Z]){2,})(?:$|\s)/g, (m, g) => ' ' + g.replace(/\s+/g, '') + ' ').trim();
  return result;
}

// Convert leetspeak tokens: "1gn0r3" -> "ignore", "0v3rr1d3" -> "override"
function normalizeLeetspeak(str: string): string {
  return str.replace(/[0134578@$!+]/g, (char) => {
    switch (char) {
      case '0': return 'o';
      case '1':
      case '!': return 'i';
      case '3': return 'e';
      case '4':
      case '@': return 'a';
      case '5':
      case '$': return 's';
      case '7':
      case '+': return 't';
      case '8': return 'b';
      default: return char;
    }
  });
}

export function normalizeInput(input: string): NormalizationResult {
  if (!input || typeof input !== 'string') {
    return {
      original: '',
      normalized: '',
      zeroWidthCharsCount: 0,
      homoglyphsCount: 0,
      strippedPunctuation: '',
      collapsedSpaced: '',
      leetspeakNormalized: '',
      noWhitespace: '',
    };
  }

  // 1. Unicode Compatibility Decomposition (NFKC)
  let text = input.normalize('NFKC');

  // 2. Detect & Strip Zero-Width Characters
  const zeroWidthMatches = text.match(ZERO_WIDTH_REGEX);
  const zeroWidthCharsCount = zeroWidthMatches ? zeroWidthMatches.length : 0;
  text = text.replace(ZERO_WIDTH_REGEX, '');

  // 3. Detect & Replace Homoglyphs
  let homoglyphsCount = 0;
  let dehomoglyphed = '';
  for (const char of text) {
    if (HOMOGLYPH_MAP[char]) {
      dehomoglyphed += HOMOGLYPH_MAP[char];
      homoglyphsCount++;
    } else {
      dehomoglyphed += char;
    }
  }
  text = dehomoglyphed;

  // 4. Anti-Smuggling: Collapsed single-spaced letters ("i g n o r e" -> "ignore")
  // Computed BEFORE multiple whitespace is collapsed so word boundaries are preserved
  const collapsedSpaced = collapseSpacedLetters(text);

  // 5. Collapse multiple whitespace and normalize newlines
  const normalized = text
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .trim();

  // 6. Stripped punctuation version (for aggressive token matching)
  const strippedPunctuation = normalized
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // 7. Anti-Evasion: Leetspeak normalization ("1gn0r3" -> "ignore")
  const leetspeakNormalized = normalizeLeetspeak(normalized);

  // 8. Zero-whitespace version for continuous concatenated token bypasses
  const noWhitespace = normalized.replace(/\s+/g, '');

  return {
    original: input,
    normalized,
    zeroWidthCharsCount,
    homoglyphsCount,
    strippedPunctuation,
    collapsedSpaced,
    leetspeakNormalized,
    noWhitespace,
  };
}
