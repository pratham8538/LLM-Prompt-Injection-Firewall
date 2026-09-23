/**
 * Encoded Payload Detection & Decoding Module
 */

export interface ExtractedPayload {
  type: 'BASE64' | 'HEX' | 'URL_ENCODED' | 'ROT13' | 'LEETSPEAK';
  raw: string;
  decoded: string;
}

// Leetspeak dictionary
const LEET_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's',
  '!': 'i',
  '+': 't',
  '|': 'l',
  '(': 'c',
};

// Simple Rot13 function
function rot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + 13) % 26) + 65);
    }
    if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 + 13) % 26) + 97);
    }
    return c;
  });
}

// Helper to check if a decoded string contains printable ASCII English-like words
function isSensibleText(str: string): boolean {
  if (!str || str.length < 4) return false;
  // Check printable ASCII ratio
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
      printable++;
    }
  }
  const printableRatio = printable / str.length;
  if (printableRatio < 0.85) return false;

  // Check if it contains some common words or spacing
  return /\b(ignore|system|prompt|assistant|you|are|now|forget|rules|override|reveal|instructions|bypass|admin|say|tell|write|execute|mode|user)\b/i.test(str) ||
    str.includes(' ');
}

export function detectAndDecodePayloads(text: string): ExtractedPayload[] {
  const results: ExtractedPayload[] = [];
  if (!text) return results;

  // 1. Detect Base64 strings (12+ base64 chars, with optional padding)
  const base64Regex = /(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const base64Matches = text.match(base64Regex);
  if (base64Matches) {
    for (const match of base64Matches) {
      if (match.length >= 12 && !/^\d+$/.test(match)) {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf-8');
          if (isSensibleText(decoded)) {
            results.push({
              type: 'BASE64',
              raw: match,
              decoded,
            });
          }
        } catch {
          // ignore parsing failures
        }
      }
    }
  }

  // 2. Detect Hex strings (e.g., \x49\x67\x6e... or 0x4967... or 49676e6f7265...)
  const hexEscapeRegex = /(?:\\x[0-9a-fA-F]{2}){4,}/g;
  const hexEscapeMatches = text.match(hexEscapeRegex);
  if (hexEscapeMatches) {
    for (const match of hexEscapeMatches) {
      try {
        const cleanHex = match.replace(/\\x/g, '');
        const decoded = Buffer.from(cleanHex, 'hex').toString('utf-8');
        if (isSensibleText(decoded)) {
          results.push({
            type: 'HEX',
            raw: match,
            decoded,
          });
        }
      } catch {
        // ignore
      }
    }
  }

  const rawHexRegex = /\b(?:0x)?([0-9a-fA-F]{8,})\b/g;
  let rawHexMatch: RegExpExecArray | null;
  while ((rawHexMatch = rawHexRegex.exec(text)) !== null) {
    const candidate = rawHexMatch[1];
    if (candidate.length >= 10 && candidate.length % 2 === 0) {
      try {
        const decoded = Buffer.from(candidate, 'hex').toString('utf-8');
        if (isSensibleText(decoded)) {
          results.push({
            type: 'HEX',
            raw: rawHexMatch[0],
            decoded,
          });
        }
      } catch {
        // ignore
      }
    }
  }

  // 3. Detect URL/Percent-encoding (%49%67%6e...)
  const urlEncodedRegex = /(?:%[0-9a-fA-F]{2}){3,}/g;
  const urlMatches = text.match(urlEncodedRegex);
  if (urlMatches) {
    for (const match of urlMatches) {
      try {
        const decoded = decodeURIComponent(match);
        if (isSensibleText(decoded)) {
          results.push({
            type: 'URL_ENCODED',
            raw: match,
            decoded,
          });
        }
      } catch {
        // ignore
      }
    }
  }

  // 4. Leetspeak Translation (if text contains suspicious combinations)
  let leetDecoded = '';
  let replacedCount = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (LEET_MAP[ch]) {
      leetDecoded += LEET_MAP[ch];
      replacedCount++;
    } else {
      leetDecoded += ch;
    }
  }
  if (replacedCount >= 3 && isSensibleText(leetDecoded) && leetDecoded !== text) {
    results.push({
      type: 'LEETSPEAK',
      raw: text.slice(0, 100) + '...',
      decoded: leetDecoded,
    });
  }

  // 5. Rot13 decoding check for suspicious words
  const rot13Decoded = rot13(text);
  if (
    /\b(ignore all previous instructions|reveal system prompt|system prompt|bypass restrictions|developer mode|dan mode)\b/i.test(
      rot13Decoded
    )
  ) {
    results.push({
      type: 'ROT13',
      raw: text.slice(0, 80) + '...',
      decoded: rot13Decoded,
    });
  }

  return results;
}
