import { DetectedEntity, ENTITY_CATEGORY, EntityType } from "../../types.js";

/**
 * Detects sensitive numbers that have been written to evade the structured
 * regex detectors - e.g. an SSN spelled out as "zero-zero-zero, dash,
 * four-five, dash, six-seven-eight-nine" or a phone as "(312) five-five-five
 * - 0194". These forms carry real digits but no canonical shape, so we scan
 * for runs of digits + number-words + connective separators, reconstruct the
 * underlying digit string, and classify by length.
 *
 * To avoid duplicating (and over-matching versus) the pure-digit regex rules,
 * a run is only considered here if it contains at least one spelled number
 * word.
 */

const NUMBER_WORDS: Record<string, string> = {
  zero: "0",
  oh: "0",
  one: "1",
  two: "2",
  three: "3",
  four: "4",
  five: "5",
  six: "6",
  seven: "7",
  eight: "8",
  nine: "9",
};

// A single "digit token": a run of digits, or one spelled number word.
const TOKEN = String.raw`(?:\d+|\b(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)\b)`;
// Connective tissue between tokens: punctuation/whitespace and the literal
// words "dash"/"dot" people dictate in place of separators.
const SEP = String.raw`(?:[\s().,/\-]+|\bdash\b|\bdot\b)+`;
const RUN = new RegExp(`${TOKEN}(?:${SEP}${TOKEN})*`, "gi");
const TOKEN_ONLY = new RegExp(TOKEN, "gi");

/** Luhn checksum, to confirm a 13-19 digit run is plausibly a card number. */
function luhnOk(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function detectObfuscated(text: string): DetectedEntity[] {
  const out: DetectedEntity[] = [];

  for (const match of text.matchAll(RUN)) {
    if (match.index === undefined) continue;
    const run = match[0];

    let digits = "";
    let hasWord = false;
    for (const tm of run.matchAll(TOKEN_ONLY)) {
      const tok = tm[0].toLowerCase();
      if (/^\d+$/.test(tok)) {
        digits += tok;
      } else {
        digits += NUMBER_WORDS[tok];
        hasWord = true;
      }
    }

    // Pure-digit runs are already handled by the structured regex rules.
    if (!hasWord) continue;

    const n = digits.length;
    let type: EntityType | null = null;
    if (n === 9) type = EntityType.SSN;
    else if (n === 7 || n === 10 || n === 11) type = EntityType.PHONE_NUMBER;
    else if (n >= 13 && n <= 19 && luhnOk(digits)) type = EntityType.CREDIT_CARD;

    if (!type) continue;

    out.push({
      type,
      category: ENTITY_CATEGORY[type],
      value: run,
      start: match.index,
      end: match.index + run.length,
      confidence: 1,
      source: "regex",
    });
  }

  return out;
}
