import { DetectedEntity, ENTITY_CATEGORY, KnownEntity } from "../../types.js";

/** Escapes regex special characters so a known value can be matched literally. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** True if `ch` should participate in a `\b`-style word boundary. */
function isWordChar(ch: string | undefined): boolean {
  return !!ch && /[A-Za-z0-9_]/.test(ch);
}

/**
 * Deterministic, lookup-based detection: scans `text` for verbatim,
 * case-insensitive, whole-word occurrences of every value in
 * `knownEntities`. Unlike the regex and NER detectors, this never guesses -
 * a value is only flagged if it exactly matches an entry in the database.
 */
export function detectWithDictionary(text: string, knownEntities: KnownEntity[]): DetectedEntity[] {
  const entities: DetectedEntity[] = [];

  for (const known of knownEntities) {
    const value = known.value?.trim();
    if (!value) continue;

    const pattern = new RegExp(escapeRegExp(value), "gi");
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      const start = match.index;
      const end = start + match[0].length;

      // Enforce word boundaries only where the matched text starts/ends on a
      // "word" character, so values containing punctuation (emails, phone
      // numbers, etc.) still match correctly.
      const beforeOk = !isWordChar(match[0][0]) || !isWordChar(text[start - 1]);
      const afterOk = !isWordChar(match[0][match[0].length - 1]) || !isWordChar(text[end]);
      if (!beforeOk || !afterOk) continue;

      entities.push({
        type: known.type,
        category: ENTITY_CATEGORY[known.type],
        value: match[0],
        start,
        end,
        confidence: 1,
        source: "dictionary",
      });
    }
  }

  return entities;
}
