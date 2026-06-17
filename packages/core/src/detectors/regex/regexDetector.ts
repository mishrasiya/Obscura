import { DetectedEntity, ENTITY_CATEGORY, CustomRule } from "../../types.js";
import { ALL_REGEX_RULES, RegexRule } from "./patterns.js";

interface Candidate {
  entity: DetectedEntity;
  ruleIndex: number;
}

/**
 * Runs all built-in (and any custom) regex rules against `text` and returns
 * a non-overlapping set of detected entities.
 *
 * Overlap resolution: candidates are sorted by start offset, then by longest
 * match, then by rule declaration order (earlier rules in `ALL_REGEX_RULES`
 * are more specific and win ties). Greedy selection then picks
 * non-overlapping spans in that order.
 */
export function detectWithRegex(text: string, customRules: CustomRule[] = []): DetectedEntity[] {
  const rules: { rule: RegexRule | CustomRule; index: number; isCustom: boolean }[] = [
    ...ALL_REGEX_RULES.map((rule, index) => ({ rule, index, isCustom: false })),
    ...customRules.map((rule, index) => ({ rule, index: ALL_REGEX_RULES.length + index, isCustom: true })),
  ];

  const candidates: Candidate[] = [];

  for (const { rule, index, isCustom } of rules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    for (const match of text.matchAll(pattern)) {
      if (match.index === undefined) continue;
      const value = match[0];

      if (!isCustom) {
        const regexRule = rule as RegexRule;
        if (regexRule.validate && !regexRule.validate(value)) continue;
      }

      const type = isCustom ? (rule as CustomRule).name : (rule as RegexRule).type;
      const category = isCustom ? (rule as CustomRule).category : ENTITY_CATEGORY[(rule as RegexRule).type];

      candidates.push({
        entity: {
          type: type as any,
          category,
          value,
          start: match.index,
          end: match.index + value.length,
          confidence: 1.0,
          source: "regex",
        },
        ruleIndex: index,
      });
    }
  }

  // Sort: earliest start first, then longest match first, then rule priority (declaration order)
  candidates.sort((a, b) => {
    if (a.entity.start !== b.entity.start) return a.entity.start - b.entity.start;
    const lenA = a.entity.end - a.entity.start;
    const lenB = b.entity.end - b.entity.start;
    if (lenA !== lenB) return lenB - lenA;
    return a.ruleIndex - b.ruleIndex;
  });

  const selected: DetectedEntity[] = [];
  let lastEnd = -1;
  for (const { entity } of candidates) {
    if (entity.start >= lastEnd) {
      selected.push(entity);
      lastEnd = entity.end;
    }
  }

  return selected;
}
