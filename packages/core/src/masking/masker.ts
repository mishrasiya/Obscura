import { createHash } from "node:crypto";
import { DetectedEntity, MaskingStrategy } from "../types.js";
import { PolicyEngine } from "../policy/policyEngine.js";

/** A vault entry waiting to be persisted, produced for every TOKENIZE replacement. */
export interface PendingVaultEntry {
  token: string;
  value: string;
  type: string;
}

export interface MaskResult {
  sanitizedText: string;
  /** Entries that must be written to the vault for later reconstruction. */
  pendingVaultEntries: PendingVaultEntry[];
}

/** Number of trailing characters preserved by PARTIAL_MASK. */
const PARTIAL_MASK_VISIBLE_CHARS = 4;

function partialMask(value: string): string {
  const visible = value.replace(/[^a-zA-Z0-9]/g, "").slice(-PARTIAL_MASK_VISIBLE_CHARS);
  return `****${visible}`;
}

function hashToken(type: string, value: string): string {
  const digest = createHash("sha256").update(value).digest("hex").slice(0, 10);
  return `[${type}_HASH_${digest}]`;
}

/**
 * Applies masking to `text` given a set of non-overlapping, sorted `entities`.
 * Returns the sanitized text plus any vault entries that should be persisted
 * for reversible (TOKENIZE) replacements.
 */
export function applyMasking(
  text: string,
  entities: DetectedEntity[],
  policy: PolicyEngine,
  initialTokenCounters: ReadonlyMap<string, number> = new Map()
): MaskResult {
  if (entities.length === 0) {
    return { sanitizedText: text, pendingVaultEntries: [] };
  }

  const pendingVaultEntries: PendingVaultEntry[] = [];
  const tokenCounters = new Map(initialTokenCounters);

  let result = "";
  let cursor = 0;

  for (const entity of entities) {
    result += text.slice(cursor, entity.start);

    const strategy = policy.strategyFor(entity.type);

    switch (strategy) {
      case MaskingStrategy.ALLOW: {
        result += entity.value;
        break;
      }
      case MaskingStrategy.REDACT: {
        result += `[REDACTED_${entity.type}]`;
        break;
      }
      case MaskingStrategy.HASH: {
        result += hashToken(String(entity.type), entity.value);
        break;
      }
      case MaskingStrategy.PARTIAL_MASK: {
        result += partialMask(entity.value);
        break;
      }
      case MaskingStrategy.TOKENIZE:
      default: {
        const n = (tokenCounters.get(entity.type) ?? 0) + 1;
        tokenCounters.set(entity.type, n);
        const token = `[${entity.type}_${n}]`;
        result += token;
        pendingVaultEntries.push({ token, value: entity.value, type: String(entity.type) });
        break;
      }
    }

    cursor = entity.end;
  }

  result += text.slice(cursor);

  return { sanitizedText: result, pendingVaultEntries };
}
