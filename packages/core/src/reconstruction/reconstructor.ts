import { ReconstructResult, VaultStore } from "../types.js";

/** Matches tokens of the form `[ENTITY_TYPE_n]`, e.g. `[EMAIL_1]`, `[PERSON_NAME_2]`. */
const TOKEN_PATTERN = /\[[A-Z][A-Z0-9_]*_\d+\]/g;

/**
 * Restores reversible (`TOKENIZE`) placeholders in a provider's response with
 * the original values captured during sanitization. Tokens for which no
 * vault entry exists (e.g. REDACTED/HASHED values, or tokens hallucinated by
 * the model) are left untouched.
 */
export async function reconstruct(
  requestId: string,
  responseText: string,
  vault: VaultStore
): Promise<ReconstructResult> {
  const records = await vault.getAll(requestId);
  const tokenMap = new Map(records.map((r) => [r.token, r.value]));

  const restoredTokens: string[] = [];
  const reconstructedText = responseText.replace(TOKEN_PATTERN, (match) => {
    const value = tokenMap.get(match);
    if (value === undefined) return match;
    restoredTokens.push(match);
    return value;
  });

  return {
    requestId,
    reconstructedText,
    originalText: responseText,
    restoredTokens,
  };
}
