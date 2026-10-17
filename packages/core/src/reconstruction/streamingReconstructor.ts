import { VaultStore } from "../types.js";

/** Matches tokens of the form `[ENTITY_TYPE_n]`, e.g. `[EMAIL_1]`, `[PERSON_NAME_2]`. */
const TOKEN_PATTERN = /\[[A-Z][A-Z0-9_]*_\d+\]/g;

/**
 * Incrementally reconstructs a streamed provider response. Streaming deltas can
 * split a placeholder like `[EMAIL_1]` across chunk boundaries, so this holds
 * back any trailing text that could be the start of an unfinished token until
 * enough has arrived to decide. Everything safely before that point is
 * reconstructed and returned immediately.
 */
export interface StreamingReconstructor {
  /** Feed the next raw delta; returns reconstructed text that is safe to emit now (may be ""). */
  push(chunk: string): string;
  /** Call once the stream ends; returns the reconstructed remainder. */
  flush(): string;
  /** Tokens restored so far (for audit/debugging; never contains raw values on its own). */
  readonly restoredTokens: readonly string[];
}

/**
 * Builds a {@link StreamingReconstructor} for a request. Loads the request's
 * vault entries once up front, so `push`/`flush` are synchronous and cheap.
 */
export async function createStreamingReconstructor(
  requestId: string,
  vault: VaultStore
): Promise<StreamingReconstructor> {
  const records = await vault.getAll(requestId);
  const tokenMap = new Map(records.map((r) => [r.token, r.value]));
  const restoredTokens: string[] = [];
  let buffer = "";

  const reconstruct = (text: string): string =>
    text.replace(TOKEN_PATTERN, (match) => {
      const value = tokenMap.get(match);
      if (value === undefined) return match;
      restoredTokens.push(match);
      return value;
    });

  return {
    restoredTokens,
    push(chunk: string): string {
      buffer += chunk;
      // Hold back from the last unclosed '[' — it may be the start of a token
      // whose closing ']' hasn't streamed in yet.
      const lastOpen = buffer.lastIndexOf("[");
      let safeLen: number;
      if (lastOpen === -1) {
        safeLen = buffer.length;
      } else {
        const closeAfter = buffer.indexOf("]", lastOpen);
        safeLen = closeAfter === -1 ? lastOpen : buffer.length;
      }
      const emit = buffer.slice(0, safeLen);
      buffer = buffer.slice(safeLen);
      return reconstruct(emit);
    },
    flush(): string {
      const out = reconstruct(buffer);
      buffer = "";
      return out;
    },
  };
}
