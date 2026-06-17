/**
 * Helpers for pulling text content out of provider-specific message arrays
 * (OpenAI and Anthropic both use `{ role, content: string | Array<{ type, text }> }`),
 * sanitizing it as a batch, and rebuilding the message array with sanitized text.
 */

export interface TextRef {
  msgIndex: number;
  partIndex?: number;
}

interface MessageLike {
  content?: unknown;
}

/** Extracts all text strings from a message array, recording where each came from. */
export function extractTexts(messages: readonly MessageLike[]): { texts: string[]; refs: TextRef[] } {
  const texts: string[] = [];
  const refs: TextRef[] = [];

  messages.forEach((msg, i) => {
    const content = msg.content;
    if (typeof content === "string") {
      texts.push(content);
      refs.push({ msgIndex: i });
    } else if (Array.isArray(content)) {
      content.forEach((part, j) => {
        if (part && typeof part === "object" && (part as any).type === "text" && typeof (part as any).text === "string") {
          texts.push((part as any).text);
          refs.push({ msgIndex: i, partIndex: j });
        }
      });
    }
  });

  return { texts, refs };
}

/** Rebuilds a message array, substituting sanitized text at the positions recorded by {@link extractTexts}. */
export function rebuildWithTexts<T extends MessageLike>(messages: readonly T[], refs: TextRef[], texts: string[]): T[] {
  const result = messages.map((m) => {
    if (Array.isArray(m.content)) {
      return { ...m, content: (m.content as unknown[]).map((p) => (typeof p === "object" && p !== null ? { ...p } : p)) };
    }
    return { ...m };
  }) as T[];

  refs.forEach((ref, idx) => {
    const target = result[ref.msgIndex] as MessageLike;
    if (ref.partIndex === undefined) {
      target.content = texts[idx];
    } else {
      (target.content as any[])[ref.partIndex].text = texts[idx];
    }
  });

  return result;
}
