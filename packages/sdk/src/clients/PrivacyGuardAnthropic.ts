import Anthropic from "@anthropic-ai/sdk";
import type { Message, MessageCreateParamsNonStreaming, TextBlockParam } from "@anthropic-ai/sdk/resources/messages";
import type { SanitizerConfig } from "@privacyguard/core";
import { BasePrivacyGuardClient } from "../base.js";
import { extractTexts, rebuildWithTexts } from "../textExtraction.js";

export interface PrivacyGuardAnthropicOptions {
  apiKey?: string;
  baseURL?: string;
}

/**
 * Drop-in, privacy-preserving wrapper around the Anthropic SDK's Messages
 * API. Sanitizes both `system` and `messages` content before sending the
 * request, and restores reversible placeholders in the response's text
 * blocks.
 *
 * ```ts
 * const client = new PrivacyGuardAnthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
 * const response = await client.messages.create({
 *   model: "claude-sonnet-4-6",
 *   max_tokens: 1024,
 *   messages: [{ role: "user", content: "My SSN is 123-45-6789..." }],
 * });
 * ```
 *
 * Note: streaming responses are not yet supported; `stream` is forced to `false`.
 */
export class PrivacyGuardAnthropic extends BasePrivacyGuardClient {
  private readonly client: Anthropic;

  constructor(options: PrivacyGuardAnthropicOptions = {}, sanitizerConfig: SanitizerConfig = {}) {
    super(sanitizerConfig);
    this.client = new Anthropic(options);
  }

  /** Access to the underlying, unwrapped Anthropic client for endpoints not covered by this wrapper. */
  get raw(): Anthropic {
    return this.client;
  }

  get messages() {
    return {
      create: (params: MessageCreateParamsNonStreaming) => this.createMessage(params),
    };
  }

  private async createMessage(params: MessageCreateParamsNonStreaming): Promise<Message> {
    const { messages, system } = params;

    // Extract system-prompt text segments (string or array of text blocks)
    // alongside message text, so everything is sanitized as one consistent batch.
    let systemTextCount = 0;
    let systemTexts: string[] = [];
    if (typeof system === "string") {
      systemTexts = [system];
      systemTextCount = 1;
    } else if (Array.isArray(system)) {
      systemTexts = system.map((block) => block.text);
      systemTextCount = system.length;
    }

    const { texts: messageTexts, refs: messageRefs } = extractTexts(messages);

    const { requestId, sanitizedTexts } = await this.sanitizer.sanitizeBatch([...systemTexts, ...messageTexts]);
    const sanitizedSystemTexts = sanitizedTexts.slice(0, systemTextCount);
    const sanitizedMessageTexts = sanitizedTexts.slice(systemTextCount);

    const sanitizedMessages = rebuildWithTexts(messages, messageRefs, sanitizedMessageTexts);

    let sanitizedSystem: typeof system;
    if (typeof system === "string") {
      sanitizedSystem = sanitizedSystemTexts[0];
    } else if (Array.isArray(system)) {
      sanitizedSystem = system.map((block, i) => ({ ...block, text: sanitizedSystemTexts[i] }) as TextBlockParam);
    } else {
      sanitizedSystem = system;
    }

    const response = await this.client.messages.create({
      ...params,
      system: sanitizedSystem,
      messages: sanitizedMessages,
      stream: false,
    });

    for (const block of response.content) {
      if (block.type === "text") {
        const { reconstructedText } = await this.sanitizer.reconstruct(requestId, block.text);
        block.text = reconstructedText;
      }
    }

    await this.sanitizer.clearSession(requestId);
    return response;
  }
}
