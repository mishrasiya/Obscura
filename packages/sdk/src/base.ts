import { Sanitizer, SanitizerConfig } from "@privacyguard/core";

/**
 * Shared base for provider-specific privacy-preserving clients. Holds the
 * underlying {@link Sanitizer} instance used to mask outgoing prompts and
 * restore reversible placeholders in responses.
 */
export abstract class BasePrivacyGuardClient {
  protected readonly sanitizer: Sanitizer;

  constructor(sanitizerConfig: SanitizerConfig = {}) {
    this.sanitizer = new Sanitizer(sanitizerConfig);
  }

  /** Pre-loads the local NER model. Call once at startup to avoid latency on the first request. */
  async warmup(): Promise<void> {
    await this.sanitizer.warmup();
  }

  /** Returns the audit trail (entity-type counts only - never raw values). */
  getAuditEvents() {
    return this.sanitizer.getAuditEvents();
  }
}
