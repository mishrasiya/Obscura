import { EntityType, ENTITY_CATEGORY, MaskingStrategy, PolicyConfig, CustomRule } from "../types.js";

/**
 * Enterprise-safe default policy:
 *  - Secrets are always REDACTED (never need to be reconstructed; the LLM
 *    should never see real credentials).
 *  - Direct identifiers and PHI are TOKENIZED so the original value can be
 *    restored in the response shown back to the user.
 *  - Structured numeric identifiers (cards, accounts, SSNs, phones) use
 *    PARTIAL_MASK only as a fallback if a deployment wants to *not* use
 *    tokenization for them; by default these are tokenized too for full
 *    reversibility.
 */
export const DEFAULT_POLICY: Record<EntityType, MaskingStrategy> = {
  // PII - tokenized (reversible)
  [EntityType.EMAIL]: MaskingStrategy.TOKENIZE,
  [EntityType.PHONE_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.SSN]: MaskingStrategy.TOKENIZE,
  [EntityType.CREDIT_CARD]: MaskingStrategy.TOKENIZE,
  [EntityType.IP_ADDRESS]: MaskingStrategy.TOKENIZE,
  [EntityType.IBAN]: MaskingStrategy.TOKENIZE,
  [EntityType.BANK_ACCOUNT]: MaskingStrategy.TOKENIZE,
  [EntityType.PASSPORT_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.DRIVERS_LICENSE]: MaskingStrategy.TOKENIZE,
  [EntityType.DATE_OF_BIRTH]: MaskingStrategy.TOKENIZE,
  [EntityType.PERSON_NAME]: MaskingStrategy.TOKENIZE,
  [EntityType.ADDRESS]: MaskingStrategy.TOKENIZE,
  [EntityType.ORGANIZATION]: MaskingStrategy.TOKENIZE,
  [EntityType.LOCATION]: MaskingStrategy.TOKENIZE,
  [EntityType.USERNAME]: MaskingStrategy.TOKENIZE,
  [EntityType.MAC_ADDRESS]: MaskingStrategy.TOKENIZE,
  [EntityType.VIN]: MaskingStrategy.TOKENIZE,
  [EntityType.URL]: MaskingStrategy.TOKENIZE,
  [EntityType.GEOLOCATION]: MaskingStrategy.TOKENIZE,
  [EntityType.FAX_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.CREDIT_CARD_EXPIRATION]: MaskingStrategy.TOKENIZE,
  [EntityType.ZIP_CODE]: MaskingStrategy.TOKENIZE,
  [EntityType.LICENSE_PLATE]: MaskingStrategy.TOKENIZE,

  // PHI - tokenized (reversible)
  [EntityType.MEDICAL_RECORD_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.ICD_CODE]: MaskingStrategy.TOKENIZE,
  [EntityType.NPI_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.HEALTH_INSURANCE_ID]: MaskingStrategy.TOKENIZE,
  [EntityType.DEA_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.BILLING_ACCOUNT_NUMBER]: MaskingStrategy.TOKENIZE,
  [EntityType.DATE_OF_SERVICE]: MaskingStrategy.TOKENIZE,
  [EntityType.PATIENT_ID]: MaskingStrategy.TOKENIZE,
  [EntityType.PROVIDER_LICENSE_NUMBER]: MaskingStrategy.TOKENIZE,

  // Secrets - always redacted, never forwarded or reconstructed
  [EntityType.AWS_ACCESS_KEY]: MaskingStrategy.REDACT,
  [EntityType.AWS_SECRET_KEY]: MaskingStrategy.REDACT,
  [EntityType.GCP_API_KEY]: MaskingStrategy.REDACT,
  [EntityType.AZURE_CLIENT_SECRET]: MaskingStrategy.REDACT,
  [EntityType.GITHUB_TOKEN]: MaskingStrategy.REDACT,
  [EntityType.SLACK_TOKEN]: MaskingStrategy.REDACT,
  [EntityType.OPENAI_API_KEY]: MaskingStrategy.REDACT,
  [EntityType.ANTHROPIC_API_KEY]: MaskingStrategy.REDACT,
  [EntityType.JWT]: MaskingStrategy.REDACT,
  [EntityType.PRIVATE_KEY]: MaskingStrategy.REDACT,
  [EntityType.DB_CONNECTION_STRING]: MaskingStrategy.REDACT,
  [EntityType.GENERIC_API_KEY]: MaskingStrategy.REDACT,
  [EntityType.PASSWORD_ASSIGNMENT]: MaskingStrategy.REDACT,
};

/**
 * Resolves the effective masking strategy for a given entity type/category,
 * merging the default policy with any user-supplied overrides and custom rules.
 */
export class PolicyEngine {
  private readonly overrides: PolicyConfig;
  private readonly customRuleStrategies: Map<string, MaskingStrategy>;

  constructor(overrides: PolicyConfig = {}, customRules: CustomRule[] = []) {
    this.overrides = overrides;
    this.customRuleStrategies = new Map(customRules.map((r) => [r.name, r.strategy]));
  }

  /** Returns the strategy to apply for a detected entity's type (or custom rule name). */
  strategyFor(type: EntityType | string): MaskingStrategy {
    if (this.customRuleStrategies.has(type)) {
      return this.customRuleStrategies.get(type)!;
    }
    if (type in DEFAULT_POLICY) {
      const entityType = type as EntityType;
      return this.overrides[entityType] ?? DEFAULT_POLICY[entityType];
    }
    // Unknown type (e.g. custom rule without explicit registration): default to redact-safe.
    return MaskingStrategy.REDACT;
  }

  /** Returns the category for a type, used for audit grouping. */
  static categoryFor(type: EntityType | string, customRules: CustomRule[] = []): string {
    if (type in ENTITY_CATEGORY) return ENTITY_CATEGORY[type as EntityType];
    const custom = customRules.find((r) => r.name === type);
    return custom?.category ?? "PII";
  }
}
