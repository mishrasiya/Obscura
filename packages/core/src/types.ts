/**
 * Core type definitions and entity taxonomy for the Obscura sanitization engine.
 */

/** High-level classification used for reporting and policy grouping. */
export type EntityCategory = "PII" | "PHI" | "SECRET";

/**
 * Canonical entity types detected across PII, PHI, and secrets domains.
 * New types can be appended without breaking existing policy configs
 * because policies fall back to `DEFAULT_POLICY` for unknown keys.
 */
export enum EntityType {
  // ---- PII ----
  EMAIL = "EMAIL",
  PHONE_NUMBER = "PHONE_NUMBER",
  SSN = "SSN",
  TAX_ID = "TAX_ID",                               // EIN / TIN / ITIN
  SALARY = "SALARY",                               // Annual / base salary or wage
  TAX_FORM = "TAX_FORM",                           // W-2 / 1099 wage forms
  CREDIT_CARD = "CREDIT_CARD",
  CVV = "CVV",                                      // Card security code
  CREDIT_CARD_EXPIRATION = "CREDIT_CARD_EXPIRATION",
  CREDIT_SCORE = "CREDIT_SCORE",                    // FICO / credit score
  IP_ADDRESS = "IP_ADDRESS",
  IBAN = "IBAN",
  BANK_ACCOUNT = "BANK_ACCOUNT",
  ROUTING_NUMBER = "ROUTING_NUMBER",                // ABA / ACH routing number
  SWIFT_CODE = "SWIFT_CODE",                        // SWIFT / BIC bank code
  CRYPTO_WALLET = "CRYPTO_WALLET",                  // BTC / ETH wallet address
  PASSPORT_NUMBER = "PASSPORT_NUMBER",
  DRIVERS_LICENSE = "DRIVERS_LICENSE",
  DATE_OF_BIRTH = "DATE_OF_BIRTH",
  DATE = "DATE",                                    // Any calendar date more specific than a year
  PERSON_NAME = "PERSON_NAME",
  ADDRESS = "ADDRESS",
  ORGANIZATION = "ORGANIZATION",
  LOCATION = "LOCATION",
  USERNAME = "USERNAME",
  MAC_ADDRESS = "MAC_ADDRESS",
  IMEI = "IMEI",                                    // Mobile device IMEI
  VIN = "VIN",
  URL = "URL",
  GEOLOCATION = "GEOLOCATION",
  FAX_NUMBER = "FAX_NUMBER",
  ZIP_CODE = "ZIP_CODE",
  LICENSE_PLATE = "LICENSE_PLATE",

  // ---- PHI ----
  MEDICAL_RECORD_NUMBER = "MEDICAL_RECORD_NUMBER",
  ICD_CODE = "ICD_CODE",
  CPT_CODE = "CPT_CODE",                            // CPT procedure code
  SNOMED_CODE = "SNOMED_CODE",                      // SNOMED CT concept code
  RXCUI_CODE = "RXCUI_CODE",                        // RxNorm concept identifier
  NPI_NUMBER = "NPI_NUMBER",
  HEALTH_INSURANCE_ID = "HEALTH_INSURANCE_ID",
  DEA_NUMBER = "DEA_NUMBER",
  BILLING_ACCOUNT_NUMBER = "BILLING_ACCOUNT_NUMBER",
  ENCOUNTER_NUMBER = "ENCOUNTER_NUMBER",            // Encounter / visit / account number
  ROOM_NUMBER = "ROOM_NUMBER",                      // Hospital room / bed identifier
  DATE_OF_SERVICE = "DATE_OF_SERVICE",
  PATIENT_ID = "PATIENT_ID",
  PROVIDER_LICENSE_NUMBER = "PROVIDER_LICENSE_NUMBER",
  MEDICAL_DEVICE_SERIAL = "MEDICAL_DEVICE_SERIAL",  // Implant / pacemaker serial
  CLINICAL_NOTE = "CLINICAL_NOTE",                  // Clinical narrative / SOAP note section

  // ---- Secrets ----
  AWS_ACCESS_KEY = "AWS_ACCESS_KEY",
  AWS_SECRET_KEY = "AWS_SECRET_KEY",
  GCP_API_KEY = "GCP_API_KEY",
  AZURE_CLIENT_SECRET = "AZURE_CLIENT_SECRET",
  GITHUB_TOKEN = "GITHUB_TOKEN",
  SLACK_TOKEN = "SLACK_TOKEN",
  SLACK_WEBHOOK = "SLACK_WEBHOOK",                  // Slack incoming webhook URL
  STRIPE_API_KEY = "STRIPE_API_KEY",                // Stripe sk_ / pk_ / rk_ key
  PAYPAL_SECRET = "PAYPAL_SECRET",                  // PayPal client secret
  OPENAI_API_KEY = "OPENAI_API_KEY",
  ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY",
  JWT = "JWT",
  PRIVATE_KEY = "PRIVATE_KEY",
  CRYPTO_PRIVATE_KEY = "CRYPTO_PRIVATE_KEY",        // Wallet seed phrase / hex key
  DB_CONNECTION_STRING = "DB_CONNECTION_STRING",
  GENERIC_API_KEY = "GENERIC_API_KEY",
  PASSWORD_ASSIGNMENT = "PASSWORD_ASSIGNMENT",
  CUI_MARKING = "CUI_MARKING",                      // CUI / CONTROLLED UNCLASSIFIED INFORMATION
}

/** Maps each entity type to its broad data-protection category. */
export const ENTITY_CATEGORY: Record<EntityType, EntityCategory> = {
  [EntityType.EMAIL]: "PII",
  [EntityType.PHONE_NUMBER]: "PII",
  [EntityType.SSN]: "PII",
  [EntityType.TAX_ID]: "PII",
  [EntityType.SALARY]: "PII",
  [EntityType.TAX_FORM]: "PII",
  [EntityType.CREDIT_CARD]: "PII",
  [EntityType.CVV]: "PII",
  [EntityType.CREDIT_CARD_EXPIRATION]: "PII",
  [EntityType.CREDIT_SCORE]: "PII",
  [EntityType.IP_ADDRESS]: "PII",
  [EntityType.IBAN]: "PII",
  [EntityType.BANK_ACCOUNT]: "PII",
  [EntityType.ROUTING_NUMBER]: "PII",
  [EntityType.SWIFT_CODE]: "PII",
  [EntityType.CRYPTO_WALLET]: "PII",
  [EntityType.PASSPORT_NUMBER]: "PII",
  [EntityType.DRIVERS_LICENSE]: "PII",
  [EntityType.DATE_OF_BIRTH]: "PII",
  [EntityType.DATE]: "PII",
  [EntityType.PERSON_NAME]: "PII",
  [EntityType.ADDRESS]: "PII",
  [EntityType.ORGANIZATION]: "PII",
  [EntityType.LOCATION]: "PII",
  [EntityType.USERNAME]: "PII",
  [EntityType.MAC_ADDRESS]: "PII",
  [EntityType.IMEI]: "PII",
  [EntityType.VIN]: "PII",
  [EntityType.URL]: "PII",
  [EntityType.GEOLOCATION]: "PII",
  [EntityType.FAX_NUMBER]: "PII",
  [EntityType.ZIP_CODE]: "PII",
  [EntityType.LICENSE_PLATE]: "PII",

  [EntityType.MEDICAL_RECORD_NUMBER]: "PHI",
  [EntityType.ICD_CODE]: "PHI",
  [EntityType.CPT_CODE]: "PHI",
  [EntityType.SNOMED_CODE]: "PHI",
  [EntityType.RXCUI_CODE]: "PHI",
  [EntityType.NPI_NUMBER]: "PHI",
  [EntityType.HEALTH_INSURANCE_ID]: "PHI",
  [EntityType.DEA_NUMBER]: "PHI",
  [EntityType.BILLING_ACCOUNT_NUMBER]: "PHI",
  [EntityType.ENCOUNTER_NUMBER]: "PHI",
  [EntityType.ROOM_NUMBER]: "PHI",
  [EntityType.DATE_OF_SERVICE]: "PHI",
  [EntityType.PATIENT_ID]: "PHI",
  [EntityType.PROVIDER_LICENSE_NUMBER]: "PHI",
  [EntityType.MEDICAL_DEVICE_SERIAL]: "PHI",
  [EntityType.CLINICAL_NOTE]: "PHI",

  [EntityType.AWS_ACCESS_KEY]: "SECRET",
  [EntityType.AWS_SECRET_KEY]: "SECRET",
  [EntityType.GCP_API_KEY]: "SECRET",
  [EntityType.AZURE_CLIENT_SECRET]: "SECRET",
  [EntityType.GITHUB_TOKEN]: "SECRET",
  [EntityType.SLACK_TOKEN]: "SECRET",
  [EntityType.SLACK_WEBHOOK]: "SECRET",
  [EntityType.STRIPE_API_KEY]: "SECRET",
  [EntityType.PAYPAL_SECRET]: "SECRET",
  [EntityType.OPENAI_API_KEY]: "SECRET",
  [EntityType.ANTHROPIC_API_KEY]: "SECRET",
  [EntityType.JWT]: "SECRET",
  [EntityType.PRIVATE_KEY]: "SECRET",
  [EntityType.CRYPTO_PRIVATE_KEY]: "SECRET",
  [EntityType.DB_CONNECTION_STRING]: "SECRET",
  [EntityType.GENERIC_API_KEY]: "SECRET",
  [EntityType.PASSWORD_ASSIGNMENT]: "SECRET",
  [EntityType.CUI_MARKING]: "SECRET",
};

/**
 * How a detected entity should be transformed before the text leaves the
 * trust boundary.
 *
 *  - TOKENIZE: replace with a reversible placeholder (e.g. `[EMAIL_1]`),
 *    original value stored in the vault for later reconstruction.
 *  - REDACT: replace with a fixed, non-reversible placeholder.
 *  - HASH: replace with a deterministic, non-reversible hash-based token
 *    (useful when the LLM needs a stable identifier without the real value).
 *  - PARTIAL_MASK: keep a small amount of context (e.g. last 4 digits).
 *  - ALLOW: leave the value untouched.
 */
export enum MaskingStrategy {
  TOKENIZE = "TOKENIZE",
  REDACT = "REDACT",
  HASH = "HASH",
  PARTIAL_MASK = "PARTIAL_MASK",
  ALLOW = "ALLOW",
}

/** A single occurrence of a sensitive entity found in text. */
export interface DetectedEntity {
  type: EntityType;
  category: EntityCategory;
  /** Raw matched substring. */
  value: string;
  /** Inclusive start offset (UTF-16 code units) in the original text. */
  start: number;
  /** Exclusive end offset (UTF-16 code units) in the original text. */
  end: number;
  /** Confidence score in [0, 1]. Regex detectors typically report 1.0. */
  confidence: number;
  /** Which detector produced this finding. */
  source: "regex" | "ner" | "dictionary";
}

/**
 * A known sensitive value to match verbatim (case-insensitive, whole-word),
 * independent of the regex/NER detectors. Used to build a deterministic
 * "PII/PHI database" of values (e.g. real names, employee emails, internal
 * IDs) that should always be redacted without relying on pattern guesses.
 */
export interface KnownEntity {
  /** The exact sensitive value to look for, e.g. "Jane Doe" or "jane.doe@example.com". */
  value: string;
  /** Entity type to record/mask this value as. */
  type: EntityType;
}

/** Per-entity-type masking configuration. */
export type PolicyConfig = Partial<Record<EntityType, MaskingStrategy>>;

/** A custom, user-supplied detection rule (e.g. internal project codenames). */
export interface CustomRule {
  /** Unique name, also used as the token label, e.g. "PROJECT_CODENAME". */
  name: string;
  pattern: RegExp;
  category: EntityCategory;
  strategy: MaskingStrategy;
}

/** Mapping of placeholder tokens back to their original values. */
export interface VaultRecord {
  token: string;
  value: string;
  type: EntityType | string;
  requestId: string;
  createdAt: number;
  expiresAt: number;
}

/** Pluggable storage backend for vault records (default: in-memory). */
export interface VaultStore {
  set(record: VaultRecord): Promise<void>;
  get(token: string): Promise<VaultRecord | undefined>;
  getAll(requestId: string): Promise<VaultRecord[]>;
  deleteAll(requestId: string): Promise<void>;
}

/** Result of sanitizing a single piece of text. */
export interface SanitizeResult {
  requestId: string;
  /** Text with sensitive entities masked/tokenized according to policy. */
  sanitizedText: string;
  /** Original text, unchanged (returned for convenience/audit). */
  originalText: string;
  /** All entities detected, in order of appearance. */
  entities: DetectedEntity[];
}

/** Result of reconstructing a provider response. */
export interface ReconstructResult {
  requestId: string;
  /** Provider response text with reversible tokens restored. */
  reconstructedText: string;
  /** Original (still-masked) provider response text. */
  originalText: string;
  /** Tokens that were found and restored. */
  restoredTokens: string[];
}

/** A structured, PII-free record of a sanitization event for compliance audit trails. */
export interface AuditEvent {
  requestId: string;
  timestamp: number;
  action: "sanitize" | "reconstruct";
  /** Counts of detected entities grouped by type. Never includes raw values. */
  entityCounts: Partial<Record<EntityType | string, number>>;
  totalEntities: number;
}

/** Sink for audit events (default: in-memory ring buffer). */
export interface AuditSink {
  record(event: AuditEvent): void;
  getEvents(): AuditEvent[];
}

/** Top-level configuration for the Sanitizer. */
export interface SanitizerConfig {
  /** Per-entity-type masking strategy overrides. Merged over DEFAULT_POLICY. */
  policy?: PolicyConfig;
  /** Additional organization-specific detection rules. */
  customRules?: CustomRule[];
  /**
   * A deterministic "database" of known sensitive values (e.g. real names,
   * employee emails, internal account numbers). Any exact, whole-word match
   * of these values is always redacted/tokenized - no regex guessing or NER
   * model involved. Takes priority over regex and NER on overlap.
   */
  knownEntities?: KnownEntity[];
  /**
   * Path to a JSON file containing an array of `KnownEntity` objects. Loaded
   * at construction time and merged with `knownEntities`. When entries are
   * added/removed via `addKnownEntities`/`removeKnownEntity`, this file is
   * updated to persist the change.
   */
  knownEntitiesFile?: string;
  /** Enable the transformer-based NER detector for names/orgs/locations. Default: true. */
  enableNer?: boolean;
  /** TTL (ms) for vault records before they're eligible for cleanup. Default: 1 hour. */
  vaultTtlMs?: number;
  /** Custom vault storage backend. Default: in-memory, AES-256-GCM encrypted at rest. */
  vaultStore?: VaultStore;
  /** Custom audit sink. Default: in-memory ring buffer. */
  auditSink?: AuditSink;
  /** 32-byte key (or hex/base64 string) used to encrypt vault entries at rest. */
  encryptionKey?: string | Buffer;
}
