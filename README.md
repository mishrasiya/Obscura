# PrivacyGuard

A privacy-first middleware platform that sits between your application and
third-party LLM providers (OpenAI, Anthropic, Gemini). It intercepts prompts
in real time, detects PII, PHI, and secrets, masks them before they reach the
provider, and reconstructs the original values in the response.

```
User prompt ──▶ [Sanitizer] ──▶ masked prompt ──▶ LLM provider (GPT/Claude/Gemini)
                     │                                      │
                  vault (encrypted,                         │
                  per-request)                              ▼
                     │                              provider response
                     └────────────▶ [Reconstructor] ◀───────┘
                                            │
                                            ▼
                                  response shown to user
```

## Packages

- **`@privacyguard/core`** - the sanitization engine: detectors, policy
  engine, masking, encrypted token vault, response reconstruction, and audit
  logging. No third-party network calls.
- **`@privacyguard/sdk`** - drop-in, privacy-preserving client wrappers for
  `openai`, `@anthropic-ai/sdk`, and `@google/generative-ai`.

## How it works

1. **Detect** - Every prompt is scanned by two complementary detectors:
   - **Regex/pattern detectors** for structured data: emails, phone numbers,
     SSNs, credit cards (Luhn-validated), IPs, IBANs, medical record numbers,
     ICD-10 codes, AWS/GCP/Azure/GitHub/Slack/OpenAI/Anthropic credentials,
     JWTs, private keys, DB connection strings, and more
     (`packages/core/src/detectors/regex/patterns.ts`).
   - **Local NER model** (`Xenova/bert-base-NER` via `@xenova/transformers`,
     running on-device via ONNX) for free-form person names, organizations,
     and locations not caught by regex.

2. **Mask** - Each detected entity is transformed according to a configurable
   policy:
   - `TOKENIZE` - replaced with a reversible placeholder (`[EMAIL_1]`); the
     original value is stored in an AES-256-GCM encrypted, per-request vault.
   - `REDACT` - replaced with a fixed, non-reversible placeholder
     (`[REDACTED_AWS_ACCESS_KEY]`). Used by default for all secrets/credentials.
   - `HASH` - replaced with a deterministic, non-reversible hash token.
   - `PARTIAL_MASK` - keeps the last 4 characters (e.g. `****1111`).
   - `ALLOW` - left untouched.

3. **Forward** - The sanitized text is sent to the LLM provider.

4. **Reconstruct** - When the response comes back, any `[EMAIL_1]`-style
   placeholders are replaced with their original values from the vault, so
   the end user sees their real data while the provider never did.

5. **Audit** - Every sanitize/reconstruct operation is logged as counts of
   entity types only (never raw values) for compliance reporting.

## Quick start

```bash
npm install
npm run build
```

### Core engine only

```ts
import { Sanitizer } from "@privacyguard/core";

const sanitizer = new Sanitizer();

const { requestId, sanitizedText } = await sanitizer.sanitize(
  "My email is jane@example.com and my AWS key is AKIAIOSFODNN7EXAMPLE."
);
// sanitizedText: "My email is [EMAIL_1] and my AWS key is [REDACTED_AWS_ACCESS_KEY]."

// ... send sanitizedText to your LLM provider, get `responseText` back ...

const { reconstructedText } = await sanitizer.reconstruct(requestId, responseText);
```

### Drop-in provider clients

```ts
import { PrivacyGuardOpenAI } from "@privacyguard/sdk";

const client = new PrivacyGuardOpenAI({ apiKey: process.env.OPENAI_API_KEY });

const completion = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Email jane@example.com about her invoice." }],
});
```

`PrivacyGuardAnthropic` and `PrivacyGuardGemini` work the same way for
`@anthropic-ai/sdk` and `@google/generative-ai` respectively. See
`examples/` for runnable samples.

## Configuration

```ts
import { Sanitizer, EntityType, MaskingStrategy } from "@privacyguard/core";

const sanitizer = new Sanitizer({
  // Override the default masking strategy per entity type.
  policy: {
    [EntityType.CREDIT_CARD]: MaskingStrategy.PARTIAL_MASK,
    [EntityType.IP_ADDRESS]: MaskingStrategy.HASH,
  },
  // Add organization-specific detection rules.
  customRules: [
    {
      name: "PROJECT_CODENAME",
      pattern: /Project[ -]?Nightingale/gi,
      category: "PII",
      strategy: MaskingStrategy.TOKENIZE,
    },
  ],
  // Disable the local NER model if only structured-pattern detection is needed.
  enableNer: true,
  // Vault entry lifetime (default: 1 hour).
  vaultTtlMs: 60 * 60 * 1000,
  // 32-byte key for encrypting vault entries at rest (hex, base64, or Buffer).
  // If omitted, a random key is generated per process.
  encryptionKey: process.env.PRIVACYGUARD_VAULT_KEY,
});
```

For multi-instance/enterprise deployments, implement `VaultStore` (e.g.
backed by Redis) and `AuditSink` (e.g. forwarding to a SIEM) and pass them via
`vaultStore` / `auditSink`.

## Entity coverage

| Category | Examples |
| --- | --- |
| PII - direct identifiers | full name (NER), SSN, passport number, driver's license number, credit card number (Luhn-validated), bank account number, IBAN |
| PII - indirect/electronic identifiers | email, phone number, fax number, mailing address, IP address (v4/v6), MAC address, GPS coordinates, vehicle identification number (VIN), URL, username/handle, date of birth, organization, location |
| PHI (HIPAA identifiers) | medical record number, health plan/insurance ID, ICD-10 diagnosis code, NPI number, DEA number - plus the PII fields above (names, dates, contacts, addresses, IDs, device/IP identifiers) which are also part of the HIPAA 18 |
| Secrets | AWS/GCP/Azure keys, GitHub/Slack tokens, OpenAI/Anthropic API keys, JWTs, private keys, DB connection strings, generic passwords/tokens |

Detection combines regex/pattern rules (`packages/core/src/detectors/regex/patterns.ts`)
with a local NER model for free-form names, organizations, and locations.
Several of the regex patterns above (driver's license, bank account, DOB,
username, fax number) rely on a nearby label (e.g. `"DOB:"`, `"Account No:"`)
to avoid false positives on bare numbers.

### Limitations / not covered

The following HIPAA/PII categories are not detected because they are not
expressible as text patterns, or are too generic/jurisdiction-specific to
match reliably without a high false-positive rate:

- **Biometric data and photographs** - fingerprints, retina/iris scans,
  facial geometry, DNA, and "full-face photographic images" are non-text
  data and require image/binary-level scanning, not a text sanitizer.
- **License plate numbers** - formats vary too widely across jurisdictions
  to pattern-match without excessive false positives; VINs (a standardized
  17-character format) are covered instead.
- **Generic "account numbers", "certificate/license numbers", and "device
  serial numbers"** - these are only reliably distinguishable from arbitrary
  numbers when labeled (see DRIVERS_LICENSE/BANK_ACCOUNT above) or are
  organization-specific. Use `customRules` to add patterns for your own
  identifier formats.
- **Security question answers** - free-form text with no detectable shape.

For anything in this list that matters for your deployment, add a
`customRules` entry (see Configuration above) with a pattern tailored to
your organization's identifier formats.

## Development

```bash
npm run build              # build all packages
cd packages/core && npx tsx --test src/**/*.test.ts   # run core tests
npx tsx examples/basic-sanitize.ts                     # run an example
```
