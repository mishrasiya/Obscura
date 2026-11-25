import { EntityType } from "../../types.js";

/**
 * A regex-based detection rule. `pattern` must be a global regex.
 * `validate` allows an optional secondary check (e.g. Luhn checksum)
 * to reduce false positives beyond what regex alone can express.
 */
export interface RegexRule {
  type: EntityType;
  pattern: RegExp;
  validate?: (match: string) => boolean;
}

/** Confirms a 17-character VIN candidate contains both letters and digits (rules out e.g. all-numeric IDs). */
function vinCheck(value: string): boolean {
  return /[A-Z]/.test(value) && /\d/.test(value);
}

/** Luhn checksum used to confirm a string of digits looks like a real card number. */
function luhnCheck(digits: string): boolean {
  const clean = digits.replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(clean)) return false;
  let sum = 0;
  let alt = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let n = parseInt(clean[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Reusable separator that accepts ":", "=", spaces, "#", "-", or the word "is"
// so patterns work for both formal ("Label: value") and conversational ("label is value") input.
const SEP = String.raw`\s*(?:is\s+|[:\s#=\-]+)\s*`;

// ---------------------------------------------------------------------------
// Secrets / credentials patterns  (evaluated first — most specific)
// ---------------------------------------------------------------------------
const SECRET_RULES: RegexRule[] = [
  {
    type: EntityType.PRIVATE_KEY,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    // Wallet seed phrase (labeled: "Seed Phrase: word1 word2 ... word12/24") or hex private key
    type: EntityType.CRYPTO_PRIVATE_KEY,
    pattern: /\b(?:Seed\s?Phrase|Mnemonic(?:\s?Phrase)?|Recovery\s?(?:Phrase|Words?)|Private\s?Key)\s*(?:is\s+|[:\s]+)\s*(?:0x[a-fA-F0-9]{64}|(?:[a-z]+(?:\s+[a-z]+){11,23}))\b/gi,
  },
  {
    type: EntityType.AWS_ACCESS_KEY,
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g,
  },
  {
    type: EntityType.AWS_SECRET_KEY,
    pattern: /\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
  },
  {
    type: EntityType.GCP_API_KEY,
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    type: EntityType.AZURE_CLIENT_SECRET,
    pattern: /\b(?:azure_client_secret|client_secret)\s*[:=]\s*['"]?([A-Za-z0-9._~\-]{32,44})['"]?/gi,
  },
  {
    // Optional labeled prefix ("github token: ghp_...") so this starts before PASSWORD_ASSIGNMENT.
    // Standalone ghp_/ghs_/etc. tokens are also caught by the bare suffix.
    type: EntityType.GITHUB_TOKEN,
    pattern: /\b(?:(?:github|gh)\s*(?:token|pat|personal\s+access\s+token)\s*[:=\s]+)?gh[pousr]_[A-Za-z0-9]{36,255}\b/gi,
  },
  {
    type: EntityType.SLACK_TOKEN,
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
  },
  {
    // Slack incoming webhook URL — must precede the generic URL rule
    type: EntityType.SLACK_WEBHOOK,
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+\b/g,
  },
  {
    // Stripe publishable, secret, and restricted keys: sk_/pk_/rk_ live or test
    type: EntityType.STRIPE_API_KEY,
    pattern: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
  },
  {
    // PayPal API client secret (labeled)
    type: EntityType.PAYPAL_SECRET,
    pattern: /\b(?:paypal[_-]?(?:client[_-]?)?secret|PAYPAL[_-]?(?:CLIENT[_-]?)?SECRET)\s*[:=]\s*['"]?[A-Za-z0-9_.\-]{16,64}['"]?/gi,
  },
  {
    // Anthropic keys must come before OpenAI to avoid sk-ant-... being labeled as OpenAI
    type: EntityType.ANTHROPIC_API_KEY,
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: EntityType.OPENAI_API_KEY,
    pattern: /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: EntityType.JWT,
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    // Database connection strings with embedded credentials
    type: EntityType.DB_CONNECTION_STRING,
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s'"]+/gi,
  },
  {
    // Negative lookahead excludes values that are themselves known-prefix secrets
    // (those are caught by more specific rules above).
    type: EntityType.PASSWORD_ASSIGNMENT,
    pattern: /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"]?(?!gh[pousr]_|sk-|sk_(?:live|test)_|xox[baprs]-|AIza|AKIA|eyJ)[^\s'",;]{4,}['"]?/gi,
  },
  {
    // CUI and CONTROLLED UNCLASSIFIED INFORMATION markings (defense/government)
    type: EntityType.CUI_MARKING,
    pattern: /\bCUI(?:\/\/[A-Z][A-Z0-9-]*(?:\/[A-Z][A-Z0-9-]*)*)?\b|\bCONTROLLED\s+UNCLASSIFIED\s+INFORMATION\b/g,
  },
  {
    // Catch-all for generic high-entropy bearer/API tokens with explicit label
    type: EntityType.GENERIC_API_KEY,
    pattern: /\b(?:Bearer)\s+[A-Za-z0-9._-]{20,}\b/g,
  },
];

// ---------------------------------------------------------------------------
// PII patterns
// ---------------------------------------------------------------------------
const PII_RULES: RegexRule[] = [
  {
    type: EntityType.EMAIL,
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  {
    // Obfuscated email: "@" written as [at]/(at) and "." as [dot]/(dot),
    // e.g. "eleanor [dot] vance93 [at] example [dot] com". Only bracketed/
    // parenthesised/symbol separators (not the bare words "at"/"dot") so
    // ordinary prose like "meet at the dot" isn't matched.
    type: EntityType.EMAIL,
    pattern:
      /[A-Za-z0-9._%+-]+(?:(?:\s*\[dot\]\s*|\s*\(dot\)\s*|\.)[A-Za-z0-9._%+-]+)*(?:\s*\[at\]\s*|\s*\(at\)\s*|@)[A-Za-z0-9-]+(?:(?:\s*\[dot\]\s*|\s*\(dot\)\s*|\.)[A-Za-z0-9-]+)+/gi,
  },
  {
    // HL7 v2 XPN person name: "LAST^FIRST^MIDDLE" of alphabetic components,
    // e.g. "PENDELTON^ARTHUR^J". The leading "|" lookbehind anchors it to the
    // start of an HL7 field (where name fields live), so mid-field address
    // components like "TER^APT" or "SPRINGFIELD^IL" aren't mistaken for names.
    // Numeric codes ("ADT^A01") can't match (components are letters only).
    type: EntityType.PERSON_NAME,
    pattern: /(?<=\|)[A-Za-z][A-Za-z'-]+\^[A-Za-z][A-Za-z'-]+(?:\^[A-Za-z][A-Za-z'-]*)*/g,
  },
  {
    // HL7 address city component: the alphabetic token sitting immediately
    // before "^<ST>^<ZIP>", e.g. the "SPRINGFIELD" in
    // "...^SPRINGFIELD^IL^62704".
    type: EntityType.LOCATION,
    pattern: /(?<=\^)[A-Za-z][A-Za-z .'-]+(?=\^[A-Z]{2}\^\d{5})/g,
  },
  {
    // FHIR JSON city value: "city": "Springfield".
    type: EntityType.LOCATION,
    pattern: /(?<="city"\s*:\s*")[A-Za-z][A-Za-z .'-]*/g,
  },
  {
    // FHIR JSON name value: "family": "Pendelton". Masks only the quoted value.
    type: EntityType.PERSON_NAME,
    pattern: /(?<="family"\s*:\s*")[A-Za-z][A-Za-z '-]*/g,
  },
  {
    // FHIR JSON given-name array elements: "given": ["Arthur", "James"].
    // The variable-length lookbehind lets each element match in turn.
    type: EntityType.PERSON_NAME,
    pattern: /(?<="given"\s*:\s*\[(?:\s*"[^"]*"\s*,)*\s*")[A-Za-z][A-Za-z '-]*/g,
  },
  {
    // US SSN: 123-45-6789, 123 45 6789, 123456789
    type: EntityType.SSN,
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  {
    // EIN/TIN/ITIN (labeled): "EIN: 12-3456789", "Tax ID: 123456789"
    type: EntityType.TAX_ID,
    pattern: /\b(?:EIN|FEIN|TIN|ITIN|Tax(?:\s?ID(?:entification)?|\s?(?:Identification\s?)?Number)|Employer(?:\s?Identification(?:\s?Number)?)?)\s*(?:is\s+|[:\s#=\-]+)\s?\d{2}-?\d{7}\b/gi,
  },
  {
    // Annual/base salary or wage (labeled or conversational)
    type: EntityType.SALARY,
    pattern: /\b(?:(?:annual|base|gross|net|monthly|weekly|hourly)\s+)?(?:salary|wage|income|earnings|compensation)\s*(?:is\s+|[:=]\s*)?\$?\s?[\d,]+(?:\.\d{2})?(?:\s*(?:\/|per)\s*(?:year|yr|annual|month|mo|hour|hr|wk|week))?\b/gi,
  },
  {
    // W-2 and 1099 tax forms with associated dollar amounts
    type: EntityType.TAX_FORM,
    pattern: /\b(?:W-?2|1099(?:-[A-Z]{1,4})?)\b(?:\s+(?:wages?|income|earnings?|form))?\s*(?:is|shows?|totals?|reports?|[:=]\s*)?\s*\$?\s?[\d,]+(?:\.\d{2})?\b/gi,
  },
  {
    type: EntityType.CREDIT_CARD,
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: luhnCheck,
  },
  {
    // CVV / CVC card security code — accepts "CVV: 123", "CVV 456", or "CVV is 789"
    type: EntityType.CVV,
    pattern: new RegExp(
      String.raw`\b(?:CVV2?|CVC2?|Card\s?Security\s?(?:Code|Number)|Security\s?Code)` + SEP + String.raw`\d{3,4}\b`,
      "gi"
    ),
  },
  {
    // Labeled credit card expiration date: "Exp: 09/27", "Expiration Date: 09/2027", "Valid Thru 09/27"
    type: EntityType.CREDIT_CARD_EXPIRATION,
    pattern: /\b(?:Exp(?:iry|iration)?(?:\s?Date)?|Valid\s?Thru|Expires?)[:\s]+\s?(?:0[1-9]|1[0-2])[\/.-]\d{2,4}\b/gi,
  },
  {
    // FICO / credit score (labeled, 300–850 range)
    type: EntityType.CREDIT_SCORE,
    pattern: /\b(?:Credit\s?Score|FICO(?:\s?Score)?)\s*(?:is\s+|[:\s#=\-]+)\s?(?:[3-7]\d{2}|8[0-4]\d|850)\b/gi,
  },
  {
    // IPv4 and comprehensive IPv6 (full-form, compressed, loopback, etc.)
    type: EntityType.IP_ADDRESS,
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}/g,
  },
  {
    // IBAN: country code (2 letters) + check digits (2) + BBAN (10-30 alphanumeric)
    type: EntityType.IBAN,
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
  },
  {
    // ABA / ACH routing number (labeled, exactly 9 digits)
    type: EntityType.ROUTING_NUMBER,
    pattern: new RegExp(
      String.raw`\b(?:ABA(?:\s?Routing)?|Routing|RTN)(?:\s?(?:No\.?|Number|#))?` + SEP + String.raw`\d{9}\b`,
      "gi"
    ),
  },
  {
    // Bank account number (labeled, 6–17 digits) — accepts "Account No: 123", "my account is 123"
    type: EntityType.BANK_ACCOUNT,
    pattern: new RegExp(
      String.raw`\b(?:(?:Bank\s?)?Account\s?(?:No\.?|Number|#)?|Acct\.?\s?(?:No\.?|#)?)` + SEP + String.raw`\d{6,17}\b`,
      "gi"
    ),
  },
  {
    // SWIFT / BIC code (labeled): "SWIFT: BOFAUS3N", "BIC: DEUTDEFF"
    type: EntityType.SWIFT_CODE,
    pattern: /\b(?:SWIFT|BIC)(?:\s?(?:Code|Number))?\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/gi,
  },
  {
    // Cryptocurrency wallet addresses: Bitcoin P2PKH (1…), P2SH (3…), Bech32 (bc1…), and Ethereum (0x…)
    type: EntityType.CRYPTO_WALLET,
    pattern: /\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}|0x[a-fA-F0-9]{40})\b/g,
  },
  {
    // Generic phone numbers: optional country code, separators, 7-15 digits total
    type: EntityType.PHONE_NUMBER,
    pattern: /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  {
    // Labeled passport number: "Passport: X12345678", "Passport No: A1234567"
    type: EntityType.PASSPORT_NUMBER,
    pattern: /\bPassport(?:\s?(?:No\.?|Number|#))?\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z][A-Z0-9]{5,8}\b/gi,
  },
  {
    // Labeled driver's license: "Driver's License: D1234567", "DL# A123-456-789-012"
    type: EntityType.DRIVERS_LICENSE,
    pattern: /\b(?:Driver'?s?\s?License|Driving\s?Licen[cs]e|DL)\s?(?:\([^)]*\))?\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z0-9-]{5,16}\b/gi,
  },
  {
    // Unlabeled driver's-license-style identifier: a leading letter followed
    // by dash-grouped digits, e.g. "P530-0194-8210".
    type: EntityType.DRIVERS_LICENSE,
    pattern: /\b[A-Z]\d{3}-\d{4}-\d{4}\b/g,
  },
  {
    // Labeled date of birth: "DOB: 01/02/1990", "Date of Birth: 1990-01-02"
    type: EntityType.DATE_OF_BIRTH,
    pattern: /\b(?:DOB|Date\s?of\s?Birth|Birth\s?date)\s*(?:is\s+|[:\s]+)\s?(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Za-z]+\s\d{1,2},?\s\d{4})\b/gi,
  },
  {
    // Generic calendar date more specific than a year (HIPAA requires masking
    // all such dates). Covers numeric (MM/DD/YYYY, MM-DD-YY), ISO (YYYY-MM-DD),
    // and long-form ("October 14, 2026"). Labeled DOB/service dates above are
    // longer matches and win over this on overlap.
    type: EntityType.DATE,
    pattern:
      /\b(?:(?<![.\d])\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}(?![.\d])|\d{4}-\d{2}-\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})\b/gi,
  },
  {
    // Compact HL7-style date (YYYYMMDD) or timestamp (YYYYMMDDHHMM[SS]),
    // e.g. "19480412", "20260101", "202611241430". Year constrained to
    // 19xx/20xx and valid month/day so ordinary long digit runs don't match.
    type: EntityType.DATE,
    pattern: /\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:(?:[01]\d|2[0-3])[0-5]\d(?:[0-5]\d)?)?\b/g,
  },
  {
    // Labeled username/handle: "username: jdoe123", "@jane_doe"
    type: EntityType.USERNAME,
    pattern: /\b(?:Username|User\s?ID|Login|Handle)[:\s]+\s?[A-Za-z0-9_.@-]{3,32}\b|@[A-Za-z0-9_]{3,24}\b/gi,
  },
  {
    // Basic US street address: "123 Main St", "4500 Oak Avenue, Apt 2"
    type: EntityType.ADDRESS,
    pattern: /\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|Court|Ct|Place|Pl|Square|Sq|Way|Terrace|Ter|Circle|Cir)\.?(?:,?\s+(?:Apt|Suite|Ste|Unit|#)\.?\s?[A-Za-z0-9-]+)?\b/gi,
  },
  {
    // Healthcare facility / institution names ending in a known org keyword,
    // e.g. "St. Jude Regional Medical Center", "Mercy Hospital". Catches
    // facility names the NER model may miss. 1-5 leading capitalized tokens.
    type: EntityType.ORGANIZATION,
    pattern: /\b(?:[A-Z][A-Za-z.'&-]+\s+){1,5}(?:Regional\s+Medical\s+Center|Medical\s+Center|Medical\s+Group|Health\s+System|Health\s+Center|Healthcare|Hospital|Clinic|Infirmary)\b/g,
  },
  {
    // Standalone unit / apartment designator, e.g. "Unit 9C", "Apt 4B",
    // "Ste 200" - catches it when it appears separately from the street line.
    type: EntityType.ADDRESS,
    pattern: /\b(?:Apartment|Apt|Suite|Ste|Unit)\.?\s*#?\s*[A-Za-z0-9-]{1,6}\b/gi,
  },
  {
    // MAC address: "00:1A:2B:3C:4D:5E" or "00-1A-2B-3C-4D-5E"
    type: EntityType.MAC_ADDRESS,
    pattern: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    // Mobile device IMEI (labeled, 15 digits)
    type: EntityType.IMEI,
    pattern: /\bIMEI\s*(?:is\s+|[:\s#=\-]+)\s?\d{15}\b/gi,
  },
  {
    // Vehicle Identification Number: 17 chars, no I/O/Q, must mix letters and digits
    type: EntityType.VIN,
    pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g,
    validate: vinCheck,
  },
  {
    // URLs (http/https); trailing sentence punctuation is excluded
    type: EntityType.URL,
    pattern: /\bhttps?:\/\/[^\s<>"')\]]*[^\s<>"')\].,!?;:]/g,
  },
  {
    // Precise GPS coordinate pair: "37.7749, -122.4194"
    type: EntityType.GEOLOCATION,
    pattern: /-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b/g,
  },
  {
    // Labeled fax number: "Fax: (555) 123-4567"
    type: EntityType.FAX_NUMBER,
    pattern: /\bFax(?:\s?(?:No\.?|Number))?\s*(?:is\s+|[:\s]+)\s*(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/gi,
  },
  {
    // ZIP / postal code. Labeled ("ZIP Code: 90210", "zip is 90210") OR an
    // unlabeled 5-digit (+optional +4) that follows a comma — i.e. the
    // "City, ST 62704" / "Springfield, 62704" geographic tail. The 4-digit
    // year case (", 2026") can't match \d{5}, avoiding that false positive.
    type: EntityType.ZIP_CODE,
    pattern: /\b(?:ZIP(?:\s+Code)?|Postal\s+Code)\s*(?:is\s+|[:\s=]+)\s*\d{5}(?:-\d{4})?\b|(?<=,\s{1,3})(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b|(?<=\^[A-Z]{2}\^)\d{5}(?:-\d{4})?\b|(?<="postalCode"\s*:\s*")\d{5}(?:-\d{4})?/gi,
  },
  {
    // Labeled vehicle license plate: "Plate: 7XYZ123", "License Plate Number: ABC-1234"
    type: EntityType.LICENSE_PLATE,
    pattern: /\b(?:License\s?)?Plate\s?(?:No\.?|Number|#)?\s*(?:is\s+|[:\s#=\-]+)\s?(?=[A-Z0-9-]*\d)[A-Z0-9-]{2,8}\b/gi,
  },
];

// ---------------------------------------------------------------------------
// PHI patterns (US-centric, common EHR/insurance formats)
// ---------------------------------------------------------------------------
const PHI_RULES: RegexRule[] = [
  {
    // ICD-10-CM: letter + 2 digits, optional decimal + up to 4 alphanumeric.
    // Negative lookbehind for "^" skips HL7 component codes (e.g. the "A01"
    // in "ADT^A01"), which share the shape but aren't diagnoses.
    type: EntityType.ICD_CODE,
    pattern: /\b(?<!\^)[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/g,
  },
  {
    // Age of 90+ (HIPAA Safe Harbor). Labeled ("age 93", "aged 93") or
    // descriptive ("93 years old", "93-year-old", "93 y/o"). Range 90-129
    // keeps it from firing on ordinary two-digit quantities.
    type: EntityType.AGE,
    pattern:
      /\b(?:age[d]?\s*(?:is\s+|[:\s=]+)\s*(?:9\d|1[0-2]\d)|(?:9\d|1[0-2]\d)[\s-]*(?:years?[\s-]*old|y\/?o\b|yrs?[\s-]*old))/gi,
  },
  {
    // CPT procedure code (labeled, exactly 5 digits with optional letter suffix)
    // Accepts "CPT Code: 99213", "CPT 99213", "cpt code is 99213", "procedure code 99213"
    type: EntityType.CPT_CODE,
    pattern: new RegExp(
      String.raw`\b(?:CPT(?:\s?Code)?|Procedure\s?Code)` + SEP + String.raw`\d{5}[A-Z]?\b`,
      "gi"
    ),
  },
  {
    // SNOMED CT concept identifier (labeled, 6–18 digit numeric code)
    type: EntityType.SNOMED_CODE,
    pattern: /\bSNOMED(?:-?CT)?\s*(?:is\s+|[:\s#=\-]+)\s?\d{6,18}\b/gi,
  },
  {
    // RxNorm (RXCUI) drug concept identifier (labeled)
    type: EntityType.RXCUI_CODE,
    pattern: /\bRX(?:CUI|NORM)\s*(?:is\s+|[:\s#=\-]+)\s?\d{1,7}\b/gi,
  },
  {
    // National Provider Identifier: labeled 10-digit number
    type: EntityType.NPI_NUMBER,
    pattern: /\bNPI[:\s]+(\d{10})\b/gi,
  },
  {
    // DEA registration number: 2 letters + 7 digits
    type: EntityType.DEA_NUMBER,
    pattern: /\b[A-Z]{2}\d{7}\b/g,
  },
  {
    // Medical record number (labeled): "MRN: 1234567", "MRN 00984512-A".
    // Allows an optional alphanumeric suffix (e.g. "-A") so facility-specific
    // check characters aren't left dangling.
    type: EntityType.MEDICAL_RECORD_NUMBER,
    pattern:
      /\bMRN\s*(?:is\s+|[:\s#=\-]+)\s?\d{5,10}(?:-[A-Za-z0-9]{1,4})?\b|\b[0-9][A-Za-z0-9-]{4,15}(?=\^+(?:MRN|MR)\b)/gi,
  },
  {
    // Medicare Beneficiary Identifier (MBI): 11 chars in the pattern
    // C-A-AN-N-A-AN-N-A-A-N-N (dashes optional), e.g. "1EG4-TE5-MK72".
    // Highly structured, so safe to match unlabeled as well as labeled.
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\b(?:MBI\s*(?:is\s+|[:\s#=\-]+)\s*)?[1-9][A-Za-z][A-Za-z0-9]\d-?[A-Za-z][A-Za-z0-9]\d-?[A-Za-z][A-Za-z]\d{2}\b/gi,
  },
  {
    // MBI dictated with a separator between every character, e.g.
    // "MBI is 2 S A 9 - T E 4 - M K 8 8". Requires the "MBI" label (the
    // per-character spacing is otherwise too loose to match safely).
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\bMBI\s*(?:is\s+|[:\s#=\-]+)\s*[1-9][\s-]*[A-Za-z][\s-]*[A-Za-z0-9][\s-]*\d[\s-]*[A-Za-z][\s-]*[A-Za-z0-9][\s-]*\d[\s-]*[A-Za-z][\s-]*[A-Za-z][\s-]*\d[\s-]*\d\b/gi,
  },
  {
    // Alphanumeric member/policy id: 1-4 leading letters + 8-12 digits
    // (e.g. "W204819204", "XYZ987654321") that the labeled rule misses when it
    // stands alone (end of an HL7 IN1 segment) or trails a slash.
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\b[A-Z]{1,4}\d{8,12}\b/g,
  },
  {
    // Insurance group number in the common "GRP-####" form, matched without
    // needing an adjacent "Group" label (survives table/pipe formatting where
    // the label-to-value link is broken).
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\bGRP-?\d{3,8}\b/gi,
  },
  {
    // Health insurance member ID / policy / group (labeled). "Policy" accepted
    // bare ("Policy XYZ987654321") as well as "Policy No/Number".
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\b(?:Member\s?ID|Policy(?:\s?(?:No\.?|Number|ID|#))?|Group(?:\s?(?:No\.?|Number|ID|#))?|Health\s?Plan(?:\s*\/\s*Insurance)?|Insurance(?:\s?ID|\s?Plan)?)\b[:\s#\/-]*(?:[A-Za-z]{2,6}-[A-Za-z]{2,6}\s+)?(?=[A-Za-z0-9-]*\d)[A-Za-z0-9]{2,6}-?[A-Za-z0-9]{2,12}\b/gi,
  },
  {
    // Encounter / visit / account number: labeled ("Encounter: ENC-2026-884120")
    // or the common ENC-YYYY-NNNNNN token on its own.
    type: EntityType.ENCOUNTER_NUMBER,
    pattern: new RegExp(
      String.raw`\b(?:Encounter|Visit|Case)\s?(?:No\.?|Number|ID|#)?` + SEP + String.raw`[A-Z0-9][A-Z0-9-]{3,20}\b` +
      String.raw`|\bENC-\d{2,4}-\d{3,8}\b`,
      "gi"
    ),
  },
  {
    // Hospital room / bed identifier: "Room 412B", "Room No. 7", "Room #3A"
    type: EntityType.ROOM_NUMBER,
    pattern: /\bRoom\s+(?:No\.?\s*|Number\s*|#\s*)?\d{1,4}[A-Za-z]?\b/gi,
  },
  {
    // Hospital and billing account numbers (labeled)
    type: EntityType.BILLING_ACCOUNT_NUMBER,
    pattern: /\b(?:Billing|Hospital)\s?(?:Account|ID|Case)(?:\s?(?:No\.?|Number|#))?\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z0-9-]{4,15}\b/gi,
  },
  {
    // Labeled patient identifier: "Patient ID: PT-2024-88213", "Patient No: 12345"
    type: EntityType.PATIENT_ID,
    pattern: /\bPatient\s?(?:ID|No\.?|Number|#)\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z0-9-]{4,15}\b/gi,
  },
  {
    // FHIR resource id value, e.g. "id": "pat-apendelton-48" - often embeds a
    // name fragment, so mask the quoted value.
    type: EntityType.PATIENT_ID,
    pattern: /(?<="id"\s*:\s*")[A-Za-z0-9._-]+/g,
  },
  {
    // Labeled service-related dates (HIPAA "dates related to an individual")
    type: EntityType.DATE_OF_SERVICE,
    pattern: /\b(?:Admission|Admit(?:ted)?|Discharge(?:d)?|Date\s?of\s?Service|DOS|Service\s?Date|Surgery\s?Date|Treatment\s?Date)(?:\s?Date)?\s*(?:is\s+|[:\s]+)\s?(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Za-z]+\s\d{1,2},?\s\d{4})\b/gi,
  },
  {
    // Labeled healthcare provider license number
    type: EntityType.PROVIDER_LICENSE_NUMBER,
    pattern: /\b(?:Provider|Medical|Physician|Practitioner)\s?License\s?(?:No\.?|Number|#)?\s*(?:is\s+|[:\s#=\-]+)\s?[A-Z0-9-]{4,15}\b/gi,
  },
  {
    // UDI in GS1 Application-Identifier form, e.g.
    // "(01)00884450123456(17)281019(21)9948271". Matched as a whole so the
    // embedded GTIN digits aren't mis-detected as a phone number. Listed
    // before the generic serial rule; its earlier start / longer span also
    // win overlap resolution against the PII phone rule.
    type: EntityType.MEDICAL_DEVICE_SERIAL,
    pattern: /(?:UDI[:\s]*)?(?:\((?:01|10|11|17|21)\)[A-Za-z0-9]+){2,}/g,
  },
  {
    // Medical device / implant serial number (labeled) — accepts ": ", "is",
    // "number is". "Serial"/"SN" labels included (e.g. "Serial SN-9948271-MX").
    type: EntityType.MEDICAL_DEVICE_SERIAL,
    pattern: new RegExp(
      String.raw`\b(?:Device\s?Serial(?:\s?(?:No\.?|Number|#))?|Serial(?:\s?(?:No\.?|Number|#))?|S\/?N|Implant\s?(?:ID|Serial)|Pacemaker\s?(?:ID|Serial|No\.?|Serial\s+Number)?|UDI)` +
      SEP +
      String.raw`[A-Z0-9-]{4,20}\b`,
      "gi"
    ),
  },
  {
    // Clinical narrative sections detected by their SOAP/EHR header keywords.
    // Captures the header + up to 300 chars of content on the same line.
    type: EntityType.CLINICAL_NOTE,
    pattern: /\b(?:Chief\s+Complaint|CC|HPI|History\s+of\s+Present\s+Illness|SOAP(?:\s+Note)?|PMH|Past\s+Medical\s+(?:Hx|History)|Assessment(?:\s+and\s+Plan)?|Physical\s+Exam(?:ination)?|Review\s+of\s+Systems|ROS|HEENT|Vitals?|Social\s+(?:Hx|History)|Family\s+(?:Hx|History)|Clinical\s+(?:Notes?|Findings?)|Progress\s+Note|Impression)[:\s][\s\S]{5,300}/gi,
  },
];

// SECRET_RULES listed first so they take priority over PII/PHI on overlapping spans
// (e.g. a DB connection string should be SECRET, not just URL; a Slack webhook is SECRET, not just URL).
export const ALL_REGEX_RULES: RegexRule[] = [...SECRET_RULES, ...PII_RULES, ...PHI_RULES];
