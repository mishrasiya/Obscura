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

// ---------------------------------------------------------------------------
// PII patterns
// ---------------------------------------------------------------------------
const PII_RULES: RegexRule[] = [
  {
    type: EntityType.EMAIL,
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  {
    // US-style SSN: 123-45-6789. Accepts dashes, spaces, or no separator at all:
    // 123-45-6789, 123 45 6789, 123456789. Deliberately matches the 3-2-4 digit
    // shape regardless of SSA area-number validity rules (e.g. 900-999) - for a
    // privacy filter, anything that *looks* like an SSN should be masked, since
    // under-masking a real SSN is far worse than over-masking a look-alike number.
    type: EntityType.SSN,
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  {
    type: EntityType.CREDIT_CARD,
    // 13-19 digits, optionally grouped with spaces or dashes
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: luhnCheck,
  },
  {
    type: EntityType.IP_ADDRESS,
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
  },
  {
    type: EntityType.IBAN,
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
  },
  {
    // Generic phone numbers: optional country code, separators, 7-15 digits total
    type: EntityType.PHONE_NUMBER,
    pattern: /(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  {
    // Labeled passport number: "Passport: X12345678", "Passport No: A1234567"
    type: EntityType.PASSPORT_NUMBER,
    pattern: /\bPassport(?:\s?(?:No\.?|Number|#))?[:\s#-]+\s?[A-Z][A-Z0-9]{5,8}\b/gi,
  },
  {
    // Labeled driver's license: "Driver's License: D1234567", "Driver's license (IL): D8675309", "DL# A123-456-789-012"
    type: EntityType.DRIVERS_LICENSE,
    pattern: /\b(?:Driver'?s?\s?License|Driving\s?Licen[cs]e|DL)\s?(?:\([^)]*\))?[:\s#-]+\s?[A-Z0-9-]{5,16}\b/gi,
  },
  {
    // Labeled bank account / routing number: "Account No: 123456789012", "Acct # 12345678",
    // "Bank account: 123456789", "routing 110000000"
    type: EntityType.BANK_ACCOUNT,
    pattern: /\b(?:(?:Bank\s?)?Account\s?(?:No\.?|Number|#)?|Acct\.?\s?(?:No\.?|#)?|Routing\s?(?:No\.?|Number|#)?)[:\s#-]+\s?\d{6,17}\b/gi,
  },
  {
    // Labeled date of birth: "DOB: 01/02/1990", "Date of Birth: 1990-01-02"
    type: EntityType.DATE_OF_BIRTH,
    pattern: /\b(?:DOB|Date\s?of\s?Birth|Birth\s?date)[:\s]+\s?(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Za-z]+\s\d{1,2},?\s\d{4})\b/gi,
  },
  {
    // Labeled username/handle: "username: jdoe123", "user: jane_doe", "@jane_doe"
    type: EntityType.USERNAME,
    pattern: /\b(?:Username|User\s?ID|Login|Handle)[:\s]+\s?[A-Za-z0-9_.@-]{3,32}\b|@[A-Za-z0-9_]{3,24}\b/gi,
  },
  {
    // Basic US street address: "123 Main St", "4500 Oak Avenue, Apt 2"
    type: EntityType.ADDRESS,
    pattern: /\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|Court|Ct|Place|Pl|Square|Sq|Way|Terrace|Ter|Circle|Cir)\.?(?:,?\s+(?:Apt|Suite|Ste|Unit|#)\.?\s?[A-Za-z0-9-]+)?\b/gi,
  },
  {
    // MAC address: "00:1A:2B:3C:4D:5E" or "00-1A-2B-3C-4D-5E"
    type: EntityType.MAC_ADDRESS,
    pattern: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    // Vehicle Identification Number: 17 chars, no I/O/Q, must mix letters and digits
    type: EntityType.VIN,
    pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g,
    validate: vinCheck,
  },
  {
    // URLs (http/https); trailing sentence punctuation is excluded from the match
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
    pattern: /\bFax(?:\s?(?:No\.?|Number))?[:\s]+(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/gi,
  },
  {
    // Labeled credit card expiration date: "Exp: 09/27", "Expiration Date: 09/2027", "Valid Thru 09/27"
    type: EntityType.CREDIT_CARD_EXPIRATION,
    pattern: /\b(?:Exp(?:iry|iration)?(?:\s?Date)?|Valid\s?Thru|Expires?)[:\s]+\s?(?:0[1-9]|1[0-2])[\/.-]\d{2,4}\b/gi,
  },
  {
    // Labeled ZIP code: "ZIP: 60614", "Zip Code: 60614-1234"
    type: EntityType.ZIP_CODE,
    pattern: /\bZIP(?:\s?Code)?[:\s]+\s?\d{5}(?:-\d{4})?\b/gi,
  },
  {
    // Labeled vehicle license plate: "Plate: 7XYZ123", "License Plate Number: ABC-1234"
    // The lookahead requires a digit in the value so ordinary phrases like
    // "license plate is" aren't mistaken for a plate value.
    type: EntityType.LICENSE_PLATE,
    pattern: /\b(?:License\s?)?Plate\s?(?:No\.?|Number|#)?[:\s#-]+\s?(?=[A-Z0-9-]*\d)[A-Z0-9-]{2,8}\b/gi,
  },
];

// ---------------------------------------------------------------------------
// PHI patterns (US-centric, common EHR/insurance formats)
// ---------------------------------------------------------------------------
const PHI_RULES: RegexRule[] = [
  {
    // ICD-10-CM: letter + 2 digits, optional decimal + up to 4 alphanumeric
    type: EntityType.ICD_CODE,
    pattern: /\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/g,
  },
  {
    // National Provider Identifier: 10 digits
    type: EntityType.NPI_NUMBER,
    pattern: /\b(?:NPI[:\s]?)(\d{10})\b/gi,
  },
  {
    // DEA registration number: 2 letters + 7 digits
    type: EntityType.DEA_NUMBER,
    pattern: /\b[A-Z]{2}\d{7}\b/g,
  },
  {
    // Medical record number, generic labeled form: MRN: 1234567 / MRN-1234567
    type: EntityType.MEDICAL_RECORD_NUMBER,
    pattern: /\bMRN[:\s#-]?\s?\d{5,10}\b/gi,
  },
  {
    // Health insurance member ID / plan, generic labeled form. Captures an
    // optional plan code (e.g. "BCBS-IL") before the member ID:
    // "Member ID: ABC123456", "Health plan / insurance: BCBS-IL XQ4820193"
    // The lookahead requires a digit in the value so the label word itself
    // (e.g. "insurance") is never mistaken for the value.
    type: EntityType.HEALTH_INSURANCE_ID,
    pattern: /\b(?:Member\s?ID|Policy\s?(?:No\.?|Number)|Health\s?Plan(?:\s*\/\s*Insurance)?|Insurance(?:\s?ID|\s?Plan)?)\b[:\s#\/-]*(?:[A-Za-z]{2,6}-[A-Za-z]{2,6}\s+)?(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{6,15}\b/gi,
  },
  {
    // Labeled billing account number: "Billing account number: ACCT-7741920", "Billing ID: 12345"
    type: EntityType.BILLING_ACCOUNT_NUMBER,
    pattern: /\bBilling\s?(?:Account|ID)(?:\s?(?:No\.?|Number|#))?[:\s#-]+\s?[A-Z0-9-]{4,15}\b/gi,
  },
  {
    // Labeled patient identifier: "Patient ID: PT-2024-88213", "Patient No: 12345"
    type: EntityType.PATIENT_ID,
    pattern: /\bPatient\s?(?:ID|No\.?|Number|#)[:\s#-]+\s?[A-Z0-9-]{4,15}\b/gi,
  },
  {
    // Labeled service-related dates (HIPAA "dates related to an individual"):
    // "Admission: 05/02/2024", "Discharge: 05/06/2024", "Date of service: 1990-01-02"
    type: EntityType.DATE_OF_SERVICE,
    pattern: /\b(?:Admission|Discharge|Admitted|Discharged|Date\s?of\s?Service|Service\s?Date)[:\s]+\s?(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Za-z]+\s\d{1,2},?\s\d{4})\b/gi,
  },
  {
    // Labeled healthcare provider license number: "Provider License #: MD-554321",
    // "Medical License No: 12345", "Physician License Number: A98765"
    type: EntityType.PROVIDER_LICENSE_NUMBER,
    pattern: /\b(?:Provider|Medical|Physician|Practitioner)\s?License\s?(?:No\.?|Number|#)?[:\s#-]+\s?[A-Z0-9-]{4,15}\b/gi,
  },
];

// ---------------------------------------------------------------------------
// Secrets / credentials patterns
// ---------------------------------------------------------------------------
const SECRET_RULES: RegexRule[] = [
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
    type: EntityType.GITHUB_TOKEN,
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    type: EntityType.SLACK_TOKEN,
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
  },
  {
    type: EntityType.OPENAI_API_KEY,
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: EntityType.ANTHROPIC_API_KEY,
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: EntityType.JWT,
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    type: EntityType.PRIVATE_KEY,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    type: EntityType.DB_CONNECTION_STRING,
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s'"]+/gi,
  },
  {
    type: EntityType.PASSWORD_ASSIGNMENT,
    pattern: /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"]?[^\s'",;]{4,}['"]?/gi,
  },
  {
    // Catch-all for generic high-entropy bearer/API tokens with explicit labels
    type: EntityType.GENERIC_API_KEY,
    pattern: /\b(?:Bearer)\s+[A-Za-z0-9._-]{20,}\b/g,
  },
];

export const ALL_REGEX_RULES: RegexRule[] = [...PII_RULES, ...PHI_RULES, ...SECRET_RULES];
