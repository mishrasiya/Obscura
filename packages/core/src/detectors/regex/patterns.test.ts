import { test } from "node:test";
import assert from "node:assert/strict";
import { detectWithRegex } from "./regexDetector.js";
import { EntityType } from "../../types.js";

/**
 * Regression matrix for the HIPAA Safe Harbor audit. Each case is a real
 * value from the audited medical-record prompt that previously leaked or was
 * misclassified. A case passes if the expected value is detected under the
 * expected entity type (and, where noted, is NOT mis-detected as something
 * else).
 */
const CASES: Array<{ name: string; text: string; type: EntityType; value: string }> = [
  // Unlabeled ZIP in the geographic tail (previously leaked).
  { name: "zip bare", text: "Springfield, 62704", type: EntityType.ZIP_CODE, value: "62704" },
  { name: "zip w/ state", text: "Springfield, IL 62704", type: EntityType.ZIP_CODE, value: "IL 62704" },

  // Labeled service dates + unlabeled generic dates (previously leaked/mangled).
  { name: "admit date", text: "Admit Date: 10/14/2026", type: EntityType.DATE_OF_SERVICE, value: "Admit Date: 10/14/2026" },
  { name: "discharge date", text: "Discharge: 10/19/2026", type: EntityType.DATE_OF_SERVICE, value: "Discharge: 10/19/2026" },
  { name: "date long-form", text: "seen October 14, 2026", type: EntityType.DATE, value: "October 14, 2026" },
  { name: "date iso", text: "on 2026-10-19 again", type: EntityType.DATE, value: "2026-10-19" },

  // MRN with facility check-char suffix (previously dropped the "-A").
  { name: "mrn suffix", text: "MRN: 00984512-A", type: EntityType.MEDICAL_RECORD_NUMBER, value: "MRN: 00984512-A" },

  // Health plan beneficiary numbers (previously a total miss).
  { name: "mbi", text: "MBI 1EG4-TE5-MK72", type: EntityType.HEALTH_INSURANCE_ID, value: "MBI 1EG4-TE5-MK72" },
  { name: "policy bare", text: "Policy XYZ987654321", type: EntityType.HEALTH_INSURANCE_ID, value: "Policy XYZ987654321" },
  { name: "group", text: "Group GRP-4402", type: EntityType.HEALTH_INSURANCE_ID, value: "Group GRP-4402" },

  // Account / encounter numbers (previously a total miss).
  { name: "encounter labeled", text: "Encounter: ENC-2026-884120", type: EntityType.ENCOUNTER_NUMBER, value: "Encounter: ENC-2026-884120" },
  { name: "encounter bare", text: "ref ENC-2026-884120 today", type: EntityType.ENCOUNTER_NUMBER, value: "ENC-2026-884120" },

  // Device identifiers & serials (previously leaked; UDI was split into a phone).
  { name: "device serial", text: "Serial SN-9948271-MX", type: EntityType.MEDICAL_DEVICE_SERIAL, value: "Serial SN-9948271-MX" },
  {
    name: "udi whole",
    text: "UDI (01)00884450123456(17)281019(21)9948271",
    type: EntityType.MEDICAL_DEVICE_SERIAL,
    value: "UDI (01)00884450123456(17)281019(21)9948271",
  },

  // Other unique identifying codes (previously left visible).
  { name: "room", text: "Room 412B", type: EntityType.ROOM_NUMBER, value: "Room 412B" },
  { name: "facility", text: "at St. Jude Regional Medical Center", type: EntityType.ORGANIZATION, value: "St. Jude Regional Medical Center" },
];

for (const c of CASES) {
  test(`detects ${c.name}`, () => {
    const found = detectWithRegex(c.text);
    assert.ok(
      found.some((e) => e.type === c.type && e.value === c.value),
      `expected ${c.type}="${c.value}" in [${found.map((e) => `${e.type}:${e.value}`).join(", ")}]`
    );
  });
}

test("UDI GTIN is NOT misclassified as a phone number", () => {
  const found = detectWithRegex("UDI (01)00884450123456(17)281019(21)9948271");
  assert.ok(!found.some((e) => e.type === EntityType.PHONE_NUMBER), "UDI must not yield a PHONE_NUMBER");
});

test("4-digit year after a comma is not mistaken for a ZIP", () => {
  const found = detectWithRegex("the fiscal plan, 2026 edition");
  assert.ok(!found.some((e) => e.type === EntityType.ZIP_CODE), "4-digit year must not match ZIP");
});
