import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer } from "../../index.js";

const HL7_FHIR =
  "PID|1||00984512-A^^^MRN^MR~000-12-3456^^^SSA^SS||PENDELTON^ARTHUR^J||19480412|M|||742 EVERGREEN TER^APT 4B^SPRINGFIELD^IL^62704||(217)555-0148|||M||ENC-2026-884120|000-12-3456\n" +
  "NK1|1|PENDELTON^MARCUS|SON|742 EVERGREEN TER^^SPRINGFIELD^IL^62704|(312)555-0177\n" +
  "IN1|1|BCBS_PPO|GRP-4402|BLUECROSS||||||20260101|||||PENDELTON^ARTHUR|SEL|||||||||||||||||||||XYZ987654321\n" +
  '{"resourceType":"Patient","id":"pat-apendelton-48","identifier":[{"system":"urn:oid:2.16.840.1.113883.4.3.17","value":"P530-0194-8210"}],' +
  '"name":[{"family":"Pendelton","given":["Arthur","James"]}],"birthDate":"1948-04-12",' +
  '"address":[{"city":"Springfield","state":"IL","postalCode":"62704"}]}';

test("structured HL7/FHIR message: no PII leaks in the clear", async () => {
  const { sanitizedText } = await new Sanitizer({ enableNer: false }).sanitize(HL7_FHIR);
  for (const leak of [
    "PENDELTON", "Pendelton", "Arthur", "Marcus", "James", // names (HL7 + FHIR)
    "SPRINGFIELD", "Springfield",                           // city
    "00984512", "pat-apendelton",                           // MRN, resource id
    "62704", "19480412", "20260101",                        // zip + compact dates
    "XYZ987654321", "P530-0194-8210",                       // policy, DL
  ]) {
    assert.ok(!sanitizedText.includes(leak), `"${leak}" leaked`);
  }
});

test("structured message: non-PII tokens are preserved", async () => {
  const { sanitizedText } = await new Sanitizer({ enableNer: false }).sanitize(HL7_FHIR);
  // OID and HL7 state code are not PII and must survive intact.
  assert.ok(sanitizedText.includes("2.16.840.1.113883.4.3.17"), "OID should be preserved");
  // Pipe/caret structure around masked values stays intact (valid-ish message).
  assert.ok(sanitizedText.includes("^^^MRN^MR"), "HL7 field structure should be preserved");
});
