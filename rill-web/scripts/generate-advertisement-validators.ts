/** Compile pinned JSON Schema at build time, never eval in the browser. */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import Ajv2020 from "ajv/dist/2020.js";
import standaloneCode from "ajv/dist/standalone/index.js";

import advertisementSchema from "../src/schemas/advertisements/advertisement-v1.schema.json";
import commonSchema from "../src/schemas/wire/common-v1.schema.json";
import contractTermsSchema from "../src/schemas/wire/contract-terms-v1.schema.json";
import envelopeSchema from "../src/schemas/wire/envelope-v1.schema.json";
import fundingBindingSchema from "../src/schemas/wire/funding-binding-v1.schema.json";
import handshakeSchema from "../src/schemas/wire/handshake-v1.schema.json";
import quoteSchema from "../src/schemas/wire/quote-v1.schema.json";
import settlementSchema from "../src/schemas/wire/settlement-v1.schema.json";
import recoverySchema from "../../rill-docs/schemas/recovery/recovery-v1.schema.json";

const ajv = new Ajv2020({ strict: true, code: { source: true, esm: true } });
ajv.addSchema(commonSchema);
ajv.addSchema(advertisementSchema);
const networkId = "https://spec.rillswap.invalid/schemas/wire/network-for-manual-import.json";
ajv.addSchema({
  $id: networkId,
  $ref: "https://spec.rillswap.invalid/schemas/wire/common-v1.schema.json#/$defs/networkIdentity",
});
const advertisement = ajv.getSchema(advertisementSchema.$id);
const network = ajv.getSchema(networkId);
if (!advertisement || !network) throw new Error("Required vendored schema failed to compile");
const output = "// Generated from vendored RS-005 schemas. Run `bun run check:schemas`.\n" +
  standaloneCode(ajv, {
    validateAdvertisement: advertisementSchema.$id,
    validateNetwork: networkId,
  });
const path = resolve(import.meta.dir, "../src/generated/manualAdvertisementValidators.js");

// RS-001/RS-003 wire messages for the browser swap client.
const wire = new Ajv2020({ strict: true, code: { source: true, esm: true } });
for (const schema of [
  commonSchema,
  contractTermsSchema,
  envelopeSchema,
  fundingBindingSchema,
  handshakeSchema,
  quoteSchema,
  settlementSchema,
]) {
  wire.addSchema(schema);
}
const def = (schema: { $id: string }, name: string): string => `${schema.$id}#/$defs/${name}`;
const wireExports = {
  validateEnvelope: envelopeSchema.$id,
  validateHandshakeAcceptPayload: def(handshakeSchema, "acceptPayload"),
  validateFirmQuoteRequest: def(quoteSchema, "firmRequest"),
  validateTermsOffer: def(quoteSchema, "termsOffer"),
  validateReverseIndicativeQuoteRequest: def(quoteSchema, "reverseIndicativeRequest"),
  validateReverseQuoteOffer: def(quoteSchema, "reverseQuoteOffer"),
  validateReverseFirmQuoteRequest: def(quoteSchema, "reverseFirmRequest"),
  validateReverseTermsOffer: def(quoteSchema, "reverseTermsOffer"),
  validateQuoteError: def(quoteSchema, "error"),
  validateContractTerms: contractTermsSchema.$id,
  validateFundingBinding: fundingBindingSchema.$id,
  validateTermsAccept: def(settlementSchema, "termsAccept"),
  validateFundingBindingMessage: def(settlementSchema, "fundingBindingMessage"),
  validateAck: def(settlementSchema, "ack"),
  validateObservation: def(settlementSchema, "observation"),
};
for (const ref of Object.values(wireExports)) {
  if (!wire.getSchema(ref)) throw new Error(`Required wire schema ${ref} failed to compile`);
}
const wireOutput = "// Generated from vendored RS-001/RS-003 schemas. Run `bun run check:schemas`.\n" +
  standaloneCode(wire, wireExports);
const wirePath = resolve(import.meta.dir, "../src/generated/wireValidators.js");

// The authoritative RS-007 schema has properties within allOf branches without
// repeating a local object type. Isolate that strictTypes exception here; all
// schema rules still apply, and the event/wire validator policies are unchanged.
const recovery = new Ajv2020({ strict: true, strictTypes: false, code: { source: true, esm: true } });
for (const schema of [commonSchema, contractTermsSchema, fundingBindingSchema, handshakeSchema, envelopeSchema, recoverySchema]) {
  recovery.addSchema(schema);
}
if (!recovery.getSchema(recoverySchema.$id)) throw new Error("Required recovery schema failed to compile");
const recoveryOutput = "// Generated from authoritative RS-007 schema. Run `bun run check:schemas`.\n" +
  standaloneCode(recovery, { validateRecoveryPlaintext: recoverySchema.$id });
const recoveryPath = resolve(import.meta.dir, "../src/generated/recoveryValidators.js");
const recoveryTypesPath = resolve(import.meta.dir, "../src/generated/recoveryValidators.d.ts");
const recoveryTypes = "/** Generated RS-007 shape validation, never cryptographic authorization. */\n" +
  "export function validateRecoveryPlaintext(value: unknown): boolean;\n";

for (const [target, text] of [[path, output], [wirePath, wireOutput], [recoveryPath, recoveryOutput], [recoveryTypesPath, recoveryTypes]] as const) {
  if (process.argv.includes("--check")) {
    if (readFileSync(target, "utf8") !== text) throw new Error(`Generated validators are stale: ${target}`);
  } else {
    writeFileSync(target, text);
  }
}
