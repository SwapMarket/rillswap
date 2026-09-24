/** Compile pinned JSON Schema at build time, never eval in the browser. */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import Ajv2020 from "ajv/dist/2020.js";
import standaloneCode from "ajv/dist/standalone/index.js";

import advertisementSchema from "../src/schemas/advertisements/advertisement-v1.schema.json";
import commonSchema from "../src/schemas/wire/common-v1.schema.json";

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
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== output) {
    throw new Error("Generated advertisement validators are stale");
  }
} else {
  writeFileSync(path, output);
}
