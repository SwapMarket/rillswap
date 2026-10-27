import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import schema from "../../rill-docs/schemas/wire/cooperative-claim-v1.schema.json";
import common from "../../rill-docs/schemas/wire/common-v1.schema.json";
import cycle from "../../rill-docs/vectors/wire/cooperative-claim-v1.json";

const ajv = new Ajv2020({ strict: true }); ajv.addSchema(common); ajv.addSchema(schema);
const request = ajv.getSchema(`${schema.$id}#/$defs/actionRequest`)!, result = ajv.getSchema(`${schema.$id}#/$defs/actionResult`)!;
for (const [name, message] of Object.entries(cycle.messages)) {
  test(`shared cooperative payload schema: ${name}`, () => {
    expect((message.message_type === "action_request" ? request : result)(message.payload)).toBe(true);
  });
}
for (const item of cycle.invalid) {
  test(`shared cooperative payload schema: ${item.name}`, () => {
    const message = structuredClone(cycle.messages[item.message as keyof typeof cycle.messages]);
    const path = item.field.split(".");
    const target = (path.length === 2 ? message.payload : message) as unknown as Record<string, unknown>;
    target[path.at(-1)!] = item.replacement;
    expect((message.message_type === "action_request" ? request : result)(message.payload)).toBe(item.shape_valid);
  });
}
