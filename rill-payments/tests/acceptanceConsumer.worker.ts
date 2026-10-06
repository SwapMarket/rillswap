import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import type { SignedAcceptance } from "../src/server";

let consumer: LightningAcceptanceConsumer, envelope: SignedAcceptance;
self.onmessage = (message) => {
  try {
    if (message.data.kind === "initialize") {
      consumer = LightningAcceptanceConsumer.open(message.data.path, message.data.identity);
      envelope = message.data.envelope;
      self.postMessage({ kind: "ready" });
    } else {
      try { self.postMessage({ kind: "result", status: consumer.consume(envelope, 1200) }); }
      finally { consumer.close(); }
    }
  } catch { self.postMessage({ kind: "refused" }); }
};
