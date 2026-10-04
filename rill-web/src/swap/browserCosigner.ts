/** Browser capabilities for the cooperative claim: vendored WASM MuSig2 plus the refusal journal. */
import type { Cosigner } from "./cooperative";
import { reserveCooperation } from "./cooperationJournal";
import { loadMusig } from "./rillCrypto";

export const browserCosigner: Cosigner = { loadMusig, reserve: reserveCooperation };
