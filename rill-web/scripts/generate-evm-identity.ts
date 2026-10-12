/** Keep standalone web builds independent of the contracts directory. Unit tests guard this generated identity. */
import { readFileSync, writeFileSync } from "node:fs";
const artifact = JSON.parse(readFileSync(new URL("../../rill-contracts/artifacts/erc20-swap-v6.json", import.meta.url), "utf8"));
const identity = { runtimeHexLength: artifact.runtimeBytecode.length, immutableRanges: artifact.immutableRanges, maskedRuntimeSha256: artifact.maskedRuntimeSha256 };
writeFileSync(new URL("../src/generated/erc20SwapIdentity.json", import.meta.url), JSON.stringify(identity, null, 2) + "\n");
