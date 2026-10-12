// Compiles the vendored Boltz ERC20Swap v6 into artifacts/erc20-swap-v6.json
// with a pinned compiler profile. `--check` fails if the artifact is stale.
// Providers and clients verify deployed runtime bytecode against this file.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import solc from "solc";

const COMPILER = "0.8.33+commit.64118f21.Emscripten.clang";
const EVM_VERSION = "cancun"; // Runs on every chain that also runs Prague; no Prague-only opcodes are needed.
const OPTIMIZER = { enabled: true, runs: 10_000_000 }; // Upstream foundry.toml release profile.
const SOURCES = ["ERC20Swap.sol", "TransferHelper.sol"] as const;

const sources = Object.fromEntries(SOURCES.map((name) => [name, { content: readFileSync(new URL(`./vendor/boltz-core/contracts/${name}`, import.meta.url), "utf8") }]));
if (solc.version() !== COMPILER) throw new Error(`Compiler version mismatch: ${solc.version()}`);
const output = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
  settings: { evmVersion: EVM_VERSION, optimizer: OPTIMIZER, metadata: { bytecodeHash: "none", appendCBOR: false },
    outputSelection: { "ERC20Swap.sol": { ERC20Swap: ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences"] } } },
}))) as { errors?: { severity: string; formattedMessage: string }[]; contracts: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string }; deployedBytecode: { object: string; immutableReferences?: Record<string, { start: number; length: number }[]> } } }>> };
const errors = output.errors?.filter((error) => error.severity === "error") ?? [];
if (errors.length) throw new Error("Compilation failed:\n" + errors.map((error) => error.formattedMessage).join("\n"));
const compiled = output.contracts["ERC20Swap.sol"]?.ERC20Swap;
if (!compiled) throw new Error("ERC20Swap missing");
const runtime = "0x" + compiled.evm.deployedBytecode.object;
// Immutable values (the EIP-712 domain separator) are patched into the runtime code at deployment,
// so verifiers hash the runtime bytecode with these ranges zeroed.
const immutableRanges = Object.values(compiled.evm.deployedBytecode.immutableReferences ?? {}).flat().map(({ start, length }) => ({ start, length }));
const masked = Buffer.from(runtime.slice(2), "hex");
for (const { start, length } of immutableRanges) masked.fill(0, start, start + length);
const generated = JSON.stringify({
  contract: "ERC20Swap", contractVersion: 6, compilerVersion: COMPILER, evmVersion: EVM_VERSION, optimizer: OPTIMIZER,
  sourceSha256: Object.fromEntries(SOURCES.map((name) => [name, createHash("sha256").update(sources[name]!.content).digest("hex")])),
  abi: compiled.abi, bytecode: "0x" + compiled.evm.bytecode.object, runtimeBytecode: runtime, immutableRanges,
  maskedRuntimeSha256: createHash("sha256").update(masked).digest("hex"),
}, null, 2) + "\n";
const path = new URL("./artifacts/erc20-swap-v6.json", import.meta.url);
if (process.argv.includes("--check")) { if (readFileSync(path, "utf8") !== generated) throw new Error("erc20-swap-v6.json is stale"); }
else writeFileSync(path, generated);
