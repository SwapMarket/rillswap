// Compiles DevStablecoin.sol into dev-stablecoin.json with the same pinned
// compiler profile as the sandbox fixture. `--check` fails if it is stale.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import solc from "solc";

const source = readFileSync(new URL("./DevStablecoin.sol", import.meta.url), "utf8");
const compilerVersion = solc.version();
if (compilerVersion !== "0.8.30+commit.73712a01.Emscripten.clang") throw new Error("Compiler version mismatch");
const output = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { "DevStablecoin.sol": { content: source } },
  settings: { evmVersion: "prague", optimizer: { enabled: false }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
}))) as { errors?: { severity: string; formattedMessage: string }[]; contracts: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string }; deployedBytecode: { object: string } } }>> };
const errors = output.errors?.filter((error) => error.severity === "error") ?? [];
if (errors.length) throw new Error("Compilation failed:\n" + errors.map((error) => error.formattedMessage).join("\n"));
const compiled = output.contracts["DevStablecoin.sol"]?.DevStablecoin;
if (!compiled) throw new Error("DevStablecoin missing");
const generated = JSON.stringify({ compilerVersion, evmVersion: "prague", sourceSha256: createHash("sha256").update(source).digest("hex"),
  abi: compiled.abi, bytecode: "0x" + compiled.evm.bytecode.object, runtimeBytecode: "0x" + compiled.evm.deployedBytecode.object }, null, 2) + "\n";
const path = new URL("./dev-stablecoin.json", import.meta.url);
if (process.argv.includes("--check")) { if (readFileSync(path, "utf8") !== generated) throw new Error("dev-stablecoin.json is stale"); }
else writeFileSync(path, generated);
