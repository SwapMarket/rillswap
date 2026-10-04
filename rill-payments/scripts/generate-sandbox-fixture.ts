import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import solc from "solc";

const source = readFileSync(new URL("../tests/fixtures/SandboxToken.sol", import.meta.url), "utf8");
const compilerVersion = solc.version();
if (compilerVersion !== "0.8.30+commit.73712a01.Emscripten.clang") throw new Error("Sandbox compiler version mismatch");
const output = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { "SandboxToken.sol": { content: source } },
  settings: { evmVersion: "prague", optimizer: { enabled: false }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
}))) as { errors?: { severity: string; formattedMessage: string }[]; contracts: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string }; deployedBytecode: { object: string } } }>> };
if (output.errors?.some((error) => error.severity === "error")) throw new Error("Sandbox compilation failed");
const compiled = output.contracts["SandboxToken.sol"]?.SandboxToken;
if (!compiled) throw new Error("Sandbox contract missing");
const generated = JSON.stringify({ compilerVersion, evmVersion: "prague", sourceSha256: createHash("sha256").update(source).digest("hex"),
  abi: compiled.abi, bytecode: "0x" + compiled.evm.bytecode.object, runtimeBytecode: "0x" + compiled.evm.deployedBytecode.object }, null, 2) + "\n";
const path = new URL("../tests/fixtures/sandbox-token.json", import.meta.url);
if (process.argv.includes("--check")) { if (readFileSync(path, "utf8") !== generated) throw new Error("Sandbox contract fixture is stale"); }
else writeFileSync(path, generated);
