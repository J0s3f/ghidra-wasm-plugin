#!/usr/bin/env node
// Independent validity ground truth for the corpus: run V8's WebAssembly validator over every
// module. A module V8 accepts but Ghidra fails on is a real gap; a module V8 rejects is malformed
// input and its failure is expected. Optional helper (needs node); the sweep itself does not use it -
// the verdicts are recorded in manifest.json ("v8") so the sweep stays offline.
//
// Usage: node test-scripts/corpus/validate-corpus.mjs [corpus-dir]
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2] ?? process.env.TEMP + "\\corpus";
const files = readdirSync(dir).filter((f) => f.endsWith(".wasm")).sort();
if (files.length === 0) {
  console.error(`no .wasm files in ${dir}`);
  process.exit(1);
}
let bad = 0;
for (const f of files) {
  let verdict = "valid";
  let detail = "";
  try {
    new WebAssembly.Module(readFileSync(join(dir, f)));
  } catch (e) {
    verdict = "INVALID";
    detail = e.message;
    bad++;
  }
  console.log(`${verdict.padEnd(8)} ${f.padEnd(34)} ${detail}`);
}
console.log(`\n${files.length} modules, ${bad} rejected by V8`);
