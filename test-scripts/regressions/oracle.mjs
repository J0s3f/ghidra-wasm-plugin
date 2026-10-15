import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
const root=process.argv[2];
const malformed=new Set(['huge_params.wasm','truncated_datacount.wasm','cross_section_type.wasm']);
let count=0;
for(const file of fs.readdirSync(root).filter(f=>f.endsWith('.wasm'))) {
  assert.equal(WebAssembly.validate(fs.readFileSync(path.join(root,file))),!malformed.has(file),file);
  count++;
}
const expected=new Map(fs.readFileSync(path.join(root,'numeric-expected.tsv'),'utf8').trim().split(/\r?\n/).map(line=>line.split('\t')));
const module=new WebAssembly.Module(fs.readFileSync(path.join(root,'numeric_matrix.wasm')));
const instance=new WebAssembly.Instance(module);
for(const [index,wanted] of expected) {
  const result=instance.exports['test_numeric_'+index]();
  assert.equal(BigInt.asUintN(typeof result==='bigint'?64:32,BigInt(result)).toString(),wanted,'Numeric fixture '+index);
  count++;
}
console.log(`Node ${process.version}: ${count} fixture validation and numeric oracle assertions passed`);
