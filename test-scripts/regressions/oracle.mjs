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

for(const name of ['brtable_large','brtable_large_mixed']) {
  const instance=new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(path.join(root,name+'.wasm'))));
  for(const input of [0,1,1022,1023,1024,1025,16382,16383,16384,-1]) {
    assert.equal(instance.exports.dispatch(input),input>=0 && input<16384 && input%2===0?43n:42n,name+' '+input);
  }
}
for(const [name,wanted] of Object.entries({isolation32:0x4411,isolation_index32:0x2277,isolation64:0x5566,isolation_simd:0x3412,isolation_atomic:0x3412,isolation_copy:0x12345678,isolation_copy_overlap:0xaabb,isolation_zero:0})) {
  const instance=new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(path.join(root,name+'.wasm'))));
  assert.equal(instance.exports['test_'+name](),wanted,name);
}
console.log('28 independent memory-isolation and large br_table execution checks passed');
