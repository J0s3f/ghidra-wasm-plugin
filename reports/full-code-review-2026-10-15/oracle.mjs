import fs from 'node:fs';
import path from 'node:path';
const directory = process.argv[2];
const rows = [];
for (const name of fs.readdirSync(directory).filter(n => n.endsWith('.wasm')).sort()) {
  const row = {fixture: name};
  try {
    const module = new WebAssembly.Module(fs.readFileSync(path.join(directory, name)));
    row.valid = true;
    try {
      const instance = new WebAssembly.Instance(module);
      const fn = Object.keys(instance.exports).find(s => s.startsWith('test_'));
      if (fn) {
        const value = instance.exports[fn]();
        row.result = value !== null && typeof value === 'object' ? '[opaque reference]' : String(value);
      }
    } catch (error) { row.runtime_error = error.message; }
  } catch (error) { row.valid = false; row.validation_error = error.message; }
  rows.push(row);
}
console.log(JSON.stringify({node:process.version,results:rows},null,2));
