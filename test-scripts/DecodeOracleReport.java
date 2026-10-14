// Per-function decode facts for the cross-engine decode oracle (test-scripts/decode-oracle.ps1).
//
// Prints one machine-parseable block per program (consumed by check-decode-oracle.py):
//
//   ORACLE-MODULE <programName>
//   ORACLE-FUNC <bodyIdx> <name> real=<N>     one line per DEFINED function, in address (code) order;
//                                             real = wasm instructions excluding the pre-analyzer's
//                                             marker pseudo-instructions (mnemonics beginning with '.',
//                                             i.e. .locals/.local/.case/.default - see MODERN_WASM_GAPS 2.4)
//   ORACLE-HISTO <mnemonic> <count>           normalized mnemonic histogram over the real instructions,
//                                             sorted by mnemonic; the mnemonic is lower-cased and operands
//                                             are stripped (getMnemonicString), so it lines up with the
//                                             WABT wasm-objdump mnemonic after the same normalization
//   ORACLE-TOTAL bodies=<B> imports=<I> real=<R> funcs=<F>
//
// Imported functions are the loader's 4-byte empty stubs: they carry zero real instructions, so
// imports = functions with real == 0 and bodies = functions with real >= 1. This script does NOT
// decompile (unlike WasmFeatureReport), so it is fast enough to run on every corpus module.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class DecodeOracleReport extends GhidraScript {

	@Override
	public void run() throws Exception {
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		// [entryOffset, name, realCount] for every defined function (real instructions >= 1).
		List<Object[]> bodies = new ArrayList<>();
		int imports = 0;
		long totalReal = 0;
		Map<String, Long> histo = new TreeMap<>();

		for (Function f : fm.getFunctions(true)) {
			int real = 0;
			for (Instruction insn : listing.getInstructions(f.getBody(), true)) {
				String m = insn.getMnemonicString();
				if (m == null) {
					continue;
				}
				if (m.startsWith(".")) {
					continue; // pre-analyzer marker (.locals/.local/.case/.default) - not a wasm instruction
				}
				real++;
				histo.merge(m.toLowerCase(), 1L, Long::sum);
			}
			if (real == 0) {
				imports++; // 4-byte empty import stub
			}
			else {
				bodies.add(new Object[] { f.getEntryPoint().getOffset(), f.getName(), (long) real });
				totalReal += real;
			}
		}
		// Bodies live in the contiguous code block, so address order == wasm body order == WABT
		// wasm-objdump -d order. Sort explicitly so the ordinal is stable even if the function
		// manager ever returns a different order.
		bodies.sort((a, b) -> Long.compare((long) a[0], (long) b[0]));

		println("ORACLE-MODULE " + currentProgram.getName());
		int idx = 0;
		for (Object[] b : bodies) {
			println("ORACLE-FUNC " + idx + " " + b[1] + " real=" + b[2]);
			idx++;
		}
		for (Map.Entry<String, Long> e : histo.entrySet()) {
			println("ORACLE-HISTO " + e.getKey() + " " + e.getValue());
		}
		println("ORACLE-TOTAL bodies=" + bodies.size() + " imports=" + imports +
			" real=" + totalReal + " funcs=" + (bodies.size() + imports));
	}
}
