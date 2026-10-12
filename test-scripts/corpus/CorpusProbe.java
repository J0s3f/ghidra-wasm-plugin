// Per-function undefined-byte evidence for the real-world corpus sweep (REPORT-H.md).
//
// WasmFeatureReport.java reports *totals*; this script localises them: which functions have a
// body that was not fully disassembled, which functions produced zero instructions, and where the
// "unimplemented"/decode-gap instructions are. It is the evidence source for the ranked findings.
//
// Owned by the corpus workstream; lives under test-scripts/corpus/ so it can be passed with
// -scriptPath test-scripts (the subdirectory becomes the java package).
//@category Test

package corpus;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

public class CorpusProbe extends GhidraScript {

	private static final int MAX_RANGES = 8;
	private static final int MAX_PREVIEW = 6;

	@Override
	public void run() throws Exception {
		String prog = currentProgram.getName();
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		int funcs = 0;
		int instrs = 0;
		long undefinedBytes = 0;
		int emptyBodies = 0;
		long thunkBytes = 0;
		int unimplInstrs = 0;

		for (Function f : fm.getFunctions(true)) {
			funcs++;
			AddressSet body = new AddressSet(f.getBody());
			AddressSet defined = new AddressSet();
			int n = 0;
			for (Instruction insn : listing.getInstructions(f.getBody(), true)) {
				n++;
				instrs++;
				defined.addRange(insn.getAddress(), insn.getMaxAddress());
				String mn = insn.getMnemonicString();
				if (mn != null && (mn.toLowerCase().contains("unimpl") || mn.equalsIgnoreCase("bad"))) {
					unimplInstrs++;
				}
			}
			AddressSet undef = body.subtract(defined);
			long ub = undef.getNumAddresses();
			undefinedBytes += ub;

			boolean interesting = ub > 0 || n == 0;
			if (n == 0 && body.getNumAddresses() > 0) {
				emptyBodies++;
				// Zero-instruction bodies are the loader's placeholders for *imported* functions.
				// They are real "undefined" bytes by the metric, but they are expected, so report
				// them separately: undefined_bytes - thunk_bytes is the decode gap that matters.
				thunkBytes += ub;
			}
			if (interesting) {
				println("UNDEF " + prog + " func=" + f.getName() + " entry=" + f.getEntryPoint() +
					" body=" + body.getNumAddresses() + " instrs=" + n + " undef_bytes=" + ub +
					" ranges=" + ranges(undef));
				preview(f);
			}
		}

		println("CORPUSPROBE-TOTAL " + prog + " funcs=" + funcs + " instrs=" + instrs +
			" undefined_bytes=" + undefinedBytes + " empty_bodies=" + emptyBodies +
			" unimpl_instrs=" + unimplInstrs + " thunk_bytes=" + thunkBytes);

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			println("BLOCK " + prog + " " + block.getName() + " size=" + block.getSize() +
				" r=" + block.isRead() + " w=" + block.isWrite() + " x=" + block.isExecute());
		}
	}

	private String ranges(AddressSetView set) {
		StringBuilder sb = new StringBuilder();
		int i = 0;
		for (AddressRange r : set.getAddressRanges()) {
			if (i++ >= MAX_RANGES) {
				sb.append("...");
				break;
			}
			if (sb.length() > 0) {
				sb.append(",");
			}
			sb.append(r.getMinAddress()).append("+").append(r.getLength());
		}
		return sb.length() == 0 ? "-" : sb.toString();
	}

	private void preview(Function f) {
		InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
		int i = 0;
		while (it.hasNext() && i < MAX_PREVIEW) {
			Instruction insn = it.next();
			println("    PREVIEW " + insn.getAddress() + "  " + insn.toString());
			i++;
		}
		if (i == 0) {
			println("    PREVIEW (no instructions)");
		}
	}
}
