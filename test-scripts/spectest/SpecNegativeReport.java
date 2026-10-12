// Machine-readable per-module report for the *negative* (invalid / malformed / unlinkable) spec
// harness. Emits one SPECNEG line per program that the loader *did* accept, so that
// parse_spec_negative.py can tell a real rejection from a silent acceptance and can say whether the
// accepted program is usable or nonsense (empty shell / partial load).
//
// Deliberately does not decompile: the negative set is imported with -noanalysis (rejection happens
// at load time) and a nonsense program can crash the decompiler. Reuses the same body/undefined-byte
// accounting as SpecModuleReport.java when analysis *is* enabled (the optional evidence pass).
//
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

public class SpecNegativeReport extends GhidraScript {

	/**
	 * Bound the instruction walk: a malformed code section can declare an enormous function body,
	 * and iterating it address-by-address would wedge the run we are trying to measure.
	 */
	private static final long MAX_SCAN_BYTES = 4L * 1024 * 1024;

	@Override
	public void run() throws Exception {
		int funcs = 0;
		long bodyBytes = 0;
		long instrs = 0;
		long undefinedBytes = 0;
		int truncated = 0;

		Listing listing = currentProgram.getListing();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			funcs++;
			AddressSetView body = f.getBody();
			long len = body.getNumAddresses();
			bodyBytes += len;
			if (len > MAX_SCAN_BYTES) {
				/* Treat the whole body as undefined and do not walk it. */
				undefinedBytes += len;
				truncated++;
				continue;
			}
			AddressSet defined = new AddressSet();
			for (Instruction insn : listing.getInstructions(body, true)) {
				instrs++;
				defined.addRange(insn.getAddress(), insn.getMaxAddress());
			}
			undefinedBytes += body.subtract(defined).getNumAddresses();
		}

		int blocks = 0;
		long moduleBlockSize = -1;
		long memoryBytes = 0;
		long tableBytes = 0;
		boolean memory = false;
		boolean table = false;
		boolean global = false;
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			blocks++;
			String n = b.getName();
			if (".module".equals(n)) {
				moduleBlockSize = b.getSize();
			}
			else if (n.startsWith(".memory")) {
				memory = true;
				memoryBytes += b.getSize();
			}
			else if (n.startsWith(".table")) {
				table = true;
				tableBytes += b.getSize();
			}
			else if (n.startsWith(".global")) {
				global = true;
			}
		}

		/* A few data units signal that section markup was actually created. */
		int data = 0;
		for (Data d : listing.getDefinedData(true)) {
			if (d == null) {
				break;
			}
			if (++data >= 100000) {
				break;
			}
		}

		println("SPECNEG name=" + currentProgram.getName() + " funcs=" + funcs + " instrs=" + instrs +
			" body_bytes=" + bodyBytes + " undefined_bytes=" + undefinedBytes + " truncated=" +
			truncated + " blocks=" + blocks + " module_block=" + (moduleBlockSize >= 0 ? 1 : 0) +
			" module_size=" + moduleBlockSize + " memory=" + (memory ? 1 : 0) + " memory_bytes=" +
			memoryBytes + " table=" + (table ? 1 : 0) + " table_bytes=" + tableBytes + " global=" +
			(global ? 1 : 0) + " data=" + data);
	}
}
