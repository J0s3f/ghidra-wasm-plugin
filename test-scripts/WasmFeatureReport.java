// One-line report of what the wasm loader + analyzers recovered from a program.
//@category Test

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

public class WasmFeatureReport extends GhidraScript {

	private final static String I32_ADD = "ERROR";

	@Override
	public void run() throws Exception {
		int funcs = 0;
		int instrs = 0;
		long undefinedBytes = 0;

		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		for (Function f : fm.getFunctions(true)) {
			funcs++;
			AddressSetView body = f.getBody();
			AddressSet defined = new AddressSet();
			for (Instruction insn : listing.getInstructions(body, true)) {
				instrs++;
				defined.addRange(insn.getAddress(), insn.getMaxAddress());
			}
			undefinedBytes += body.subtract(defined).getNumAddresses();
		}

		DecompInterface dif = new DecompInterface();
		dif.openProgram(currentProgram);
		int ok = 0;
		int fail = 0;
		for (Function f : fm.getFunctions(true)) {
			DecompileResults res = dif.decompileFunction(f, 120, monitor);
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				ok++;
			}
			else {
				fail++;
			}
		}
		dif.dispose();

		println("PROBE " + currentProgram.getName() + " funcs=" + funcs + " instrs=" + instrs +
			" undefined_bytes=" + undefinedBytes + " decompiled=" + ok + " decompile_failed=" + fail);

		for (ghidra.program.model.mem.MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName().startsWith(".memory") || block.getName().startsWith(".table")) {
				println("PROBE-BLOCK " + currentProgram.getName() + " " + block.getName() + " size=" +
					block.getSize());
			}
		}
	}
}
