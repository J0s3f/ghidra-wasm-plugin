// Detailed per-program disassembly + decompilation dump for the WebAssembly spec-test harness.
//
// Only intended for small selections (e.g. -Files i32,memory): it prints every instruction and the
// decompiled C for every function, tagged for machine parsing.
//
//@category Test

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class SpecDisasm extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("SPECASM name=" + currentProgram.getName());
		DecompInterface dif = new DecompInterface();
		dif.toggleCCode(true);
		dif.openProgram(currentProgram);

		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			println("SPECASMFUNC name=" + currentProgram.getName() + " fn=" + f.getName() + " entry=" +
				f.getEntryPoint() + " proto=" + f.getPrototypeString(false, false).replace(' ', '_'));
			for (Instruction insn : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				println("SPECASM name=" + currentProgram.getName() + " " + insn.getAddress() + "  " +
					insn.toString());
			}
			DecompileResults res = dif.decompileFunction(f, 120, monitor);
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				println("SPECC name=" + currentProgram.getName() + " fn=" + f.getName() + " BEGIN");
				println(res.getDecompiledFunction().getC());
				println("SPECC name=" + currentProgram.getName() + " fn=" + f.getName() + " END");
			}
			else {
				println("SPECC name=" + currentProgram.getName() + " fn=" + f.getName() + " FAILED=" +
					(res == null ? "null" : res.getErrorMessage().replace('\n', ' ')));
			}
		}
		dif.dispose();
	}
}
