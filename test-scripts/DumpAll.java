// Print the decompiled C for every function in the program (for tiny probe modules).
//@category Test

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DumpAll extends GhidraScript {

	/**
	 * Decompile with one retry at a much larger budget (same helper as DumpDecomp.java).
	 * The heaviest WebAssembly functions can exceed the first budget on a loaded CI
	 * runner; a single retry removes that flake without weakening the check.
	 */
	private static DecompileResults decompileWithRetry(DecompInterface dif, Function f, ghidra.util.task.TaskMonitor monitor) {
		DecompileResults res = dif.decompileFunction(f, 120, monitor);
		if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
			res = dif.decompileFunction(f, 600, monitor);
		}
		return res;
	}

	@Override
	public void run() throws Exception {
		DecompInterface dif = new DecompInterface();
		dif.toggleCCode(true);
		dif.openProgram(currentProgram);
		println("DECOMP " + currentProgram.getName());
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			DecompileResults res = decompileWithRetry(dif, f, monitor);
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				println("---- " + f.getName() + " prototype: " + f.getPrototypeString(false, false));
				println(res.getDecompiledFunction().getC());
			}
			else {
				println("---- " + f.getName() + " DECOMPILE FAILED: " +
					(res == null ? "null" : res.getErrorMessage()));
			}
		}
		dif.dispose();
	}
}
