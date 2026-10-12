// Test script: verify disassembly + decompilation of a WebAssembly program.
//@category Test

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

public class DumpDecomp extends GhidraScript {

	/**
	 * Decompile with one retry at a much larger budget. The heaviest WebAssembly functions
	 * (e.g. br_table.0.wasm in the spec suite) can exceed the first budget on a loaded CI
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
		dif.toggleSyntaxTree(true);
		dif.openProgram(currentProgram);

		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		int totalFuncs = 0;
		int totalInstrs = 0;
		int undefinedBytes = 0;
		int decompiled = 0;
		int failures = 0;

		for (Function f : fm.getFunctions(true)) {
			totalFuncs++;
			AddressSetView body = f.getBody();
			AddressSet defined = new AddressSet();
			for (Instruction insn : listing.getInstructions(body, true)) {
				totalInstrs++;
				defined.addRange(insn.getAddress(), insn.getMaxAddress());
			}
			undefinedBytes += body.subtract(defined).getNumAddresses();

			DecompileResults res = decompileWithRetry(dif, f, monitor);
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				decompiled++;
			}
			else {
				failures++;
				String err = (res == null) ? "null result" : res.getErrorMessage();
				println("DECOMPILE FAIL: " + f.getName() + " @ " + f.getEntryPoint() + " : " + err);
			}
		}

		println("SUMMARY functions=" + totalFuncs + " decompiled=" + decompiled + " failed=" + failures +
			" instructions=" + totalInstrs + " undefined_bytes=" + undefinedBytes);

		// Print decompilation of a few representative (largest) functions.
		Function[] biggest = new Function[3];
		int[] sizes = new int[3];
		for (Function f : fm.getFunctions(true)) {
			int size = (int) f.getBody().getNumAddresses();
			for (int i = 0; i < 3; i++) {
				if (size > sizes[i]) {
					for (int j = 2; j > i; j--) {
						sizes[j] = sizes[j - 1];
						biggest[j] = biggest[j - 1];
					}
					sizes[i] = size;
					biggest[i] = f;
					break;
				}
			}
		}
		for (Function f : biggest) {
			if (f == null) {
				continue;
			}
			DecompileResults res = decompileWithRetry(dif, f, monitor);
			println("==================== " + f.getName() + " @ " + f.getEntryPoint() + " ====================");
			if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
				println(res.getDecompiledFunction().getC());
			}
			else {
				println("DECOMPILATION FAILED: " + (res == null ? "null" : res.getErrorMessage()));
			}
		}
		dif.dispose();
	}
}
