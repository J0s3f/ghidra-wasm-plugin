// Machine-readable per-module decode + decompile report for the WebAssembly spec-test harness.
//
// Emits one SPECMODULE line per program plus SPECFUNC lines for functions that failed to decompile
// or that contain bytes the disassembler did not turn into instructions (a sync/decode signal).
//
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

public class SpecModuleReport extends GhidraScript {

	@Override
	public void run() throws Exception {
		int funcs = 0;
		long instrs = 0;
		long undefinedBytes = 0;
		long bodyBytes = 0;
		int undefFuncs = 0;

		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		DecompInterface dif = new DecompInterface();
		dif.openProgram(currentProgram);
		int decOk = 0;
		int decFail = 0;

		for (Function f : fm.getFunctions(true)) {
			funcs++;
			AddressSetView body = f.getBody();
			bodyBytes += body.getNumAddresses();
			AddressSet defined = new AddressSet();
			long finstrs = 0;
			for (Instruction insn : listing.getInstructions(body, true)) {
				instrs++;
				finstrs++;
				defined.addRange(insn.getAddress(), insn.getMaxAddress());
			}
			AddressSetView undefSet = body.subtract(defined);
			long undef = undefSet.getNumAddresses();
			if (undef > 0) {
				undefFuncs++;
				undefinedBytes += undef;
			}

			DecompileResults res = dif.decompileFunction(f, 120, monitor);
			if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
				// The heaviest spec functions (br_table.0.wasm) can exceed the first budget on a
				// loaded CI runner; one retry at a much larger budget removes that flake.
				res = dif.decompileFunction(f, 600, monitor);
			}
			boolean ok = res != null && res.decompileCompleted() && res.getDecompiledFunction() != null;
			if (ok) {
				decOk++;
			}
			else {
				decFail++;
			}
			if (undef > 0 || !ok) {
				String err = ok ? "-" : (res == null ? "null result" : sanitize(res.getErrorMessage()));
				println("SPECFUNC name=" + currentProgram.getName() + " fn=" + sanitize(f.getName()) +
					" entry=" + f.getEntryPoint() + " size=" + body.getNumAddresses() + " instrs=" +
					finstrs + " undef=" + undef + " undef_at=" + undefRanges(undefSet, 4) +
					" decompile=" + (ok ? "ok" : "FAIL") + " err=" + err);
			}
		}
		dif.dispose();

		println("SPECMODULE name=" + currentProgram.getName() + " funcs=" + funcs + " instrs=" + instrs +
			" body_bytes=" + bodyBytes + " undefined_bytes=" + undefinedBytes + " undef_funcs=" +
			undefFuncs + " decompiled=" + decOk + " decompile_failed=" + decFail);
	}

	private static String sanitize(String s) {
		if (s == null) {
			return "";
		}
		return s.replace(' ', '_').replace('\n', ' ').replace('\r', ' ');
	}

	/** "start-end" for the first few undefined address ranges, so a baseline can cite exact bytes. */
	private static String undefRanges(AddressSetView set, int max) {
		StringBuilder sb = new StringBuilder();
		int n = 0;
		for (ghidra.program.model.address.AddressRange r : set) {
			if (n++ > 0) {
				sb.append(",");
			}
			if (n > max) {
				sb.append("...");
				break;
			}
			sb.append(r.getMinAddress()).append("-").append(r.getMaxAddress());
		}
		return sb.length() == 0 ? "-" : sb.toString();
	}
}
