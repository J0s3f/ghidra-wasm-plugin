// Dump the disassembly listing of a program, for spot-checking decode correctness.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class ListProgram extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("LISTING " + currentProgram.getName());
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			println("  function " + f.getName() + " @ " + f.getEntryPoint() + " " + f.getPrototypeString(false, false));
			for (Instruction insn : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				println("    " + insn.getAddress() + "  " + insn.toString());
			}
		}
	}
}
