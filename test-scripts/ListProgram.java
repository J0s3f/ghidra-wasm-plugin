// Dump the disassembly listing of a program, for spot-checking decode correctness.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class ListProgram extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("LISTING " + currentProgram.getName());
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			println("  function " + f.getName() + " @ " + f.getEntryPoint() + " " + f.getPrototypeString(false, false));
			for (Instruction insn : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				println("    " + insn.getAddress() + "  " + insn.toString());
				if (getScriptArgs().length > 0 && getScriptArgs()[0].equals("pcode")) {
					for (PcodeOp op : insn.getPcode()) {
						println("      PCODE " + op);
						if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
							println("      ACCESS space=" + currentProgram.getAddressFactory()
								.getAddressSpace((int) op.getInput(0).getOffset()).getName()
								+ " address_bytes=" + op.getInput(1).getSize());
						}
					}
				}
			}
		}
	}
}
