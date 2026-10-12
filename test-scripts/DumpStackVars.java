// Print every function's stack-frame variables (name, offset, size, type), one per line.
// Used as the evidence for the stack-as-aggregate + SROA probes (test-scripts/probes_sroa.py).
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;

public class DumpStackVars extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("STACKVARS " + currentProgram.getName());
		int funcsWithVars = 0;
		int totalVars = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			StackFrame frame = f.getStackFrame();
			Variable[] vars = frame.getStackVariables();
			totalVars += vars.length;
			if (vars.length > 0) {
				funcsWithVars++;
			}
			println("  function " + f.getName() + " frameSize=" + frame.getFrameSize() +
				" vars=" + vars.length);
			for (Variable v : vars) {
				DataType dt = v.getDataType();
				println("    var off=" + v.getStackOffset() + " size=" + dt.getLength() +
					" type=" + dt.getName() + " name=" + v.getName());
			}
		}
		println("STACKSUM " + currentProgram.getName() + " funcs_with_vars=" + funcsWithVars +
			" total_vars=" + totalVars);
	}
}
