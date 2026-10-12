// Print the initializer bytes of every wasm global and the data type applied at its address.
// Useful for verifying constant-expression / extended-const handling.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public class CheckGlobals extends GhidraScript {

	@Override
	public void run() throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("GLOBALS ").append(currentProgram.getName()).append(":");
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.getName().startsWith(".global")) {
				continue;
			}
			byte[] bytes = new byte[(int) block.getSize()];
			block.getBytes(block.getStart(), bytes);
			StringBuilder hex = new StringBuilder();
			for (byte b : bytes) {
				hex.append(String.format("%02x", b));
			}
			DataType dt = null;
			Data data = currentProgram.getListing().getDataAt(block.getStart());
			if (data != null) {
				dt = data.getDataType();
			}
			sb.append(" ").append(block.getName()).append("=[").append(hex).append("]")
					.append(dt == null ? "" : " dt=" + dt.getName());
		}
		println(sb.toString());
	}
}
