// Fail if struct synthesis created a structure with an unreasonably large extent.
// analyzeHeadless <proj> <name> -import ST05_sparse_offsets_no_giant_struct.wasm
//     -scriptPath test-scripts -postScript CheckStructExtent.java
//
// Sparse accesses (offsets MBs apart) used to produce structures with millions of
// padding components, which the decompiler cannot serialize ("Response buffer size exceeded").
//@category Test.Wasm
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

public class CheckStructExtent extends GhidraScript {

	private static final int MAX_EXTENT = 0x4000;
	private static final int MAX_COMPONENTS = 0x4000;

	@Override
	public void run() throws Exception {
		int structs = 0;
		Iterator<DataType> it = currentProgram.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			DataType type = it.next();
			if (!(type instanceof Structure) || !type.getPathName().startsWith("/wasm/")) continue;
			Structure struct = (Structure) type;
			structs++;
			if (struct.getLength() > MAX_EXTENT || struct.getNumComponents() > MAX_COMPONENTS) {
				throw new AssertionError("synthesized struct too large: " + type.getName() +
					" length=" + struct.getLength() + " components=" + struct.getNumComponents());
			}
		}
		println("STRUCT-EXTENT " + currentProgram.getName() + " structs=" + structs + " passed");
	}
}
