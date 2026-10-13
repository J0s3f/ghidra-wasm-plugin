// Print synthesized wasm structures and function prototypes showing struct-typed params.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;

public class DumpTypes extends GhidraScript {

	@Override
	public void run() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		CategoryPath wasmCat = new CategoryPath("/wasm");

		println("TYPES " + currentProgram.getName());

		// Print all structures in the /wasm category
		int structCount = 0;
		java.util.Iterator<DataType> dtIter = dtm.getAllDataTypes();
		while (dtIter.hasNext()) {
			DataType dt = dtIter.next();
			if (dt instanceof Structure && dt.getCategoryPath().equals(wasmCat)) {
				Structure struct = (Structure) dt;
				if (!struct.getName().startsWith("wasm_struct_")) continue;
				structCount++;
				println("STRUCT " + struct.getName() + " size=" + struct.getLength());
				for (int i = 0; i < struct.getNumComponents(); i++) {
					ghidra.program.model.data.DataTypeComponent comp = struct.getComponent(i);
					println("  FIELD " + comp.getOffset() + " " + comp.getFieldName() +
						" " + comp.getDataType().getName() + " (" + comp.getLength() + " bytes)");
				}
			}
		}
		println("STRUCT_COUNT " + structCount);

		// Print function prototypes with struct-typed parameters
		int retypeCount = 0;
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
		while (iter.hasNext()) {
			Function f = iter.next();
			Parameter[] params = f.getParameters();
			boolean hasStructPtr = false;
			for (Parameter p : params) {
				if (p.getDataType() instanceof PointerDataType) {
					DataType target = ((PointerDataType) p.getDataType()).getDataType();
					if (target instanceof Structure && target.getName().startsWith("wasm_struct_")) {
						hasStructPtr = true;
						break;
					}
				}
			}
			if (hasStructPtr) {
				retypeCount++;
				println("RETYPED " + f.getName() + " : " + f.getPrototypeString(false, false));
			}
		}
		println("RETYPED_COUNT " + retypeCount);
	}
}
