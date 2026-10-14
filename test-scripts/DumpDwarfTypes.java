// Survey: list every Structure in the program grouped by category path,
// with field offsets/sizes. Used to discover where Ghidra's DWARF importer
// materialises types (fallback ground truth for dwarf_type_metric.py).
//@category Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import java.util.TreeMap;

public class DumpDwarfTypes extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("DWARDTYPES " + currentProgram.getName());
		TreeMap<String, Integer> cats = new TreeMap<>();
		int structs = 0;
		java.util.Iterator<DataType> dtIter =
			currentProgram.getDataTypeManager().getAllDataTypes();
		while (dtIter.hasNext()) {
			DataType dt = dtIter.next();
			if (!(dt instanceof Structure)) continue;
			String cat = dt.getCategoryPath().getPath();
			cats.put(cat, cats.getOrDefault(cat, 0) + 1);
			if (!cat.startsWith("/DWARF")) continue;
			structs++;
			Structure struct = (Structure) dt;
			println("DWARFSTRUCT " + struct.getName() + " size=" + struct.getLength());
			for (int i = 0; i < struct.getNumComponents(); i++) {
				ghidra.program.model.data.DataTypeComponent comp = struct.getComponent(i);
				println("  DWARFFIELD " + comp.getOffset() + " " + comp.getFieldName() +
					" " + comp.getDataType().getName() + " (" + comp.getLength() + " bytes)");
			}
		}
		println("DWARFSTRUCT_COUNT " + structs);
		for (java.util.Map.Entry<String, Integer> e : cats.entrySet()) {
			println("CATEGORY " + e.getKey() + " structs=" + e.getValue());
		}
	}
}
