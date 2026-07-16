/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm.analysis;

import java.lang.reflect.Field;

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.util.bin.format.dwarf.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;

public class WasmDWARFAnalyzer extends DWARFAnalyzer {

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();

		if (WasmLoader.WEBASSEMBLY.equals(format)
				&& DWARFSectionProviderFactory.createSectionProviderFor(program, TaskMonitor.DUMMY) != null) {
			return true;
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		/*
		 * Import DWARF data types (structs, typedefs, enums) but not functions.
		 * The DWARF function importer resolves variable/parameter locations via
		 * DWARF location expressions that reference wasm-native locals and frame
		 * bases; these do not translate to this plugin's ram/register layout, so
		 * it places variables at invalid addresses (ram:ffffffff) and corrupts
		 * decompiled bodies. Types alone are location-independent and safe, and
		 * give us the original struct layouts for the decompiler.
		 */
		try {
			Field f = DWARFAnalyzer.class.getDeclaredField("importOptions");
			f.setAccessible(true);
			DWARFImportOptions opts = (DWARFImportOptions) f.get(this);
			if (opts != null) {
				opts.setImportDataTypes(true);
				opts.setImportFuncs(false);
			}
		} catch (Exception e) {
			Msg.warn(this, "Could not constrain DWARF import options: " + e);
		}
		return super.added(program, set, monitor, log);
	}
}
