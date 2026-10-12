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
// Dumps the source map (address -> file:line) that the WebAssembly DWARF analyzer produced,
// plus the decompiler output of the first few functions so that any source line comments
// visible to the decompiler show up too.
//
// Usage: analyzeHeadless ... -import fixture.wasm -postScript DumpSourceMap.java
//
//@category WASM
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.sourcemap.SourceMapEntryIterator;

public class DumpSourceMap extends GhidraScript {

	private static final int MAX_PRINTED_ENTRIES = 200;
	private static final int MAX_DECOMPILED_FUNCS = 6;

	@Override
	protected void run() throws Exception {
		SourceFileManager sourceManager = currentProgram.getSourceFileManager();

		List<SourceFile> files = sourceManager.getAllSourceFiles();
		println("SOURCEFILES " + files.size());
		for (SourceFile file : files) {
			println("  FILE " + file.getPath() + " idType=" + file.getIdType());
		}

		AddressSetView executeSet = currentProgram.getMemory().getExecuteSet();
		SourceMapEntryIterator iter =
			sourceManager.getSourceMapEntryIterator(currentProgram.getMinAddress(), true);
		int total = 0;
		int executable = 0;
		while (iter.hasNext()) {
			SourceMapEntry entry = iter.next();
			Address addr = entry.getBaseAddress();
			boolean isExec = executeSet.contains(addr);
			if (isExec) {
				executable++;
			}
			if (total < MAX_PRINTED_ENTRIES) {
				println(String.format("SRCMAP %s -> %s:%d len=%d exec=%s", addr,
					entry.getSourceFile().getPath(), entry.getLineNumber(), entry.getLength(),
					isExec));
			}
			total++;
		}
		println(String.format("SOURCEMAP total=%d executable=%d", total, executable));

		dumpDecompiler();
	}

	private void dumpDecompiler() {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			int printed = 0;
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				if (printed >= MAX_DECOMPILED_FUNCS) {
					break;
				}
				DecompileResults results =
					decompiler.decompileFunction(function, 30, monitor);
				if (!results.decompileCompleted()) {
					println("DECOMP-FAILED " + function.getName());
					continue;
				}
				println("DECOMP " + function.getName() + " @ " + function.getEntryPoint());
				println(results.getDecompiledFunction().getC());
				printed++;
			}
		}
		catch (Exception e) {
			println("DECOMP-ERROR " + e);
		}
		finally {
			decompiler.dispose();
		}
	}
}
