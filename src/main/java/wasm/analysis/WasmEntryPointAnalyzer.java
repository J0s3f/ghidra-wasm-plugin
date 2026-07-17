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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmExportEntry;

/**
 * Names the user's <code>main</code> function on binaries where the name
 * section is absent (stripped / release builds). Deterministic and
 * name-section-independent: the module's exported <code>_start</code> (the
 * export section survives stripping) runs the stereotyped Emscripten/WASI
 * sequence
 *
 * <pre>
 *   __wasm_call_ctors();   // returns void
 *   result = main();       // the only non-void callee
 *   exit(result);          // returns void / noreturn
 * </pre>
 *
 * so <code>main</code> is the single callee of <code>_start</code> whose wasm
 * type has a return value (return types come from the type section, which is
 * never stripped). Naming it lets recompiled/decompiled output use
 * <code>main</code> instead of an anonymous <code>unnamed_function_N</code>.
 */
public class WasmEntryPointAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Entry Point Analyzer";
	private static final String DESCRIPTION =
		"Identifies and names the user main() via the exported _start call sequence, " +
		"so stripped binaries (no name section) still show main.";

	public WasmEntryPointAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			nameMain(program);
		} catch (Exception e) {
			Msg.warn(this, "Entry-point analysis failed: " + e);
		}
		return true;
	}

	private void nameMain(Program program) throws Exception {
		/* already have a main (e.g. from the name section)? nothing to do */
		if (!program.getSymbolTable().getGlobalSymbols("main").isEmpty()) {
			return;
		}

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmModule module = state.getModule();

		/* locate the exported _start (export names survive stripping) */
		WasmFuncSignature startSig = null;
		for (WasmExportEntry exp : module.getExports(WasmExternalKind.EXT_FUNCTION)) {
			if ("_start".equals(exp.getName()) || "__main_argc_argv".equals(exp.getName())) {
				startSig = state.getFunction(exp.getIndex());
				break;
			}
		}
		if (startSig == null) {
			return;
		}
		Function startFunc = program.getFunctionManager().getFunctionAt(startSig.getStartAddr());
		if (startFunc == null) {
			return;
		}

		/* main is the single non-void callee of _start */
		List<Function> nonVoidCallees = new ArrayList<>();
		InstructionIterator iter = program.getListing().getInstructions(startFunc.getBody(), true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();
			if (!instr.getMnemonicString().equals("call")) {
				continue;
			}
			for (Reference ref : instr.getReferencesFrom()) {
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (callee == null) {
					continue;
				}
				WasmFuncSignature cs = state.getFunctionByAddress(callee.getEntryPoint());
				if (cs != null && !cs.isImport() && cs.getReturns().length > 0
						&& !nonVoidCallees.contains(callee)) {
					nonVoidCallees.add(callee);
				}
			}
		}

		if (nonVoidCallees.size() == 1) {
			Function main = nonVoidCallees.get(0);
			main.setName("main", SourceType.ANALYSIS);
			Msg.info(this, "Named user entry point " + main.getEntryPoint() + " as main");
		}
	}
}
