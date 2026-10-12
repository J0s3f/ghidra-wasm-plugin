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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmEnums.ValType;

public class WasmSignatureAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Signature Analyzer";
	private final static String DESCRIPTION = "Apply function signatures from Wasm metadata";

	public WasmSignatureAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run immediately after Apply Data Archives, since that pass might introduce
		// invalid signatures
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	private static boolean paramsMatch(List<Parameter> newParams, Parameter[] existingParams) {
		/* TODO: what if existingParams has a struct which occupies multiple slots? */
		if (newParams.size() != existingParams.length) {
			return false;
		}
		for (int i = 0; i < existingParams.length; i++) {
			if (newParams.get(i).getLength() != existingParams[i].getLength()) {
				return false;
			}
		}
		return true;
	}

	private static void setFunctionSignature(Program program, Function function, WasmFuncSignature sig) throws Exception {
		DataType returnType;
		ValType[] returns = sig.getReturns();
		if (returns.length == 0) {
			returnType = VoidDataType.dataType;
		}
		else if (returns.length == 1) {
			returnType = returns[0].asSignatureDataType();
		}
		else {
			/* multiple results: all of them, as a struct returned by value */
			returnType = multiValueReturnType(program, returns);
		}

		function.setCallingConvention("__wasm");

		DataType curReturn = function.getReturnType();
		if (returnType.getLength() != curReturn.getLength() || Undefined.isUndefined(curReturn)) {
			/* function return type is wrong or still undefined: set it */
			function.setReturnType(returnType, SourceType.IMPORTED);
		}

		/*
		 * Parameters: keep the width-correct but signedness/pointer-agnostic
		 * Undefined types (asDataType) rather than committing concrete ints
		 * (asSignatureDataType). Committing int forces the decompiler to insert
		 * (int) casts wherever a pointer is passed to the parameter, which adds
		 * far more noise than the "undefined4 param" it removes. Returns are
		 * safe to commit (they don't get cast at call sites) and are handled
		 * above.
		 */
		List<Parameter> params = new ArrayList<>();
		ValType[] rawParams = sig.getParams();
		for (int i = 0; i < rawParams.length; i++) {
			params.add(new ParameterImpl("param" + (i + 1), rawParams[i].asDataType(), program));
		}

		if (!paramsMatch(params, function.getParameters())) {
			function.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
		}
	}

	/**
	 * Build the return type of a function with more than one result: a
	 * packed structure with one field per result, in result order. The
	 * struct is returned by value in the output register block of the
	 * __wasm prototype (the {@code oN} registers, cspec pentry at
	 * register 0x30000000): the function epilogue packs the results
	 * contiguously into that block (InjectPayloadWasmPop) and callers
	 * read them back from it (InjectPayloadWasmPush), so the whole
	 * result tuple is visible to the decompiler as one value.
	 *
	 * The struct is packed (no alignment padding): field {@code i} sits
	 * at the sum of the sizes of the previous fields, exactly where the
	 * epilogue writes it. The type is registered in the program's data
	 * type manager under a name derived from the result tuple, so every
	 * function with the same tuple shares one named type.
	 *
	 * @param program the program
	 * @param returns the function's result types (length >= 2)
	 * @return the struct data type
	 */
	private static DataType multiValueReturnType(Program program, ValType[] returns) {
		StringBuilder name = new StringBuilder("wasm_ret");
		for (ValType type : returns) {
			name.append('_').append(type.name());
		}
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		CategoryPath category = new CategoryPath("/wasm");
		DataType existing = dataTypeManager.getDataType(category, name.toString());
		if (existing != null) {
			return existing;
		}
		StructureDataType struct = new StructureDataType(category, name.toString(), 0);
		struct.setPackingEnabled(true);
		for (int i = 0; i < returns.length; i++) {
			struct.add(returns[i].asSignatureDataType(), "f" + i, null);
		}
		return dataTypeManager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> functions = state.getFunctions();
		monitor.initialize(functions.size());
		for (int i = 0; i < functions.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(i);

			WasmFuncSignature func = functions.get(i);
			Function function = program.getListing().getFunctionAt(func.getStartAddr());
			try {
				setFunctionSignature(program, function, func);
			} catch (Exception e) {
				Msg.error(this, "Failed to set function signature for " + func.getName(), e);
			}
		}
		return true;
	}
}
