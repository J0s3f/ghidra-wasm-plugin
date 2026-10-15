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
package wasm.pcode;

import java.util.*;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.format.sections.structures.WasmGCType;

/** Expose every constructor operand, including mixed-width fields, to native decompilation. */
public final class InjectPayloadWasmGCNew extends InjectPayloadCallother {
	private final boolean array;
	public InjectPayloadWasmGCNew(String source, boolean array) { super(source); this.array = array; }
	@Override public PcodeOp[] getPcode(Program program, InjectContext context) {
		int type = (int) context.inputlist.get(0).getOffset();
		var declared = WasmAnalysis.getState(program).getModule().getType(type);
		WasmGCType definition = declared instanceof WasmGCType gc ? gc : null;
		int count = array ? modelledArrayCount(program, context) : definition == null ? 0 : definition.getFieldCount();
		long base = context.inputlist.get(array ? 2 : 1).getOffset();
		String name = array ? "wasm_array_new_fixed" : "wasm_struct_new";
		int userop = 0;
		while (userop < program.getLanguage().getNumberOfUserDefinedOpNames() && !name.equals(program.getLanguage().getUserDefinedOpName(userop))) { userop++; }
		if(userop==program.getLanguage().getNumberOfUserDefinedOpNames()) throw new IllegalStateException("Missing GC constructor userop "+name);
		var constant = program.getAddressFactory().getConstantSpace();
		List<Varnode> inputs = new ArrayList<>();
		inputs.add(new Varnode(constant.getAddress(userop), 4)); inputs.add(context.inputlist.get(0));
		for (int i = 0; i < count; i++) {
			int size = definition == null ? 4 : array ? definition.getElementValType().getSize() : definition.getFieldValType(i).getSize();
			inputs.add(new Varnode(program.getAddressFactory().getRegisterSpace().getAddress(base + (long) i * WasmLoader.REG_SIZE), size));
		}
		return new PcodeOp[]{new PcodeOp(context.baseAddr, 0, PcodeOp.CALLOTHER, inputs.toArray(Varnode[]::new), context.output.get(0))};
	}

	/**
	 * array.new_fixed's immediate is an unbounded u32 (valid in unreachable code), so expose only
	 * the operands pre-analysis modelled: its input count (ctx_case_index, bits 32..63), which
	 * also positions the first operand slot.
	 */
	private static int modelledArrayCount(Program program, InjectContext context) {
		long declared = context.inputlist.get(1).getOffset() & 0xffffffffL;
		try {
			var function = program.getFunctionManager().getFunctionContaining(context.baseAddr);
			var analysis = function == null ? null : WasmAnalysis.getState(program).getFunctionAnalysis(function.getEntryPoint());
			var value = analysis == null ? null : analysis.getContext(context.baseAddr);
			if (value == null) { return 0; }
			return (int) Math.min(Math.min(declared, value.shiftRight(64).longValue() & 0xffffffffL), Integer.MAX_VALUE);
		} catch (java.io.IOException | RuntimeException e) {
			return 0;
		}
	}
}
