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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;
import wasm.format.WasmEnums.ValType;

/**
 * Handle variable-length pops from the stack to registers. We use this to
 * handle branches (popping block arguments to temporary registers), function
 * calls (popping function arguments to input registers), and function return
 * (popping return values to output registers).
 *
 * The two callother fixups that share this payload use different register
 * layouts for the destination:
 * <ul>
 * <li>{@code popCallOther} (call arguments, block arguments) and the call
 * prologue keep one value per REG_SIZE-wide register slot (i0, i1, ... / t0,
 * t1, ...), matching {@link InjectPayloadWasmEntry} and
 * {@link InjectPayloadWasmPush}.</li>
 * <li>{@code callEpilogueCallOther} (the function return) packs the results
 * contiguously into the output register block (o0, o0+size, ...). The output
 * pentry of the {@code __wasm} prototype covers that whole block, so a
 * multi-result function's results form one contiguous region that the
 * decompiler reads as a single (struct) return value.</li>
 * </ul>
 */
public class InjectPayloadWasmPop extends InjectPayloadCallother {

	private final boolean packContiguously;

	public InjectPayloadWasmPop(String sourceName) {
		this(sourceName, false);
	}

	public InjectPayloadWasmPop(String sourceName, boolean packContiguously) {
		super(sourceName);
		this.packContiguously = packContiguously;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program.getLanguage(), con.baseAddr);
		emitPops(program, con, ops);
		return ops.getPcodeOps();
	}

	protected void emitPops(Program program, InjectContext con, PcodeOpEmitter ops) {
		long regoffset = con.inputlist.get(0).getOffset();
		Address baseAddress = program.getAddressFactory().getAddressSpace("register").getAddress(regoffset);

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionAnalysis funcAnalysis;
		try {
			funcAnalysis = state.getFunctionAnalysis(
					program.getFunctionManager().getFunctionContaining(con.baseAddr).getEntryPoint());
		} catch (Exception e) {
			return;
		}
		if (funcAnalysis == null) {
			return;
		}

		StackEffect stackEffect = funcAnalysis.getStackEffect(con.baseAddr);
		if (stackEffect == null) {
			return;
		}

		long stackHeight = stackEffect.getPopHeight();
		ValType[] todo = stackEffect.getToPop();
		Address stackAddress = program.getRegister("s0").getAddress().add(stackHeight * WasmLoader.REG_SIZE);
		if (packContiguously) {
			/*
			 * Function return (callEpilogueCallOther): the results are the
			 * function's return value. Pack them contiguously into the output
			 * register block starting at the base register (o0) so that a
			 * multi-result function returns one contiguous region that the
			 * decompiler models as a single (struct) return value in the
			 * __wasm output pentry.
			 */
			int offset = 0;
			int maxFieldSize = 1;
			for (int i = 0; i < todo.length; i++) {
				ops.emitCopy(stackAddress.add(i * WasmLoader.REG_SIZE),
						baseAddress.add(offset), todo[i].getSize());
				offset += todo[i].getSize();
				maxFieldSize = Math.max(maxFieldSize, todo[i].getSize());
			}
			/*
			 * The decompiler reads the return storage rounded up to the
			 * struct's alignment (its largest field), so a packed struct
			 * whose size is not a multiple of that alignment (e.g. an
			 * (i32, f64) return: 12 bytes, alignment 8) would otherwise
			 * show the tail padding as undefined (in_register_...). Zero the
			 * padding so the decompiled return value has no undefined bytes.
			 */
			int alignedSize = ((offset + maxFieldSize - 1) / maxFieldSize) * maxFieldSize;
			if (alignedSize > offset) {
				Address zero = program.getLanguage().getAddressFactory()
						.getConstantSpace().getAddress(0);
				ops.emitCopy(zero, baseAddress.add(offset), alignedSize - offset);
			}
		}
		else {
			for (int i = 0; i < todo.length; i++) {
				ops.emitCopy(stackAddress.add(i * WasmLoader.REG_SIZE), baseAddress.add(i * WasmLoader.REG_SIZE), todo[i].getSize());
			}
		}
	}
}
