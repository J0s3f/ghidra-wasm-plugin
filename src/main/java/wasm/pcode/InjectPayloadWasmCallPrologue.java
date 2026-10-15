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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.WasmLoader;
import wasm.analysis.WasmVarargInfo;

/**
 * Call prologue: pops function arguments from the operand stack into the
 * artificial input registers (via InjectPayloadWasmPop), and additionally, for
 * callsites of known variadic functions (Emscripten ABI: varargs passed
 * through a stack buffer), loads each variadic argument out of the va buffer
 * into the input registers following the fixed arguments. Combined with the
 * callsite prototype override written by WasmVarargAnalyzer, this lets the
 * decompiler display the actual variadic values (e.g.
 * printf("%d\n", x) instead of printf(fmt, va_buffer)).
 */
public class InjectPayloadWasmCallPrologue extends InjectPayloadWasmPop {

	/*
	 * Scratch varnodes in the (otherwise unused) upper part of the input register
	 * region. Must not collide with real input registers (i0..i255 occupy the
	 * first 256 slots).
	 */
	private static final long SCRATCH_SLOT = 4000;

	public InjectPayloadWasmCallPrologue(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program.getLanguage(), con.baseAddr);
		WasmCallerState.emit(program, con, ops, false);
		emitPops(program, con, ops);
		emitVarargLoads(program, con, ops);
		return ops.getPcodeOps();
	}

	private void emitVarargLoads(Program program, InjectContext con, PcodeOpEmitter ops) {
		WasmVarargInfo info;
		try {
			info = WasmVarargInfo.get(program, con.baseAddr);
		} catch (Exception e) {
			return;
		}
		if (info == null || info.offsets.length == 0)
			return;

		long regoffset = con.inputlist.get(0).getOffset();
		Address inputsBase = program.getAddressFactory().getAddressSpace("register").getAddress(regoffset);
		AddressSpace ramSpace = program.getAddressFactory().getAddressSpace("memory");

		Address bufPtr = inputsBase.add(SCRATCH_SLOT * WasmLoader.REG_SIZE);
		Address slotAddr = bufPtr.add(WasmLoader.REG_SIZE);

		/* Save the va-buffer pointer before we overwrite its register slot */
		ops.emitCopy(inputsBase.add((long) info.bufParamIndex * WasmLoader.REG_SIZE), bufPtr, 4);

		for (int i = 0; i < info.offsets.length; i++) {
			Address dest = inputsBase.add((long) (info.bufParamIndex + i) * WasmLoader.REG_SIZE);
			ops.emitAddConst(bufPtr, info.offsets[i], slotAddr, 4);
			ops.emitLoad(ramSpace, slotAddr, 4, dest, info.sizes[i]);
		}
	}
}
