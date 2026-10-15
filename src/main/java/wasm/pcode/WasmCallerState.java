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

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;

/** Keep caller virtual registers alive when Ghidra substitutes an inline callee's pcode. */
final class WasmCallerState {
	private WasmCallerState() {}
	static void emit(Program program, InjectContext context, PcodeOpEmitter ops, boolean restore) {
		var caller = program.getFunctionManager().getFunctionContaining(context.baseAddr);
		if (caller == null) { return; }
		var instruction=program.getListing().getInstructionAt(context.baseAddr);
		if(instruction==null) return;
		boolean inline=false;
		for(var reference:instruction.getReferencesFrom()) if(reference.getReferenceType().isCall()) {
			var target=program.getFunctionManager().getFunctionAt(reference.getToAddress());
			if(target!=null && target.isInline()) {inline=true;break;}
		}
		if(!inline) return;
		try {
			var state = WasmAnalysis.getState(program);
			var analysis = state.getFunctionAnalysis(caller.getEntryPoint());
			if (analysis == null) { return; }
			var effect = analysis.getStackEffect(context.baseAddr);
			if (effect == null) { return; }
			var signature = analysis.getSignature();
			var factory = program.getAddressFactory();
			long base = state.getCallerSaveOffset(context.baseAddr,
				((long) signature.getLocals().length + effect.getPopHeight()) * WasmLoader.REG_SIZE);
			long slot = 0;
			var locals = signature.getLocals();
			for (int i = 0; i < locals.length; i++, slot += WasmLoader.REG_SIZE) {
				var register = program.getRegister("l0").getAddress().add((long) i * WasmLoader.REG_SIZE);
				var saved = factory.getUniqueSpace().getAddress(base + slot);
				ops.emitCopy(restore ? saved : register, restore ? register : saved, locals[i].getSize());
			}
			for (long i = 0; i < effect.getPopHeight(); i++, slot += WasmLoader.REG_SIZE) {
				var register = program.getRegister("s0").getAddress().add(i * WasmLoader.REG_SIZE);
				var saved = factory.getUniqueSpace().getAddress(base + slot);
				// A slot may carry a scalar, reference, or vector. Preserve the whole slot.
				ops.emitCopy(restore ? saved : register, restore ? register : saved, WasmLoader.REG_SIZE);
			}
		} catch (java.io.IOException e) {
			throw new IllegalStateException("Cannot preserve inline caller state", e);
		}
	}
}
