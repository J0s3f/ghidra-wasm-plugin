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
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.WasmLoader;

/** Resolve a memory-indexed access to the program's independent memory space. */
public final class InjectPayloadWasmMemoryAccess extends InjectPayloadCallother {
	private final boolean store;
	public InjectPayloadWasmMemoryAccess(String sourceName, boolean store) {
		super(sourceName); this.store = store;
	}
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Varnode index = context.inputlist.get(0);
		Varnode pointer = context.inputlist.get(1);
		var space = WasmLoader.getMemorySpace(program.getAddressFactory(), (int) index.getOffset(), pointer.getSize() == 8);
		PcodeOp op = new PcodeOp(context.baseAddr, 0, store ? PcodeOp.STORE : PcodeOp.LOAD);
		op.setInput(new Varnode(program.getAddressFactory().getConstantSpace().getAddress(space.getSpaceID()), 4), 0);
		op.setInput(pointer, 1);
		if (store) { op.setInput(context.inputlist.get(2), 2); }
		else { op.setOutput(context.output.get(0)); }
		return new PcodeOp[]{op};
	}
}
