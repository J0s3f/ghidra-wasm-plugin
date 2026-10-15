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
import wasm.analysis.WasmFunctionAnalysis;

/** Read a coalesced branch selector without expanding the label vector into basic blocks. */
public final class InjectPayloadWasmBrTable extends InjectPayloadCallother {
	public InjectPayloadWasmBrTable(String sourceName) { super(sourceName); }
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		var factory = program.getAddressFactory();
		Varnode pointer = new Varnode(factory.getUniqueSpace().getAddress(0x900000), 8);
		Varnode constant4 = new Varnode(factory.getConstantSpace().getAddress(4), 8);
		Varnode base = new Varnode(factory.getConstantSpace().getAddress(
			WasmFunctionAnalysis.getBrTableOffset(context.baseAddr)), 8);
		Varnode space = new Varnode(factory.getConstantSpace().getAddress(
			factory.getAddressSpace("brtable").getSpaceID()), 4);
		return new PcodeOp[] {
			new PcodeOp(context.baseAddr, 0, PcodeOp.INT_ZEXT, new Varnode[]{context.inputlist.get(0)}, pointer),
			new PcodeOp(context.baseAddr, 1, PcodeOp.INT_MULT, new Varnode[]{pointer, constant4}, pointer),
			new PcodeOp(context.baseAddr, 2, PcodeOp.INT_ADD, new Varnode[]{pointer, base}, pointer),
			new PcodeOp(context.baseAddr, 3, PcodeOp.LOAD, new Varnode[]{space, pointer}, context.output.get(0))
		};
	}
}
