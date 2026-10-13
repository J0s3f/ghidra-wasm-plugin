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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpEmitter {
	private Language language;
	private Address baseAddress;
	private List<PcodeOp> ops = new ArrayList<>();

	public PcodeOpEmitter(Language language, Address baseAddress) {
		this.language = language;
		this.baseAddress = baseAddress;
	}

	public PcodeOp[] getPcodeOps() {
		if (ops.size() == 0) {
			// Work around Ghidra issue #3389: decompiler can crash if injection produces an
			// empty array
			emitNop();
		}
		return ops.toArray(new PcodeOp[0]);
	}

	private PcodeOp newOp(int opcode) {
		PcodeOp op = new PcodeOp(baseAddress, ops.size(), opcode);
		ops.add(op);
		return op;
	}

	private Varnode getRegister(String name) {
		Register register = language.getRegister(name);
		return new Varnode(register.getAddress(), register.getNumBytes());
	}

	public void emitNop() {
		PcodeOp op = newOp(PcodeOp.COPY);
		Varnode lrVarnode = getRegister("LR");
		op.setInput(lrVarnode, 0);
		op.setOutput(lrVarnode);
	}

	public void emitCopy(Address fromAddr, Address toAddr, int size) {
		/* toAddr = fromAddr */
		PcodeOp op = newOp(PcodeOp.COPY);
		op.setInput(new Varnode(fromAddr, size), 0);
		op.setOutput(new Varnode(toAddr, size));
	}

	public void emitAddConst(Address fromAddr, long constant, Address toAddr, int size) {
		/* toAddr = fromAddr + constant */
		PcodeOp op = newOp(PcodeOp.INT_ADD);
		op.setInput(new Varnode(fromAddr, size), 0);
		op.setInput(new Varnode(language.getAddressFactory().getConstantSpace().getAddress(constant), size), 1);
		op.setOutput(new Varnode(toAddr, size));
	}

	public void emitLoad(AddressSpace space, Address ptrAddr, int ptrSize, Address destAddr, int destSize) {
		/* destAddr = *[space]ptrAddr */
		PcodeOp op = newOp(PcodeOp.LOAD);
		op.setInput(new Varnode(language.getAddressFactory().getConstantSpace().getAddress(space.getSpaceID()), 4), 0);
		op.setInput(new Varnode(ptrAddr, ptrSize), 1);
		op.setOutput(new Varnode(destAddr, destSize));
	}

	private long uniqueOffset = 0x100000;

	private Varnode newUnique(int size) {
		Varnode v = new Varnode(language.getAddressFactory().getUniqueSpace().getAddress(uniqueOffset), size);
		uniqueOffset += 0x20;
		return v;
	}

	private Varnode constVn(long value, int size) {
		return new Varnode(language.getAddressFactory().getConstantSpace().getAddress(value), size);
	}

	/**
	 * Emit an unrolled, granularity-sized copy of {@code count} elements from
	 * {@code src} to {@code dst} (both pointer varnodes into linear memory), i.e.
	 * <pre>for i in 0..count: *(dst + i*gran) = *(src + i*gran)</pre>
	 * When src points into read-only memory the decompiler folds each load to a
	 * constant, turning a bulk memory.copy of a .rodata initializer into plain
	 * <code>dst[i] = &lt;const&gt;</code> stores (recompilable), instead of an
	 * opaque memory_copy() call.
	 */
	public void emitUnrolledCopy(Varnode src, Varnode dst, int count, int gran) {
		AddressSpace memorySpace = language.getAddressFactory().getAddressSpace("memory");
		Varnode memId = constVn(memorySpace.getSpaceID(), 4);
		int ptrSize = src.getSize();
		for (int i = 0; i < count; i++) {
			long off = (long) i * gran;
			/* sp = src + off */
			Varnode sp = newUnique(ptrSize);
			PcodeOp add1 = newOp(PcodeOp.INT_ADD);
			add1.setInput(src, 0);
			add1.setInput(constVn(off, ptrSize), 1);
			add1.setOutput(sp);
			/* val = *[memory] sp */
			Varnode val = newUnique(gran);
			PcodeOp load = newOp(PcodeOp.LOAD);
			load.setInput(memId, 0);
			load.setInput(sp, 1);
			load.setOutput(val);
			/* dp = dst + off */
			Varnode dp = newUnique(ptrSize);
			PcodeOp add2 = newOp(PcodeOp.INT_ADD);
			add2.setInput(dst, 0);
			add2.setInput(constVn(off, ptrSize), 1);
			add2.setOutput(dp);
			/* *[memory] dp = val */
			PcodeOp store = newOp(PcodeOp.STORE);
			store.setInput(memId, 0);
			store.setInput(dp, 1);
			store.setInput(val, 2);
		}
	}

	/** Emit a CALLOTHER to the named pcodeop with the given inputs (no output). */
	public void emitCallOther(int pcodeopIndex, Varnode... inputs) {
		PcodeOp op = newOp(PcodeOp.CALLOTHER);
		op.setInput(constVn(pcodeopIndex, 4), 0);
		for (int i = 0; i < inputs.length; i++) {
			op.setInput(inputs[i], i + 1);
		}
	}
}
