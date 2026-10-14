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
package ghidra.program.emulation;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntUnaryOperator;
import java.util.function.LongToIntFunction;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.MemBufferByteProvider;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.EmulateMemoryStateBuffer;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFuncSignature;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	private static class WasmFunctionAnalysisProvider {
		private AddressSpace codeSpace;
		private WasmModule module;
		private WasmAnalysis analysis;
		private long[] functionAddresses;

		/* Emulation-coverage state (see REPORT-EMU.md): the declared memory/table shapes and a
		 * function-address -> funcidx map, used by the emulator-side trap checks. */
		private long[] memoryPageSize;
		private long[] memoryPages;
		private long[] memoryMaxPages;
		private Map<Long, Integer> funcidxByAddress;

		public WasmFunctionAnalysisProvider(AddressFactory addressFactory, MemoryState memoryState) {
			Address moduleAddress = WasmLoader.getModuleAddress(addressFactory);
			codeSpace = moduleAddress.getAddressSpace();
			ByteProvider byteProvider = new MemBufferByteProvider(new EmulateMemoryStateBuffer(memoryState, moduleAddress));

			// Since we don't have a Program context, we have to re-analyze the Wasm module
			// from the memory contents.
			try {
				// XXX Nasty hack to retrieve the length of the Wasm module. Assumes that the
				// memory following the module will be uninitialized, or set to zero.
				BinaryReader reader = new BinaryReader(byteProvider, true);
				new WasmHeader(reader);
				long moduleSize;
				while (true) {
					moduleSize = reader.getPointerIndex();
					int id = reader.readNextUnsignedByte();
					long contentLength = reader.readNext(LEB128::unsigned);
					reader.setPointerIndex(reader.getPointerIndex() + contentLength);
					// A custom section (id 0) must have a name, so a zero-length custom section
					// is invalid. This happens if we have two consecutive null bytes, which
					// suggests that we're at the end of the module.
					if (id == 0 && contentLength == 0) {
						break;
					}
				}

				reader = new BinaryReader(new ByteProviderWrapper(byteProvider, 0, moduleSize), true);
				module = new WasmModule(reader);
			} catch (IOException e) {
				throw new LowlevelError("Unable to parse Wasm module", e);
			}

			analysis = new WasmAnalysis(addressFactory, module);
			List<WasmFuncSignature> functions = analysis.getFunctions();
			functionAddresses = new long[functions.size()];
			for (int i = 0; i < functions.size(); i++) {
				functionAddresses[i] = functions.get(i).getStartAddr().getOffset();
			}
			Arrays.sort(functionAddresses);

			/* Emulation-coverage state: declared memory shapes, a mutable page counter for
			 * memory.grow, and a function-address -> funcidx map for call_indirect type checks. */
			List<WasmResizableLimits> memories = new ArrayList<>();
			for (WasmImportEntry entry : module.getImports(WasmExternalKind.EXT_MEMORY)) {
				memories.add(entry.getMemoryType());
			}
			memories.addAll(module.getNonImportedMemories());
			memoryPageSize = new long[memories.size()];
			memoryPages = new long[memories.size()];
			memoryMaxPages = new long[memories.size()];
			for (int i = 0; i < memories.size(); i++) {
				WasmResizableLimits limits = memories.get(i);
				/* Custom page sizes share the loader's saturating helper (see
				 * WasmLoader.getMemoryPageSize); identical to the old shift for the
				 * oracle-legal exponents 0/16, bounded for anything else. */
				memoryPageSize[i] = WasmLoader.getMemoryPageSize(limits);
				memoryPages[i] = limits.getInitial();
				memoryMaxPages[i] = limits.hasMaximum() ? limits.getMaximum()
						: WasmLoader.maxMemoryPages(limits);
			}

			funcidxByAddress = new HashMap<>();
			for (int i = 0; i < module.getFunctionCount(); i++) {
				funcidxByAddress.put(WasmLoader.getFunctionAddressOffset(module, i), i);
			}
		}

		public int getMemoryCount() {
			return memoryPages.length;
		}

		public long getMemoryPageSize(int memidx) {
			return memoryPageSize[memidx];
		}

		public long getMemorySizeBytes(int memidx) {
			/* Saturating multiply: a hostile page count or page size must bound the
			 * emulated memory, never wrap it negative (identical for sane values). */
			long pages = memoryPages[memidx];
			long pageSize = memoryPageSize[memidx];
			if (pages < 0 || pageSize <= 0 || pages > Long.MAX_VALUE / pageSize) {
				return Long.MAX_VALUE;
			}
			return pages * pageSize;
		}

		/**
		 * WebAssembly {@code memory.grow} semantics: return the previous size in pages, or -1
		 * (unsigned) when the requested delta would exceed the declared maximum.
		 */
		public long growMemory(int memidx, long deltaPages) {
			long old = memoryPages[memidx];
			if (deltaPages < 0 || old + deltaPages > memoryMaxPages[memidx]) {
				return -1;
			}
			memoryPages[memidx] = old + deltaPages;
			return old;
		}

		public long getTableSize(int tableidx) {
			WasmTableType table = module.getTableType(tableidx);
			return table == null ? 0 : table.getLimits().getInitial();
		}

		public Integer getFuncidxByAddress(long address) {
			return funcidxByAddress.get(address);
		}

		public WasmModule getModule() {
			return module;
		}

		public WasmFunctionAnalysis getAnalysisForAddress(Address address) {
			if (address.getAddressSpace() != codeSpace) {
				return null;
			}

			int index = Arrays.binarySearch(functionAddresses, address.getOffset());
			if (index < 0) {
				/* No exact match, so the index is the negative of the insertion point */
				index = -index - 2;
			}
			if (index < 0 || index >= functionAddresses.length) {
				return null;
			}
			try {
				return analysis.getFunctionAnalysis(codeSpace.getAddress(functionAddresses[index]));
			} catch (IOException e) {
				throw new LowlevelError("Unable to analyze Wasm function", e);
			}
		}
	}

	private WasmFunctionAnalysisProvider analysisProvider;
	private WasmFunctionAnalysis prevAnalysis;
	private Register contextRegister;
	private long localsBase;
	private WasmEmulationHelper helper;
	/*
	 * The last value written to each register-space (operand-stack) slot, keyed by offset+size.
	 * The Wasm stack slots are direct register-space varnodes and an in-place instruction
	 * (e.g. i32.trunc_f32_s, f32.neg) overwrites its own input, so the pre-instruction value has
	 * to be remembered to reconstruct it (see operandValue).
	 */
	private final Map<Long, Long> regSlotValues = new HashMap<>();

	/*
	 * The exact WebAssembly trap texts the spec testsuite asserts. The emulator raises these
	 * itself (see checkMemoryBounds / checkArithmeticTraps / checkCallIndirect), and
	 * ghidra_scripts/spectest.py forwards them verbatim so assert_trap can compare.
	 */
	static final String TRAP_OUT_OF_BOUNDS_MEMORY = "out of bounds memory access";
	static final String TRAP_INTEGER_DIVIDE_BY_ZERO = "integer divide by zero";
	static final String TRAP_INTEGER_OVERFLOW = "integer overflow";
	static final String TRAP_INVALID_CONVERSION = "invalid conversion to integer";
	static final String TRAP_UNDEFINED_ELEMENT = "undefined element";
	static final String TRAP_UNINITIALIZED_ELEMENT = "uninitialized element";
	static final String TRAP_INDIRECT_CALL_TYPE_MISMATCH = "indirect call type mismatch";

	/*
	 * Must stay in sync with @define REG_STACK_BASE in WebAssembly.slaspec.
	 * The operand-stack slots s0, s1, ... live at this base in the register space.
	 */
	private static final long REG_STACK_BASE = 0x50000000L;

	public WasmEmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		contextRegister = emu.getLanguage().getContextBaseRegister();
		helper = new WasmEmulationHelper(emu.getLanguage());
		localsBase = emu.getLanguage().getRegister("l0").getOffset();

		registerPcodeOpBehavior("funcEntryCallOther", new FuncEntryOpBehaviour());
		registerPcodeOpBehavior("popCallOther", new PopOpBehaviour());
		registerPcodeOpBehavior("pushCallOther", new PushOpBehaviour());
		registerPcodeOpBehavior("callPrologueCallOther", new CallPrologueOpBehaviour());
		registerPcodeOpBehavior("callEpilogueCallOther", new CallEpilogueOpBehaviour());

		registerPcodeOpBehavior("ctz", new BitCountOpBehaviour("ctz", Integer::numberOfTrailingZeros, Long::numberOfTrailingZeros));
		registerPcodeOpBehavior("clz", new BitCountOpBehaviour("clz", Integer::numberOfLeadingZeros, Long::numberOfLeadingZeros));
		registerPcodeOpBehavior("popcnt", new BitCountOpBehaviour("popcnt", Integer::bitCount, Long::bitCount));

		registerPcodeOpBehavior("memory_size", new MemorySizeOpBehaviour());
		registerPcodeOpBehavior("memory_grow", new MemoryGrowOpBehaviour());
	}

	/**
	 * Normalize the argument list handed to {@link OpBehaviorOther#evaluate}.
	 *
	 * <p>Ghidra 12.1 changed
	 * {@link EmulateInstructionStateModifier#executeCallOther(PcodeOp)} to strip the
	 * CALLOTHER userop-index varnode before invoking the behaviour, and documented it on
	 * {@link OpBehaviorOther#evaluate}: "The original {@link PcodeOp#CALLOTHER} first
	 * input has been stripped (i.e., CALLOTHER index value), leaving only the inputs
	 * that were specified as arguments to the named pcodeop within the language spec".
	 * Ghidra &le; 11.x passed the full {@code PcodeOp.getInputs()} array instead,
	 * userop index included.
	 *
	 * <p>These behaviours were written for the old layout
	 * (e.g. {@code funcEntryCallOther(&i0,&l0)} -&gt; {@code inputs[1] == i0} and
	 * {@code inputs[2] == l0}, {@code inputs.length == 3}). On Ghidra &ge; 12.1 they
	 * therefore saw exactly one operand too few and aborted the first emulated
	 * instruction with {@code funcEntryCallOther requires two inputs}.
	 *
	 * <p>Accept either layout: {@code expected} arguments (new API, index stripped) or
	 * {@code expected + 1} (old API, index at {@code inputs[0]}).
	 *
	 * @param inputs operands as delivered by the emulator
	 * @param expected number of language-spec arguments
	 * @param opName userop name, for the error message
	 * @return the {@code expected} language-spec arguments
	 */
	private static Varnode[] getArgs(Varnode[] inputs, int expected, String opName) {
		if (inputs.length == expected) {
			return inputs; // Ghidra >= 12.1: userop index already stripped
		}
		if (inputs.length == expected + 1) {
			return Arrays.copyOfRange(inputs, 1, inputs.length); // Ghidra <= 11.x: index at [0]
		}
		throw new LowlevelError(opName + " requires " + expected + " input(s), got " + inputs.length);
	}

	private WasmFunctionAnalysis getAnalysis(Address address) {
		// Optimization: cache the analysis for the current function, so we only need to
		// search if the function changes
		if (prevAnalysis != null) {
			WasmFuncSignature func = prevAnalysis.getSignature();
			if (address.compareTo(func.getStartAddr()) >= 0 && address.compareTo(func.getEndAddr()) <= 0) {
				return prevAnalysis;
			}
		}
		WasmFunctionAnalysis analysis = analysisProvider.getAnalysisForAddress(address);
		if (analysis == null) {
			return null;
		}
		prevAnalysis = analysis;
		return analysis;
	}

	private class BitCountOpBehaviour implements OpBehaviorOther {
		String name;
		IntUnaryOperator i32Func;
		LongToIntFunction i64Func;
		public BitCountOpBehaviour(String name, IntUnaryOperator i32Func, LongToIntFunction i64Func) {
			this.name = name;
			this.i32Func = i32Func;
			this.i64Func = i64Func;
		}

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			Varnode[] args = getArgs(inputs, 1, name);

			int size = args[0].getSize();
			long value = memState.getValue(args[0]);
			int result;
			if (size == 4) {
				result = i32Func.applyAsInt((int)value);
			} else if (size == 8) {
				result = i64Func.applyAsInt(value);
			} else {
				throw new LowlevelError(name + " cannot be applied to object of size " + size);
			}

			memState.setValue(out, (long)result);
		}
	}

	private class FuncEntryOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			Varnode[] args = getArgs(inputs, 2, "funcEntryCallOther");

			long inputOffset = args[0].getOffset();
			long localsOffset = args[1].getOffset();
			AddressSpace regSpace = emu.getLanguage().getAddressFactory().getAddressSpace("register");

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			int numParams = funcAnalysis.getSignature().getParams().length;
			int numLocals = funcAnalysis.getSignature().getLocals().length;
			helper.copyRegisters(memState, inputOffset, localsOffset, numParams);
			byte[] zero = new byte[WasmLoader.REG_SIZE];
			for(int i=numParams; i<numLocals; i++) {
				memState.setChunk(zero, regSpace, localsOffset + i * WasmLoader.REG_SIZE, zero.length);
			}
		}
	}

	private class PopOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			// Pop operands from stack to a register block
			Varnode[] args = getArgs(inputs, 1, "popCallOther");

			long baseOffset = args[0].getOffset();

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				return;
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(emu.getMemoryState(), stackOffset, baseOffset, count);
		}
	}

	private class PushOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			// Push operands from one register block to stack
			Varnode[] args = getArgs(inputs, 1, "pushCallOther");

			long baseOffset = args[0].getOffset();

			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				return;
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPushHeight());
			int count = stackEffect.getToPush().length;
			helper.copyRegisters(emu.getMemoryState(), baseOffset, stackOffset, count);
		}
	}

	private class CallPrologueOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			Varnode[] args = getArgs(inputs, 1, "callPrologueCallOther");

			long baseOffset = args[0].getOffset();

			// Push locals onto shadow stack
			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			if (funcAnalysis == null) {
				throw new LowlevelError("Unable to find Wasm function analysis for address " +
						emu.getExecuteAddress());
			}
			helper.pushShadowStackRegs(memState, localsBase, funcAnalysis.getSignature().getLocals().length);

			// Pop params into i* registers
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				throw new LowlevelError("Unable to find stack effect for function at " + emu.getExecuteAddress());
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(memState, stackOffset, baseOffset, count);

			// Push stack onto shadow stack
			helper.pushShadowStackRegs(memState, helper.getStackOffset(0), stackEffect.getPopHeight());

			// Push LR to shadow stack
			helper.pushShadowStackLR(memState);
		}
	}

	private class CallEpilogueOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			MemoryState memState = emu.getMemoryState();
			Varnode[] args = getArgs(inputs, 1, "callEpilogueCallOther");

			long baseOffset = args[0].getOffset();

			// Pop LR from shadow stack
			helper.popShadowStackLR(memState);

			// Pop outputs into o* registers
			WasmFunctionAnalysis funcAnalysis = getAnalysis(emu.getExecuteAddress());
			StackEffect stackEffect = funcAnalysis.getStackEffect(emu.getExecuteAddress());
			if (stackEffect == null) {
				throw new LowlevelError("Unable to find stack effect for function at " + emu.getExecuteAddress());
			}

			long stackOffset = helper.getStackOffset(stackEffect.getPopHeight());
			int count = stackEffect.getToPop().length;
			helper.copyRegisters(memState, stackOffset, baseOffset, count);

			// Pop stack from shadow stack
			int stackHeight = helper.popShadowStackRegs(memState, helper.getStackOffset(0));

			// Push outputs onto stack
			helper.copyRegisters(memState, baseOffset, helper.getStackOffset(stackHeight), count);

			// Pop locals from shadow stack
			helper.popShadowStackRegs(memState, localsBase);
		}
	}

	/*
	 * ============================ Emulation-coverage trap checks ============================
	 *
	 * The SLEIGH emulator reads uninitialized memory as zero and has no notion of the Wasm
	 * abstract machine's traps, so an out-of-bounds access, a division by zero, an out-of-range
	 * float->int conversion or an indirect call through a bad table entry simply "succeeds".
	 * The checks below run once per instruction (postExecuteCallback), inspect the pcode that
	 * just executed and raise the exact spec trap text when the abstract machine would trap.
	 * They are purely emulator-side: no pcode/SLEIGH change is involved.
	 */

	private class MemorySizeOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			Varnode[] args = getArgs(inputs, 1, "memory_size");
			int memidx = (int) emu.getMemoryState().getValue(args[0]);
			long pages = 0;
			if (analysisProvider != null && memidx >= 0 &&
				memidx < analysisProvider.getMemoryCount()) {
				long pageSize = analysisProvider.getMemoryPageSize(memidx);
				pages = analysisProvider.getMemorySizeBytes(memidx) / pageSize;
			}
			emu.getMemoryState().setValue(out, pages);
		}
	}

	private class MemoryGrowOpBehaviour implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			Varnode[] args = getArgs(inputs, 2, "memory_grow");
			MemoryState memState = emu.getMemoryState();
			int memidx = (int) memState.getValue(args[0]);
			long delta = args[1].getSize() == 4
					? (memState.getValue(args[1]) & 0xffffffffL)
					: memState.getValue(args[1]);
			long result = -1;
			if (analysisProvider != null && memidx >= 0 &&
				memidx < analysisProvider.getMemoryCount()) {
				result = analysisProvider.growMemory(memidx, delta);
			}
			memState.setValue(out, result);
		}
	}

	private static long slotKey(long offset, int size) {
		return (offset << 8) | (size & 0xff);
	}

	/**
	 * The value an operand held <em>before</em> the instruction that just ran. When the operand
	 * and the operation's output are the same register-space slot (an in-place instruction such
	 * as {@code i32.trunc_f32_s} or {@code f32.neg}), the slot already holds the result, so the
	 * value recorded at the end of the previous instruction is used instead.
	 */
	private long operandValue(Emulate emulate, Varnode operand, Varnode output) {
		if (output != null && operand.getAddress().equals(output.getAddress())) {
			Long previous = regSlotValues.get(slotKey(operand.getAddress().getOffset(), operand.getSize()));
			if (previous != null) {
				return previous;
			}
		}
		return emulate.getMemoryState().getValue(operand);
	}

	/** Like {@link #operandValue} but returns null when an overwritten operand was never tracked. */
	private Long operandValueOrNull(Emulate emulate, Varnode operand, Varnode output) {
		if (output != null && operand.getAddress().equals(output.getAddress())) {
			return regSlotValues.get(slotKey(operand.getAddress().getOffset(), operand.getSize()));
		}
		return emulate.getMemoryState().getValue(operand);
	}

	/** Remember every register-space (operand-stack) slot this instruction wrote. */
	private void recordRegisterWrites(Emulate emulate, PcodeOp[] pcode) {
		MemoryState memState = emulate.getMemoryState();
		AddressSpace register = emulate.getLanguage().getAddressFactory().getAddressSpace("register");
		for (PcodeOp op : pcode) {
			Varnode out = op.getOutput();
			if (out != null && register.equals(out.getAddress().getAddressSpace())) {
				regSlotValues.put(slotKey(out.getAddress().getOffset(), out.getSize()),
					memState.getValue(out));
			}
			if (op.getOpcode() == PcodeOp.STORE && register.equals(spaceOf(emulate, op))) {
				long address = memState.getValue(op.getInput(1));
				int size = op.getInput(2).getSize();
				regSlotValues.put(slotKey(address, size), memState.getValue(op.getInput(2)));
			}
		}
	}

	private static AddressSpace spaceOf(Emulate emulate, PcodeOp op) {
		int spaceId = (int) op.getInput(0).getAddress().getOffset();
		return emulate.getLanguage().getAddressFactory().getAddressSpace(spaceId);
	}

	private static byte[] readBytes(Emulate emulate, Address addr, int length) {
		byte[] buf = new byte[length];
		int read = emulate.getMemoryState().getChunk(buf, addr.getAddressSpace(),
			addr.getOffset(), length, false);
		if (read <= 0) {
			return null;
		}
		if (read < length) {
			buf = Arrays.copyOf(buf, read);
		}
		return buf;
	}

	private static int readInstructionByte(Emulate emulate, Address addr) {
		byte[] buf = readBytes(emulate, addr, 1);
		return buf == null ? -1 : (buf[0] & 0xff);
	}

	/** Decode an unsigned LEB128 at {@code pos}; {@code outPos[0]} receives the end offset. */
	private static long decodeULEB(byte[] bytes, int pos, int[] outPos) {
		long result = 0;
		int shift = 0;
		int p = pos;
		while (p < bytes.length) {
			int b = bytes[p++] & 0xff;
			result |= (long) (b & 0x7f) << shift;
			if ((b & 0x80) == 0) {
				outPos[0] = p;
				return result;
			}
			shift += 7;
			if (shift > 63) {
				return -1;
			}
		}
		return -1;
	}

	/** Decode the memory index from a scalar, SIMD, or atomic memarg. */
	private int accessedMemoryIndex(Emulate emulate, Address instructionAddress) {
		byte[] bytes = readBytes(emulate, instructionAddress, 24);
		if (bytes == null || bytes.length < 2) {
			return -1;
		}
		int[] pos = {1};
		int opcode = bytes[0] & 0xff;
		if (opcode == 0xfd || opcode == 0xfe) {
			if (decodeULEB(bytes, pos[0], pos) < 0) {
				return -1;
			}
		} else if (opcode < 0x28 || opcode > 0x3e) {
			return -1;
		}
		long flags = decodeULEB(bytes, pos[0], pos);
		if (flags < 0) {
			return -1;
		}
		long index = (flags & 0x40) == 0 ? 0 : decodeULEB(bytes, pos[0], pos);
		return index < 0 || index > Integer.MAX_VALUE ? -1 : (int) index;
	}

	/** Check LOAD/STORE ranges in the instruction's declared memory and actual space.
	 * The memidx comes from the instruction: dividing a >4 GiB EA by the stride
	 * would incorrectly select another memory, including in mixed-index modules.
	 */
	private void checkMemoryBounds(Emulate emulate, Address instructionAddress, PcodeOp[] pcode) {
		if (analysisProvider == null || analysisProvider.getMemoryCount() == 0) {
			return;
		}
		MemoryState memState = emulate.getMemoryState();
		AddressFactory factory = emulate.getLanguage().getAddressFactory();
		AddressSpace memorySpace = factory.getAddressSpace("memory");
		AddressSpace memory64Space = factory.getAddressSpace("memory64");
		int memidx = accessedMemoryIndex(emulate, instructionAddress);
		if (memidx < 0 || memidx >= analysisProvider.getMemoryCount()) {
			return;
		}
		for (PcodeOp op : pcode) {
			int opcode = op.getOpcode();
			if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) {
				continue;
			}
			AddressSpace space = spaceOf(emulate, op);
			if (!memorySpace.equals(space) && !memory64Space.equals(space)) {
				continue;
			}
			long address = memState.getValue(op.getInput(1));
			int size = opcode == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();
			checkAddressInMemory(emulate, space, memidx, address, size, opcode == PcodeOp.STORE);
		}
	}

	/** Check unsigned ranges without overflowing address + size. */
	private void checkAddressInMemory(Emulate emulate, AddressSpace space, int memidx,
			long address, int size, boolean isStore) {
		long addressInMemory = address - (long) memidx * WasmLoader.MEMORY_STRIDE;
		long memorySize = analysisProvider.getMemorySizeBytes(memidx);
		if (Long.compareUnsigned(addressInMemory, memorySize) > 0
				|| Long.compareUnsigned(size, memorySize - addressInMemory) > 0) {
			if (isStore && Long.compareUnsigned(addressInMemory, memorySize) < 0) {
				int inBoundsBytes = (int) Math.min(size, memorySize - addressInMemory);
				emulate.getMemoryState().setChunk(new byte[inBoundsBytes], space, address, inBoundsBytes);
			}
			throw new LowlevelError(TRAP_OUT_OF_BOUNDS_MEMORY);
		}
	}

	/**
	 * Trap on the integer and float->int operations the spec requires to trap and that the
	 * generic Ghidra op behaviours do not signal: unsigned div/rem by zero, signed div
	 * overflow (INT_MIN / -1), and out-of-range/NaN truncations.
	 */
	private void checkArithmeticTraps(Emulate emulate, Address lastExecuteAddress, PcodeOp[] pcode) {
		MemoryState memState = emulate.getMemoryState();
		for (PcodeOp op : pcode) {
			switch (op.getOpcode()) {
				case PcodeOp.INT_DIV:
				case PcodeOp.INT_REM:
				case PcodeOp.INT_SDIV:
				case PcodeOp.INT_SREM: {
					int size = op.getInput(1).getSize();
					long denominator = memState.getValue(op.getInput(1));
					long denom = size == 4 ? (denominator & 0xffffffffL) : denominator;
					if (denom == 0) {
						throw new LowlevelError(TRAP_INTEGER_DIVIDE_BY_ZERO);
					}
					if (op.getOpcode() == PcodeOp.INT_SDIV) {
						long numerator = memState.getValue(op.getInput(0));
						long numer = size == 4 ? (numerator & 0xffffffffL) : numerator;
						long minValue = size == 4 ? 0x80000000L : Long.MIN_VALUE;
						long minusOne = size == 4 ? 0xffffffffL : -1L;
						if (numer == minValue && denom == minusOne) {
							throw new LowlevelError(TRAP_INTEGER_OVERFLOW);
						}
					}
					break;
				}
				case PcodeOp.FLOAT_TRUNC:
					checkTruncTrap(emulate, lastExecuteAddress, op);
					break;
				default:
					break;
			}
		}
	}

	private void checkTruncTrap(Emulate emulate, Address lastExecuteAddress, PcodeOp op) {
		int opcode = readInstructionByte(emulate, lastExecuteAddress);
		/* i32/i64.trunc_f32/f64_s/u are 0xA8..0xAB and 0xAE..0xB1; the trunc_sat family is 0xFC
		 * and must not trap. */
		boolean isConversion = (opcode >= 0xA8 && opcode <= 0xAB) || (opcode >= 0xAE && opcode <= 0xB1);
		if (!isConversion) {
			return;
		}
		boolean signed = opcode == 0xA8 || opcode == 0xAA || opcode == 0xAE || opcode == 0xB0;
		int inSize = op.getInput(0).getSize();
		int outSize = op.getOutput().getSize();
		long raw = operandValue(emulate, op.getInput(0), op.getOutput());
		double value = inSize == 4 ? Float.intBitsToFloat((int) raw) : Double.longBitsToDouble(raw);
		if (Double.isNaN(value)) {
			throw new LowlevelError(TRAP_INVALID_CONVERSION);
		}
		boolean overflow;
		if (signed) {
			overflow = outSize == 4
					? !(value >= -2147483648.0 && value < 2147483648.0)
					: !(value >= -9.223372036854776E18 && value < 9.223372036854776E18);
		}
		else {
			overflow = outSize == 4
					? !(value > -1.0 && value < 4294967296.0)
					: !(value > -1.0 && value < 1.8446744073709552E19);
		}
		if (overflow) {
			throw new LowlevelError(TRAP_INTEGER_OVERFLOW);
		}
	}

	/**
	 * Trap on call_indirect / return_call_indirect before the (possibly bogus) target is called:
	 * an out-of-range index is "undefined element", a null table entry is "uninitialized
	 * element", and a structurally different function type is "indirect call type mismatch".
	 */
	private void checkCallIndirect(Emulate emulate, Address lastExecuteAddress, PcodeOp[] pcode) {
		if (analysisProvider == null) {
			return;
		}
		boolean hasCallIndirect = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.CALLIND) {
				hasCallIndirect = true;
				break;
			}
		}
		if (!hasCallIndirect) {
			return;
		}
		byte[] bytes = readBytes(emulate, lastExecuteAddress, 16);
		if (bytes == null || bytes.length < 2) {
			return;
		}
		int opcode = bytes[0] & 0xff;
		if (opcode != 0x11 && opcode != 0x13) {
			return;
		}
		int[] pos = new int[1];
		long typeidx = decodeULEB(bytes, 1, pos);
		long tableidx = typeidx < 0 ? -1 : decodeULEB(bytes, pos[0], pos);
		if (typeidx < 0 || tableidx < 0) {
			return;
		}

		AddressSpace tableSpace = emulate.getLanguage().getAddressFactory().getAddressSpace("table");
		MemoryState memState = emulate.getMemoryState();
		long elementAddress = -1;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.LOAD && tableSpace.equals(spaceOf(emulate, op))) {
				elementAddress = memState.getValue(op.getInput(1));
				break;
			}
		}
		if (elementAddress < 0) {
			return;
		}

		long tableBase = tableidx << 32;
		long index = (elementAddress - tableBase) / 4;
		long tableSize = analysisProvider.getTableSize((int) tableidx);
		if (index < 0 || index >= tableSize) {
			throw new LowlevelError(TRAP_UNDEFINED_ELEMENT);
		}
		long element = memState.getValue(tableSpace, elementAddress, 4) & 0xffffffffL;
		if (element == 0) {
			throw new LowlevelError(TRAP_UNINITIALIZED_ELEMENT);
		}

		Integer funcidx = analysisProvider.getFuncidxByAddress(element);
		if (funcidx == null) {
			return;
		}
		WasmModule module = analysisProvider.getModule();
		WasmFuncType expected = module.getType((int) typeidx);
		WasmFuncType actual = module.getFunctionType(funcidx);
		if (expected == null || actual == null) {
			return;
		}
		if (!Arrays.equals(expected.getParamTypes(), actual.getParamTypes()) ||
			!Arrays.equals(expected.getReturnTypes(), actual.getReturnTypes())) {
			throw new LowlevelError(TRAP_INDIRECT_CALL_TYPE_MISMATCH);
		}
	}

	/**
	 * Wasm's f32/f64 {@code neg} and {@code abs} are pure sign-bit operations that must preserve a
	 * NaN payload, but Ghidra's FLOAT_NEG/FLOAT_ABS decode to a host double and re-encode, which
	 * canonicalises a NaN (0x7f80f1e2 -&gt; 0x7fc00000). Recompute the result from the still-live
	 * operand temp and rewrite the operand-stack store. Emulator-side only.
	 */
	private void checkFloatPurity(Emulate emulate, PcodeOp[] pcode) {
		MemoryState memState = emulate.getMemoryState();
		for (PcodeOp op : pcode) {
			int opcode = op.getOpcode();
			if (opcode != PcodeOp.FLOAT_NEG && opcode != PcodeOp.FLOAT_ABS) {
				continue;
			}
			Varnode in = op.getInput(0);
			Varnode out = op.getOutput();
			if (out == null) {
				continue;
			}
			Long original = operandValueOrNull(emulate, in, out);
			if (original == null) {
				continue; // the operand has already been overwritten and was not tracked
			}
			int size = in.getSize();
			long signMask = size == 4 ? 0x80000000L : 0x8000000000000000L;
			long corrected = opcode == PcodeOp.FLOAT_NEG ? (original ^ signMask) : (original & ~signMask);
			memState.setValue(out, corrected);
			for (PcodeOp store : pcode) {
				if (store.getOpcode() != PcodeOp.STORE || !sameVarnode(store.getInput(2), out)) {
					continue;
				}
				AddressSpace space = spaceOf(emulate, store);
				long address = memState.getValue(store.getInput(1));
				memState.setValue(space, address, store.getInput(2).getSize(), corrected);
			}
		}
	}

	private static boolean sameVarnode(Varnode a, Varnode b) {
		return a != null && b != null && a.getSize() == b.getSize() &&
			a.getAddress().equals(b.getAddress());
	}

	/**
	 * Map a Wasm load/store opcode byte to its access width in bytes, or -1 if the opcode is
	 * not a recognised load/store.
	 */
	private static int getLoadStoreAccessWidth(int opcode) {
		switch (opcode) {
			case 0x28: case 0x2A: case 0x34: case 0x35: return 4;  // i32.load, f32.load, i64.load32_s/u
			case 0x29: case 0x2B: return 8;                       // i64.load, f64.load
			case 0x2C: case 0x2D: case 0x30: case 0x31: return 1;  // 8-bit loads
			case 0x2E: case 0x2F: case 0x32: case 0x33: return 2;  // 16-bit loads
			case 0x36: case 0x38: case 0x3E: return 4;             // i32.store, f32.store, i64.store32
			case 0x37: case 0x39: return 8;                       // i64.store, f64.store
			case 0x3A: case 0x3C: return 1;                       // 8-bit stores
			case 0x3B: case 0x3D: return 2;                       // 16-bit stores
			default: return -1;
		}
	}

	/** Reconstruct the unwrapped EA for scalar, SIMD and atomic memargs.
	 * This preserves the i32 decoder while detecting lost carries in both the
	 * i32 and i64 paths. Operand-stack values are saved after each instruction
	 * because loads, SIMD lane loads and atomic RMWs overwrite their address slot.
	 */
	private void checkMemoryBounds64(Emulate emulate, Address instructionAddress, PcodeOp[] pcode) {
		if (analysisProvider == null || analysisProvider.getMemoryCount() == 0) {
			return;
		}
		byte[] bytes = readBytes(emulate, instructionAddress, 24);
		if (bytes == null || bytes.length < 2) {
			return;
		}
		int opcode = bytes[0] & 0xff;
		int[] pos = {1};
		int stackN, accessWidth;
		boolean isStore, overwritesAddress;
		if (opcode >= 0x28 && opcode <= 0x3e) {
			isStore = opcode >= 0x36;
			overwritesAddress = !isStore;
			stackN = isStore ? 2 : 1;
			accessWidth = getLoadStoreAccessWidth(opcode);
		} else if (opcode == 0xfd) {
			long sub = decodeULEB(bytes, pos[0], pos);
			if (sub >= 0 && sub <= 11) {
				int[] widths = {16, 8, 8, 8, 8, 8, 8, 1, 2, 4, 8, 16};
				accessWidth = widths[(int) sub];
				isStore = sub == 11;
				stackN = isStore ? 2 : 1;
			} else if (sub >= 84 && sub <= 91) {
				accessWidth = 1 << ((sub - 84) % 4);
				isStore = sub >= 88;
				stackN = 2;
			} else if (sub == 92 || sub == 93) {
				accessWidth = sub == 92 ? 4 : 8;
				isStore = false;
				stackN = 1;
			} else {
				return;
			}
			overwritesAddress = !isStore;
		} else if (opcode == 0xfe) {
			long sub = decodeULEB(bytes, pos[0], pos);
			if (sub >= 0 && sub <= 2) {
				accessWidth = sub == 2 ? 8 : 4;
				stackN = sub == 0 ? 2 : 3;
				isStore = false;
			} else if (sub >= 16 && sub <= 78) {
				int shape = sub <= 29 ? (int) (sub - 16) % 7
						: sub <= 71 ? (int) (sub - 30) % 7 : (int) sub - 72;
				int[] widths = {4, 8, 1, 2, 1, 2, 4};
				accessWidth = widths[shape];
				stackN = sub < 23 ? 1 : sub < 72 ? 2 : 3;
				isStore = sub >= 23;
			} else {
				return;
			}
			overwritesAddress = !(sub >= 23 && sub <= 29);
		} else {
			return;
		}
		long flags = decodeULEB(bytes, pos[0], pos);
		if (flags < 0) {
			return;
		}
		long memidx = (flags & 0x40) == 0 ? 0 : decodeULEB(bytes, pos[0], pos);
		if (memidx < 0 || memidx >= analysisProvider.getMemoryCount()) {
			return;
		}
		long offset = decodeULEB(bytes, pos[0], pos); // u64 bit pattern, including negative longs
		WasmFunctionAnalysis function = getAnalysis(instructionAddress);
		BigInteger context = function == null ? null : function.getContext(instructionAddress);
		if (context == null) {
			return;
		}
		boolean is64Bit = (context.shiftRight(112).intValue() & 3) == 3;
		int addressBytes = is64Bit ? 8 : 4;
		long stackSize = context.longValue() & 0xffffffffL;
		if (stackSize < stackN) {
			return;
		}
		long slot = REG_STACK_BASE + (stackSize - stackN) * WasmLoader.REG_SIZE;
		Long saved = regSlotValues.get(slotKey(slot, addressBytes));
		long dynamicBase;
		if (saved != null) {
			dynamicBase = saved;
		} else if (!overwritesAddress) {
			AddressSpace register = emulate.getLanguage().getAddressFactory().getAddressSpace("register");
			dynamicBase = emulate.getMemoryState().getValue(register, slot, addressBytes);
		} else if (!is64Bit && opcode >= 0x28 && opcode <= 0x35) {
			dynamicBase = reverseComputeLoadBase(emulate, pcode);
			if (dynamicBase < 0) {
				return;
			}
		} else {
			return; // The regular full-width LOAD/STORE range check still applies.
		}
		if (!is64Bit) {
			dynamicBase &= 0xffffffffL;
		}
		long ea = dynamicBase + offset;
		long memorySize = analysisProvider.getMemorySizeBytes((int) memidx);
		if (Long.compareUnsigned(ea, dynamicBase) < 0
				|| Long.compareUnsigned(ea, memorySize) > 0
				|| Long.compareUnsigned(accessWidth, memorySize - ea) > 0) {
			if (isStore) {
				long wrapped = is64Bit ? ea : ea & 0xffffffffL;
				if (Long.compareUnsigned(wrapped, memorySize) < 0) {
					int inBounds = (int) Math.min(accessWidth, memorySize - wrapped);
					AddressSpace space = emulate.getLanguage().getAddressFactory()
							.getAddressSpace(is64Bit ? "memory64" : "memory");
					emulate.getMemoryState().setChunk(new byte[inBounds], space,
							wrapped + memidx * WasmLoader.MEMORY_STRIDE, inBounds);
				}
			}
			throw new LowlevelError(TRAP_OUT_OF_BOUNDS_MEMORY);
		}
	}

	/**
	 * Fallback for loads when {@link #regSlotValues} has no entry: find the LOAD in the pcode,
	 * get the wrapped 32-bit address, find the {@code INT_ADD} that produced it, and reverse-
	 * compute the dynamic base as {@code (wrappedAddr - constantOffset) mod 2^32}.
	 * Returns -1 if the computation cannot be performed reliably.
	 */
	private long reverseComputeLoadBase(Emulate emulate, PcodeOp[] pcode) {
		AddressSpace memorySpace = emulate.getLanguage().getAddressFactory().getAddressSpace("memory");
		MemoryState memState = emulate.getMemoryState();
		for (int i = 0; i < pcode.length; i++) {
			PcodeOp op = pcode[i];
			if (op.getOpcode() != PcodeOp.LOAD) {
				continue;
			}
			if (!memorySpace.equals(spaceOf(emulate, op))) {
				continue;
			}
			Varnode addrVar = op.getInput(1);
			long wrappedAddr = memState.getValue(addrVar);
			/* Scan backwards for the INT_ADD that wrote addrVar. */
			for (int j = i - 1; j >= 0; j--) {
				PcodeOp prev = pcode[j];
				if (prev.getOpcode() != PcodeOp.INT_ADD) {
					continue;
				}
				Varnode prevOut = prev.getOutput();
				if (prevOut == null || !sameVarnode(prevOut, addrVar)) {
					continue;
				}
				/* Found the INT_ADD. Check that one input is a constant and the other
				 * is in the register space (the operand-stack slot). */
				Varnode in0 = prev.getInput(0);
				Varnode in1 = prev.getInput(1);
				long constVal;
				if (in0.isConstant() && !in1.isConstant()) {
					constVal = in0.getOffset();
				}
				else if (in1.isConstant() && !in0.isConstant()) {
					constVal = in1.getOffset();
				}
				else {
					return -1; // multi-memory or unexpected shape
				}
				return (wrappedAddr - (constVal & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
			}
		}
		return -1;
	}

	private void updateContextValue(Emulate emulate, Address currentAddress) {
		WasmFunctionAnalysis funcAnalysis = getAnalysis(currentAddress);
		if (funcAnalysis == null) {
			return;
		}

		BigInteger context = funcAnalysis.getContext(currentAddress);
		if (context == null) {
			return;
		}

		emulate.setContextRegisterValue(new RegisterValue(contextRegister, context));
	}

	@Override
	public void initialExecuteCallback(Emulate emulate, Address current_address, RegisterValue contextRegisterValue) throws LowlevelError {
		if (analysisProvider == null) {
			analysisProvider = new WasmFunctionAnalysisProvider(emulate.getLanguage().getAddressFactory(), emulate.getMemoryState());
		}

		// Set initial context value
		updateContextValue(emulate, current_address);

		// Set SSP register if not set
		helper.setInitialSSP(emulate.getMemoryState());
	}

	@Override
	public void postExecuteCallback(Emulate emulate, Address lastExecuteAddress, PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress) throws LowlevelError {
		updateContextValue(emulate, currentAddress);
		if (lastExecutePcode == null) {
			return;
		}
		checkMemoryBounds(emulate, lastExecuteAddress, lastExecutePcode);
		checkMemoryBounds64(emulate, lastExecuteAddress, lastExecutePcode);
		checkArithmeticTraps(emulate, lastExecuteAddress, lastExecutePcode);
		checkCallIndirect(emulate, lastExecuteAddress, lastExecutePcode);
		checkFloatPurity(emulate, lastExecutePcode);
		recordRegisterWrites(emulate, lastExecutePcode);
	}
}
