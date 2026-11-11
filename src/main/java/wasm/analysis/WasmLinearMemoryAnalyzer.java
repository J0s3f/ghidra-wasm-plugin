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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmResizableLimits;

/** Materialize conservative representations of directly referenced linear-memory locations. */
public class WasmLinearMemoryAnalyzer extends AbstractAnalyzer {
	private static final class MemoryInfo {
		final int index;
		final WasmResizableLimits limits;
		final boolean is64;
		final AddressSet initialized = new AddressSet();
		boolean unknown;

		MemoryInfo(int index, WasmResizableLimits limits, boolean is64, boolean unknown) {
			this.index = index;
			this.limits = limits;
			this.is64 = is64;
			this.unknown = unknown;
		}
	}

	private static final class Candidate {
		final Address address;
		final int width;
		final MemoryInfo memory;

		Candidate(Address address, int width, MemoryInfo memory) {
			this.address = address;
			this.width = width;
			this.memory = memory;
		}
	}

	public WasmLinearMemoryAnalyzer() {
		super("Wasm Linear Memory Globals",
			"Identify directly referenced linear-memory locations without inferring source types.",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor()
			.equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		WasmModule module = WasmAnalysis.getState(program).getModule();
		Map<AddressSpace, MemoryInfo> memories = buildMemoryMap(program, module, monitor);
		List<Candidate> candidates = new ArrayList<>();
		List<StackValue> stack = new ArrayList<>();
		Instruction previous = null;
		// Function analyzers are scheduled with function entry points, not necessarily their
		// bodies. Retain the supplied set too, for callers that explicitly select instructions.
		AddressSet instructionSet = new AddressSet(set);
		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			instructionSet.add(function.getBody());
		}
		InstructionIterator instructions = program.getListing().getInstructions(instructionSet, true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			monitor.checkCancelled();
			Address site = instruction.getAddress();
			if (previous == null || !site.equals(previous.getFallThrough()) ||
					program.getFunctionManager().getFunctionAt(site) != null ||
					hasIncomingFlow(program, site)) {
				stack.clear();
			}
			previous = instruction;
			collectConstantAccess(instruction, memories, stack, candidates);
			int width = accessWidth(instruction.getMnemonicString());
			if (width == 0) continue;
			boolean load = instruction.getMnemonicString().contains(".load");
			for (Reference ref : instruction.getReferencesFrom()) {
				if (load ? !ref.getReferenceType().isRead() : !ref.getReferenceType().isWrite()) continue;
				Address address = ref.getToAddress();
				MemoryInfo memory = memories.get(address.getAddressSpace());
				if (memory != null) candidates.add(new Candidate(address, width, memory));
			}
		}
		// The first candidate at an address is the widest. Earlier addresses win other overlaps.
		candidates.sort(Comparator.comparing((Candidate c) -> c.address)
			.thenComparing(Comparator.comparingInt((Candidate c) -> c.width).reversed()));
		AddressSet accepted = new AddressSet();
		for (Candidate candidate : candidates) {
			monitor.checkCancelled();
			try {
				Address end = candidate.address.addNoWrap(candidate.width - 1);
				if (accepted.intersects(candidate.address, end) ||
						!mapped(program, candidate.address, end)) continue;
				Data existing = program.getListing().getDefinedDataAt(candidate.address);
				if (existing != null) {
					// Preserve existing data; only an exact-width undefined scalar is eligible.
					if (existing.getLength() != candidate.width ||
							!Undefined.isUndefined(existing.getDataType())) continue;
				}
				else {
					if (containsDefinedCode(program, candidate.address, candidate.width)) continue;
					DataType type = Undefined.getUndefinedDataType(candidate.width);
					if (type == null || type.getLength() != candidate.width) {
						type = new ArrayDataType(Undefined1DataType.dataType, candidate.width, 1);
					}
					DataUtilities.createData(program, candidate.address, type, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				accepted.addRange(candidate.address, end);
				String kind = candidate.memory.initialized.contains(candidate.address, end) ? "data" :
					(!candidate.memory.unknown && !candidate.memory.initialized.intersects(candidate.address, end)
						? "bss" : null);
				if (kind != null) applyLabel(program, candidate, kind);
			}
			catch (Exception e) {
				Msg.debug(this, "Skipping linear-memory location " + candidate.address + ": " + e);
			}
		}
		return true;
	}

	/** A known Wasm integer stack value; null stack entries represent unknown values. */
	private static final class StackValue {
		final long value;
		final int bits;
		StackValue(long value, int bits) {
			this.value = value;
			this.bits = bits;
		}
	}

	private static boolean hasIncomingFlow(Program program, Address address) {
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(address);
		while (refs.hasNext()) {
			if (refs.next().getReferenceType().isFlow()) return true;
		}
		return false;
	}

	private static StackValue pop(List<StackValue> stack) {
		return stack.isEmpty() ? null : stack.remove(stack.size() - 1);
	}

	/**
	 * Track only explicitly modeled operations in a straight-line region. Unknown operations
	 * discard the stack rather than guessing their stack effect; control-flow joins start fresh.
	 */
	private static void collectConstantAccess(Instruction instruction,
			Map<AddressSpace, MemoryInfo> memories, List<StackValue> stack,
			List<Candidate> candidates) {
		String mnemonic = instruction.getMnemonicString();
		int width = accessWidth(mnemonic);
		if (width != 0) {
			boolean load = mnemonic.contains(".load");
			boolean lane = mnemonic.endsWith("_lane");
			if (!load || lane) pop(stack); // stored value, or the input vector of a lane load
			StackValue base = pop(stack);
			if (base != null) {
				try {
					byte[] bytes = instruction.getBytes();
					int[] pos = { 1 };
					if ((bytes[0] & 0xff) == 0xfd) readUnsignedLeb(bytes, pos);
					BigInteger flags = readUnsignedLeb(bytes, pos);
					if (flags.bitLength() <= 7) {
						int flag = flags.intValue();
						BigInteger index = flag >= 0x40
							? readUnsignedLeb(bytes, pos) : BigInteger.ZERO;
						BigInteger offset = readUnsignedLeb(bytes, pos);
						if (index.bitLength() <= 31) {
							int memoryIndex = index.intValue();
							for (MemoryInfo info : memories.values()) {
								if (info.index != memoryIndex || base.bits != (info.is64 ? 64 : 32)) continue;
								BigInteger value = info.is64 ? WasmLoader.unsignedLong(base.value)
									: BigInteger.valueOf(base.value & 0xffffffffL);
								BigInteger effective = value.add(offset);
								BigInteger last = effective.add(BigInteger.valueOf(width - 1));
								if (last.bitLength() <= base.bits) {
									Address address = WasmLoader.getMemoryAddress(
										instruction.getProgram().getAddressFactory(), info.index,
										effective.longValue(), info.is64);
									candidates.add(new Candidate(address, width, info));
								}
								break;
							}
						}
					}
				}
				catch (Exception e) {
					// Malformed or unrepresentable immediates are not proof of an address.
				}
			}
			if (load) stack.add(null);
			return;
		}
		if (mnemonic.equals("i32.const") || mnemonic.equals("i64.const")) {
			StackValue value = null;
			for (Object operand : instruction.getOpObjects(0)) {
				if (operand instanceof Scalar) {
					value = new StackValue(((Scalar) operand).getSignedValue(),
						mnemonic.equals("i32.const") ? 32 : 64);
					break;
				}
			}
			stack.add(value);
			return;
		}
		if (mnemonic.equals("local.get") || mnemonic.equals("global.get") ||
				mnemonic.equals("f32.const") || mnemonic.equals("f64.const") ||
				mnemonic.equals("v128.const")) {
			stack.add(null);
			return;
		}
		if (mnemonic.equals("drop") || mnemonic.equals("local.set") || mnemonic.equals("global.set")) {
			pop(stack);
			return;
		}
		if (mnemonic.equals("local.tee")) return;
		if (mnemonic.equals("i32.add") || mnemonic.equals("i64.add") ||
				mnemonic.equals("i32.sub") || mnemonic.equals("i64.sub") ||
				mnemonic.equals("i32.mul") || mnemonic.equals("i64.mul")) {
			StackValue right = pop(stack);
			StackValue left = pop(stack);
			int bits = mnemonic.startsWith("i32") ? 32 : 64;
			StackValue result = null;
			if (left != null && right != null && left.bits == bits && right.bits == bits) {
				long value = mnemonic.endsWith(".add") ? left.value + right.value :
					(mnemonic.endsWith(".sub") ? left.value - right.value : left.value * right.value);
				result = new StackValue(bits == 32 ? value & 0xffffffffL : value, bits);
			}
			stack.add(result);
			return;
		}
		stack.clear();
	}

	private static BigInteger readUnsignedLeb(byte[] bytes, int[] position) {
		BigInteger result = BigInteger.ZERO;
		for (int i = 0; i < 10; i++) {
			if (position[0] >= bytes.length) throw new IllegalArgumentException("Truncated LEB");
			int b = bytes[position[0]++] & 0xff;
			if (i == 9 && (b & 0x7e) != 0) throw new IllegalArgumentException("LEB overflow");
			result = result.or(BigInteger.valueOf(b & 0x7f).shiftLeft(i * 7));
			if ((b & 0x80) == 0) return result;
		}
		throw new IllegalArgumentException("LEB overflow");
	}

	private static Map<AddressSpace, MemoryInfo> buildMemoryMap(Program program, WasmModule module,
			TaskMonitor monitor) throws CancelledException {
		Map<AddressSpace, MemoryInfo> result = new HashMap<>();
		List<MemoryInfo> byIndex = new ArrayList<>();
		int imports = module.getImports(WasmExternalKind.EXT_MEMORY).size();
		int count = imports + module.getNonImportedMemories().size();
		for (int i = 0; i < count; i++) {
			monitor.checkCancelled();
			WasmResizableLimits limits = i < imports
				? module.getImports(WasmExternalKind.EXT_MEMORY).get(i).getMemoryType()
				: module.getNonImportedMemories().get(i - imports);
			MemoryInfo info = null;
			try {
				boolean is64 = limits != null && limits.is64Bit();
				AddressSpace space = WasmLoader.getMemorySpace(program.getAddressFactory(), i, is64);
				info = new MemoryInfo(i, limits, is64, i < imports || limits == null);
				result.put(space, info);
			}
			catch (RuntimeException e) {
				Msg.debug(WasmLinearMemoryAnalyzer.class, "Missing memory space " + i + ": " + e);
			}
			byIndex.add(info);
		}
		for (WasmDataSegment segment : module.getDataSegments()) {
			monitor.checkCancelled();
			if (!segment.isActive()) {
				// A passive segment can later be copied to any memory.
				for (MemoryInfo info : byIndex) if (info != null) info.unknown = true;
				continue;
			}
			long index = segment.getIndex();
			if (index < 0 || index >= byIndex.size()) {
				for (MemoryInfo info : byIndex) if (info != null) info.unknown = true;
				continue;
			}
			MemoryInfo info = byIndex.get((int) index);
			if (info == null || segment.getSize() == 0) continue;
			Long offset = segment.getMemoryOffset();
			if (offset == null) {
				info.unknown = true;
				continue;
			}
			try {
				long value = info.is64 ? offset : offset & 0xffffffffL;
				if (info.limits == null ||
						WasmLoader.unsignedLong(value).add(BigInteger.valueOf(segment.getSize()))
							.compareTo(WasmLoader.unsignedLong(info.limits.getInitial())
								.multiply(BigInteger.valueOf(WasmLoader.getMemoryPageSize(info.limits)))) > 0) {
					info.unknown = true;
					continue;
				}
				Address start = WasmLoader.getMemoryAddress(program.getAddressFactory(), info.index, value, info.is64);
				Address end = start.addNoWrap(segment.getSize() - 1);
				if (!mapped(program, start, end)) {
					info.unknown = true;
					continue;
				}
				info.initialized.addRange(start, end);
			}
			catch (Exception e) {
				info.unknown = true;
			}
		}
		return result;
	}

	private static boolean mapped(Program program, Address start, Address end) {
		Address current = start;
		while (true) {
			MemoryBlock block = program.getMemory().getBlock(current);
			if (block == null || !block.isInitialized()) return false;
			if (block.contains(end)) return true;
			try {
				current = block.getEnd().addNoWrap(1);
			}
			catch (Exception e) {
				return false;
			}
		}
	}

	private static boolean containsDefinedCode(Program program, Address start, int width)
			throws Exception {
		for (int i = 0; i < width; i++) {
			Address address = start.addNoWrap(i);
			if (program.getListing().getDefinedDataContaining(address) != null ||
					program.getListing().getInstructionContaining(address) != null) return true;
		}
		return false;
	}

	private static void applyLabel(Program program, Candidate candidate, String kind) throws Exception {
		for (Symbol symbol : program.getSymbolTable().getSymbols(candidate.address)) {
			if (!symbol.isDynamic()) return;
		}
		String name = kind + "_" + (candidate.memory.index == 0 ? "" : "m" + candidate.memory.index + "_") +
			Long.toHexString(candidate.address.getOffset());
		if (!program.getSymbolTable().getSymbols(name, program.getGlobalNamespace()).isEmpty()) return;
		program.getSymbolTable().createLabel(candidate.address, name, SourceType.ANALYSIS);
	}

	/** Width of bytes transferred, not the resulting vector/scalar width. */
	private static int accessWidth(String mnemonic) {
		switch (mnemonic) {
		case "i32.load": case "i32.store": case "f32.load": case "f32.store":
		case "i64.load32_s": case "i64.load32_u": case "i64.store32":
		case "v128.load32_splat": case "v128.load32_lane": case "v128.store32_lane":
		case "v128.load32_zero": return 4;
		case "i64.load": case "i64.store": case "f64.load": case "f64.store":
		case "v128.load8x8_s": case "v128.load8x8_u":
		case "v128.load16x4_s": case "v128.load16x4_u":
		case "v128.load32x2_s": case "v128.load32x2_u":
		case "v128.load64_splat": case "v128.load64_lane": case "v128.store64_lane":
		case "v128.load64_zero": return 8;
		case "i32.load8_s": case "i32.load8_u": case "i32.store8":
		case "i64.load8_s": case "i64.load8_u": case "i64.store8":
		case "v128.load8_splat": case "v128.load8_lane": case "v128.store8_lane": return 1;
		case "i32.load16_s": case "i32.load16_u": case "i32.store16":
		case "i64.load16_s": case "i64.load16_u": case "i64.store16":
		case "v128.load16_splat": case "v128.load16_lane": case "v128.store16_lane": return 2;
		case "v128.load": case "v128.store": return 16;
		default: return 0;
		}
	}
}
