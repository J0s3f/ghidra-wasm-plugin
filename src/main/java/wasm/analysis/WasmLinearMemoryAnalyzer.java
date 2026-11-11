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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
	/**
	 * Instructions at which operand-stack and local contents of different paths can meet, or
	 * at which control transfers through a continuation.
	 */
	private static final Set<String> REGION_BOUNDARIES = Set.of("block", "loop", "if", "else", "end",
		"try", "try_table", "catch", "catch_all", "delegate", "resume", "resume_throw",
		"resume_throw_ref", "suspend", "switch");

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

		/** Whether [start, start + width) lies within this memory's index type. */
		boolean fitsIndex(BigInteger start, int width) {
			return start.add(BigInteger.valueOf(width - 1)).bitLength() <= (is64 ? 64 : 32);
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

	/** The memory index and static offset immediates of a memory access. */
	private record Memarg(int memory, BigInteger offset) {}

	/** A known integer of a varnode, unsigned and masked to its size in bytes. */
	private record Known(long value, int size) {}

	public WasmLinearMemoryAnalyzer() {
		super("Wasm Linear Memory Globals",
			"Identify directly referenced linear-memory locations without inferring source types.",
			AnalyzerType.FUNCTION_ANALYZER);
		// After ASCII string recovery (DATA_TYPE_PROPOGATION + 5): the strings it creates are
		// existing data here, so their names are not superseded by inferred labels.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after().after());
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
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<MemoryInfo> memories = buildMemories(program, state.getModule(), monitor);
		Map<AddressSpace, MemoryInfo> bySpace = new HashMap<>();
		for (MemoryInfo info : memories) {
			if (info != null) {
				bySpace.put(WasmLoader.getMemorySpace(program.getAddressFactory(), info.index, info.is64), info);
			}
		}
		List<Candidate> candidates = new ArrayList<>();
		RegisterTracker registers = RegisterTracker.create(program);
		// Function analyzers are scheduled with function entry points, not necessarily their
		// bodies. Instructions of the supplied set outside those bodies are scanned without the
		// function's stack effects, which only makes calls more conservative.
		AddressSet remaining = new AddressSet(set);
		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			WasmFunctionAnalysis analysis = null;
			try {
				analysis = state.getFunctionAnalysis(function.getEntryPoint());
			}
			catch (IOException e) {
				Msg.debug(this, "No stack effects for " + function.getEntryPoint() + ": " + e);
			}
			scan(program, function.getBody(), analysis, registers, memories, bySpace, candidates, monitor);
			remaining.delete(function.getBody());
		}
		scan(program, remaining, null, registers, memories, bySpace, candidates, monitor);
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
				String kind = classify(candidate.memory, candidate.address, end);
				if (kind != null) applyLabel(program, candidate, kind);
			}
			catch (Exception e) {
				Msg.debug(this, "Skipping linear-memory location " + candidate.address + ": " + e);
			}
		}
		return true;
	}

	/**
	 * Initialized storage is "data". Zero-filled storage is "bss" only at or above the memory's
	 * lowest initialized byte: toolchains place zero-initialized globals after initialized data,
	 * while lower addresses hold the null region or a stack-first stack.
	 */
	private static String classify(MemoryInfo memory, Address start, Address end) {
		if (memory.initialized.contains(start, end)) return "data";
		if (memory.unknown || memory.initialized.isEmpty() || memory.initialized.intersects(start, end) ||
				start.compareTo(memory.initialized.getMinAddress()) < 0) return null;
		return "bss";
	}

	private static void scan(Program program, AddressSetView body, WasmFunctionAnalysis analysis,
			RegisterTracker registers, List<MemoryInfo> memories, Map<AddressSpace, MemoryInfo> bySpace,
			List<Candidate> candidates, TaskMonitor monitor) throws CancelledException {
		if (body.isEmpty()) return;
		Instruction previous = null;
		InstructionIterator instructions = program.getListing().getInstructions(body, true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			monitor.checkCancelled();
			Address site = instruction.getAddress();
			String mnemonic = instruction.getMnemonicString();
			if (previous == null || !site.equals(previous.getFallThrough()) ||
					program.getFunctionManager().getFunctionAt(site) != null ||
					hasIncomingFlow(program, site) || REGION_BOUNDARIES.contains(mnemonic)) {
				registers.clear();
			}
			previous = instruction;
			Known base = registers.apply(instruction, analysis);
			int width = accessWidth(mnemonic);
			if (width == 0) continue;
			Memarg memarg = readMemarg(instruction);
			if (memarg == null || memarg.memory() < 0 || memarg.memory() >= memories.size()) continue;
			MemoryInfo memory = memories.get(memarg.memory());
			if (memory == null) continue;
			if (base != null && base.size() == (memory.is64 ? 8 : 4)) {
				BigInteger effective = WasmLoader.unsignedLong(base.value()).add(memarg.offset());
				if (memory.fitsIndex(effective, width)) {
					candidates.add(new Candidate(WasmLoader.getMemoryAddress(program.getAddressFactory(),
						memory.index, effective.longValue(), memory.is64), width, memory));
				}
			}
			boolean load = mnemonic.contains(".load");
			for (Reference ref : instruction.getReferencesFrom()) {
				if (load ? !ref.getReferenceType().isRead() : !ref.getReferenceType().isWrite()) continue;
				Address address = ref.getToAddress();
				if (bySpace.get(address.getAddressSpace()) != memory) continue;
				// Reference analysis computes base + offset in the index width. A target below the
				// static offset wrapped around: the real access is out of bounds and traps.
				BigInteger target = WasmLoader.unsignedLong(address.getOffset());
				if (target.compareTo(memarg.offset()) < 0 || !memory.fitsIndex(target, width)) continue;
				candidates.add(new Candidate(address, width, memory));
			}
		}
	}

	/**
	 * Constant contents of the operand-stack and local registers within one straight-line region,
	 * derived from each instruction's raw p-code. Operations without a modelled result make their
	 * outputs unknown; effects the raw p-code does not show invalidate what they may write.
	 */
	private static final class RegisterTracker {
		/** Register banks are this far apart in WebAssembly.slaspec. */
		private static final long BANK_SIZE = 0x10000000L;

		private final Program program;
		private final PcodeInjectLibrary injectLibrary;
		private final long stackBase;
		private final long slotSize;
		private final long localsBase;
		private final Register stackHeight;
		private final Map<Long, Known> known = new HashMap<>();

		private RegisterTracker(Program program, long stackBase, long slotSize, long localsBase,
				Register stackHeight) {
			this.program = program;
			this.injectLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			this.stackBase = stackBase;
			this.slotSize = slotSize;
			this.localsBase = localsBase;
			this.stackHeight = stackHeight;
		}

		static RegisterTracker create(Program program) {
			Register s0 = program.getRegister("s0");
			Register s1 = program.getRegister("s1");
			Register l0 = program.getRegister("l0");
			Register height = program.getRegister("ctx_sp");
			if (s0 == null || s1 == null || l0 == null || height == null) {
				throw new IllegalStateException("WebAssembly stack or local registers are missing");
			}
			return new RegisterTracker(program, s0.getOffset(), s1.getOffset() - s0.getOffset(),
				l0.getOffset(), height);
		}

		void clear() {
			known.clear();
		}

		/** Apply the instruction; return the known base operand of its memory access, if any. */
		Known apply(Instruction instruction, WasmFunctionAnalysis analysis) {
			// Slots at or above the operand-stack height hold dropped values: a push that the raw
			// p-code does not spell out must not expose one of them.
			BigInteger height = instruction.getValue(stackHeight, false);
			invalidateStackFrom(height == null || height.bitLength() > 31 ? 0 : height.intValue());
			Map<Long, Known> uniques = new HashMap<>();
			Map<Long, Known> addressBases = new HashMap<>();
			Known accessBase = null;
			boolean branches = false;
			for (PcodeOp op : instruction.getPcode()) {
				switch (op.getOpcode()) {
				case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND, PcodeOp.RETURN:
					branches = true;
					break;
				case PcodeOp.CALL, PcodeOp.CALLIND:
					// Register effects of calls are applied by their dynamic push fixup.
					break;
				case PcodeOp.CALLOTHER: {
					String name = program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
					if ("wasm_memory_load".equals(name) || "wasm_memory_store".equals(name)) {
						if (op.getNumInputs() > 2 && op.getInput(2).isUnique()) {
							accessBase = addressBases.get(op.getInput(2).getOffset());
						}
					}
					else if (name == null || (!"memory_copy".equals(name) &&
							injectLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, name) != null)) {
						// Dynamic fixups (calls, branch relocation, function entry) write stack
						// slots the raw p-code does not name: at most those above the pops.
						WasmFunctionAnalysis.StackEffect effect =
							analysis == null ? null : analysis.getStackEffect(instruction.getAddress());
						if (effect == null) known.clear();
						else invalidateStackFrom(Math.min(effect.getPopHeight(), effect.getPushHeight()));
					}
					write(op.getOutput(), null, uniques);
					break;
				}
				default: {
					Known result = evaluate(op, uniques);
					Varnode out = op.getOutput();
					if (op.getOpcode() == PcodeOp.INT_ADD && out != null && out.isUnique()) {
						// A memarg address: offset constant plus base operand.
						Varnode baseInput = op.getInput(0).isConstant() ? op.getInput(1) : op.getInput(0);
						Known base = read(baseInput, uniques);
						if (base != null) addressBases.put(out.getOffset(), base);
					}
					write(out, result, uniques);
				}
				}
			}
			if (branches) known.clear();
			return accessBase;
		}

		private Known evaluate(PcodeOp op, Map<Long, Known> uniques) {
			Varnode out = op.getOutput();
			if (out == null || out.getSize() > 8) return null;
			int size = out.getSize();
			switch (op.getOpcode()) {
			case PcodeOp.COPY: {
				Known value = read(op.getInput(0), uniques);
				return value != null && value.size() == size ? value : null;
			}
			case PcodeOp.INT_ZEXT: {
				Known value = read(op.getInput(0), uniques);
				return value == null ? null : new Known(value.value(), size);
			}
			case PcodeOp.INT_SEXT: {
				Known value = read(op.getInput(0), uniques);
				if (value == null) return null;
				int shift = 64 - value.size() * 8;
				return new Known(mask((value.value() << shift) >> shift, size), size);
			}
			case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT: {
				Known left = read(op.getInput(0), uniques);
				Known right = read(op.getInput(1), uniques);
				if (left == null || right == null || left.size() != size || right.size() != size) return null;
				long value = op.getOpcode() == PcodeOp.INT_ADD ? left.value() + right.value()
					: op.getOpcode() == PcodeOp.INT_SUB ? left.value() - right.value()
						: left.value() * right.value();
				return new Known(mask(value, size), size);
			}
			default:
				return null;
			}
		}

		private Known read(Varnode varnode, Map<Long, Known> uniques) {
			if (varnode.getSize() > 8) return null;
			Known value;
			if (varnode.isConstant()) {
				return new Known(mask(varnode.getOffset(), varnode.getSize()), varnode.getSize());
			}
			else if (varnode.isUnique()) {
				value = uniques.get(varnode.getOffset());
			}
			else if (tracked(varnode)) {
				value = known.get(varnode.getOffset());
			}
			else {
				return null;
			}
			return value != null && value.size() == varnode.getSize() ? value : null;
		}

		private void write(Varnode out, Known value, Map<Long, Known> uniques) {
			if (out == null) return;
			if (out.isUnique()) {
				if (value == null) uniques.remove(out.getOffset());
				else uniques.put(out.getOffset(), value);
				return;
			}
			if (!tracked(out)) return;
			long start = out.getOffset();
			long end = start + out.getSize();
			known.entrySet().removeIf(e -> e.getKey() < end && start < e.getKey() + e.getValue().size());
			if (value != null) known.put(start, value);
		}

		private void invalidateStackFrom(int height) {
			long from = stackBase + Math.max(0, height) * slotSize;
			known.keySet().removeIf(offset -> offset >= from && offset < stackBase + BANK_SIZE);
		}

		private boolean tracked(Varnode varnode) {
			if (!varnode.isRegister()) return false;
			long offset = varnode.getOffset();
			return (offset >= stackBase && offset < stackBase + BANK_SIZE) ||
				(offset >= localsBase && offset < localsBase + BANK_SIZE);
		}

		private static long mask(long value, int size) {
			return size >= 8 ? value : value & ((1L << (size * 8)) - 1);
		}
	}

	private static boolean hasIncomingFlow(Program program, Address address) {
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(address);
		while (refs.hasNext()) {
			if (refs.next().getReferenceType().isFlow()) return true;
		}
		return false;
	}

	/** Parse the memarg immediates; null when malformed or unrepresentable. */
	private static Memarg readMemarg(Instruction instruction) {
		try {
			byte[] bytes = instruction.getBytes();
			int[] pos = { 1 };
			if ((bytes[0] & 0xff) == 0xfd) readUnsignedLeb(bytes, pos);
			BigInteger flags = readUnsignedLeb(bytes, pos);
			if (flags.bitLength() > 7) return null;
			BigInteger index = flags.intValue() >= 0x40 ? readUnsignedLeb(bytes, pos) : BigInteger.ZERO;
			BigInteger offset = readUnsignedLeb(bytes, pos);
			return index.bitLength() <= 31 ? new Memarg(index.intValue(), offset) : null;
		}
		catch (Exception e) {
			// Malformed or unrepresentable immediates are not proof of an address.
			return null;
		}
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

	/** Memories by index; null for a memory without an address space. */
	private static List<MemoryInfo> buildMemories(Program program, WasmModule module,
			TaskMonitor monitor) throws CancelledException {
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
				WasmLoader.getMemorySpace(program.getAddressFactory(), i, is64);
				info = new MemoryInfo(i, limits, is64, i < imports || limits == null);
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
		return byIndex;
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
