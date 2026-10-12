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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;

/**
 * This preanalysis pass is partially patterned after the validation algorithm
 * described in the Appendix:
 * https://webassembly.github.io/spec/core/appendix/algorithm.html
 */
public class WasmFunctionAnalysis {

	/**
	 * Upper bound on the number of br_table labels the pre-analyzer materialises as branch
	 * instructions in one br_table. Each case is a separate basic block ending in a conditional
	 * branch, and a pathological br_table (the spec suite's br_table.wast `large` function has
	 * ~16k labels) makes the native decompiler process die. Past the cap the labels are still
	 * consumed (by the byte-only `.case_ignored` directive) but contribute no control flow, and a
	 * warning is logged. See REPORT-SF.md finding 3.
	 */
	static final int MAX_BR_TABLE_CASES = 1024;

	private WasmFuncSignature func;
	/* null in the value stack means Unknown */
	private List<ValType> valueStack = new ArrayList<>();
	private List<ControlFrame> controlStack = new ArrayList<>();
	private Map<Address, StackEffect> stackEffects = new HashMap<>();
	private Map<Address, Long> globalGetSets = new HashMap<>();
	private ContextRegister contextreg = new ContextRegister();

	/*
	 * @@NAME: the extended-name-section label index space (function-wide, source order). Every
	 * block/loop/if/try the body introduces gets the next index; labelNameTargets maps that index
	 * to the address a branch to the label jumps to (the loop's start, otherwise the construct's
	 * `end`). The name applier analyzer turns these into real Ghidra labels.
	 */
	private int labelCounter = 0;
	private Map<Integer, Address> labelNameTargets = new HashMap<>();

	public WasmFunctionAnalysis(WasmFuncSignature func) {
		this.func = func;
	}

	/*
	 * Cache for program context changes so we can set the context register once,
	 * instead of piece-by-piece
	 */
	private static class ContextRegister {
		private static class RegisterDefinition {
			private int start;
			private int end;

			public RegisterDefinition(int start, int end) {
				this.start = start;
				this.end = end;
			}

			public int getShift() {
				return CONTEXT_REG_WIDTH - 1 - end;
			}

			public int getWidth() {
				return end - start + 1;
			}
		}

		/* These definitions must be synced with WebAssembly.slaspec */
		private static final int CONTEXT_REG_WIDTH = 128;
		private static final RegisterDefinition REG_IS_DIRECTIVE = new RegisterDefinition(0, 0);
		private static final RegisterDefinition REG_IS_RETURN = new RegisterDefinition(1, 1);
		private static final RegisterDefinition REG_IS_GLOBAL_SP = new RegisterDefinition(2, 2);
		private static final RegisterDefinition REG_DIRECTIVE_TYPE = new RegisterDefinition(3, 5);
		private static final RegisterDefinition REG_OPERAND_SIZE = new RegisterDefinition(6, 13);
		private static final RegisterDefinition REG_CASE_INDEX = new RegisterDefinition(32, 63);
		private static final RegisterDefinition REG_BR_TARGET = new RegisterDefinition(64, 95);
		private static final RegisterDefinition REG_SP = new RegisterDefinition(96, 127);
		/* @@M64: memory index / address-operand width code, see setMemoryWidths(). */
		private static final RegisterDefinition REG_MEM64 = new RegisterDefinition(14, 15);
		/* @@SS/@@STR: callother shape code for the variable-arity proposal instructions. */
		private static final RegisterDefinition REG_SS_SHAPE = new RegisterDefinition(16, 19);

		private static final int DIRECTIVE_CASE = 0;
		private static final int DIRECTIVE_DEFAULT = 1;
		private static final int DIRECTIVE_LOCALS = 2;
		private static final int DIRECTIVE_LOCAL = 3;

		private Map<Address, BigInteger> contextValues = new HashMap<>();

		private void setRegister(Address address, RegisterDefinition reg, long value) {
			if (!contextValues.containsKey(address)) {
				contextValues.put(address, BigInteger.ZERO);
			}

			if (value < 0 || value > (1L << reg.getWidth()) - 1) {
				throw new ArithmeticException("Context register value " + value + " is out of range");
			}
			contextValues.put(address, contextValues.get(address).or(BigInteger.valueOf(value).shiftLeft(reg.getShift())));
		}

		public BigInteger getContext(Address address) {
			return contextValues.get(address);
		}

		public void commitContext(Program program) {
			ProgramContext context = program.getProgramContext();
			Register contextRegister = context.getBaseContextRegister();
			for (Map.Entry<Address, BigInteger> entry : contextValues.entrySet()) {
				Address address = entry.getKey();
				if (program.getListing().getInstructionContaining(address) != null)
					continue;

				RegisterValue value = new RegisterValue(contextRegister, entry.getValue());
				try {
					context.setRegisterValue(address, address, value);
				} catch (ContextChangeException e) {
					Msg.error(this, "Failed to set context register at " + address, e);
				}
			}
			contextValues.clear();
		}

		public void setIsReturn(Address address, int value) {
			setRegister(address, REG_IS_RETURN, value);
		}

		/**
		 * Set how large the stack operand is. This currently affects local.*, global.*
		 * and select instructions.
		 */
		public void setOperandSize(Address address, ValType type) {
			if (type == null) {
				/*
				 * The width is unknown: either we are in unreachable (polymorphic) code - the
				 * spec test suite has dedicated `select`-after-<terminator> functions for exactly
				 * this - or the function contains an instruction whose stack effect we could not
				 * model. An instruction's *encoding* never depends on the operand width, but the
				 * `ctx_operand_size`-conditioned constructors (select, local.*, global.*, ...)
				 * need a defined value, otherwise no constructor matches and the byte is left
				 * undefined. Default to 32-bit instead of leaving the context unset.
				 */
				type = ValType.i32;
			}
			setRegister(address, REG_OPERAND_SIZE, type.getSize());
		}

		/**
		 * @@M64: record the width code of the memory instruction's address operands (see the
		 * MEM_CTX_* constants). 0 is the default ("every address operand is 32-bit") and is
		 * never written, so 32-bit memories keep the context untouched byte for byte.
		 *
		 * (The `degradeWidths` flag that the unimplemented-instruction workstream originally
		 * introduced was superseded by the spec-findings fix, which always degrades an unknown
		 * operand width to 32-bit - see {@link #setOperandSize}.)
		 */
		public void setMemoryWidths(Address address, int code) {
			if (code != 0) {
				setRegister(address, REG_MEM64, code);
			}
		}

		/**
		 * @@SS/@@STR: shape code for the variable-arity stack-switching / stringref callother
		 * (StackSwitchOps.sinc, StringOps.sinc). The value is p*2+r with p/r the number of
		 * operand-stack slots the callother's declared inputs/outputs model (0 or 1 each); a
		 * larger true arity is clamped here, so the pre-analyzer's own stack walk stays exact
		 * while only the callother's pcode signature degrades. Must stay in sync with the
		 * ctx_ss_shape context field in WebAssembly.slaspec.
		 */
		public void setSsShape(Address address, int shape) {
			setRegister(address, REG_SS_SHAPE, Math.min(Math.max(shape, 0), 15));
		}
		/** Mark this try instruction as dispatching to a handler (its branch target). */
		public void setTryHandler(Address address) {
			setRegister(address, REG_CASE_INDEX, 1);
		}

		// @@EH begin: new exception handling (try_table / throw_ref). See EH2Ops.java / EH2Ops.sinc.
		/** Directive type for one try_table catch clause; must match DIRECTIVE_EH_CLAUSE in EH2Ops.sinc. */
		private static final int DIRECTIVE_EH_CLAUSE = 4;

		// @@SS begin: stack switching. See StackSwitchOps.sinc.
		/** Directive type for one resume/resume_throw/resume_throw_ref handler clause. */
		private static final int DIRECTIVE_SS_HANDLER = 6;

		/**
		 * Disassemble this "instruction" as one handler clause of a resume/resume_throw/
		 * resume_throw_ref (`on <tag> <label>` or `on <tag> switch`), like {@link #setEhClause}
		 * does for try_table catch clauses.
		 */
		public void setSsHandler(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_SS_HANDLER);
		}
		// @@SS end

		/**
		 * Directive type for a br_table label past the modelled-case cap; must match
		 * DIRECTIVE_CASE_IGNORED in WebAssembly.slaspec. See {@link #MAX_BR_TABLE_CASES}.
		 */
		private static final int DIRECTIVE_CASE_IGNORED = 5;

		/**
		 * Disassemble this "instruction" as one catch clause of a try_table (catch/catch_ref/
		 * catch_all/catch_all_ref), like {@link #setBrTableCase} does for br_table labels.
		 */
		public void setEhClause(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_EH_CLAUSE);
		}
		// @@EH end

		/** Mark this global.* instruction as operating on the C stack pointer. */
		public void setIsGlobalSp(Address address, boolean value) {
			setRegister(address, REG_IS_GLOBAL_SP, value ? 1 : 0);
		}

		/** Set the address that this instruction branches to. */
		public void setBranchTarget(Address address, Address target) {
			setRegister(address, REG_BR_TARGET, target.getOffset());
		}

		/**
		 * Set the virtual stack pointer. Our SLEIGH converts stack operations into
		 * register operations by using the stack pointer to index a register file.
		 */
		public void setStackPointer(Address address, long value) {
			setRegister(address, REG_SP, value);
		}

		/* Number of locals table entries */
		public void setLocalsDeclaration(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_LOCALS);
		}

		/* One entry in the function locals table */
		public void setLocalDeclaration(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_LOCAL);
		}

		/**
		 * Disassemble this "instruction" as a case statement underneath a br_table. We
		 * break out case statements individually in order to provide each one with a
		 * unique branch target.
		 */
		public void setBrTableCase(Address address, int index) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			if (index == -1) {
				setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_DEFAULT);
			} else {
				setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_CASE);
				setRegister(address, REG_CASE_INDEX, index);
			}
		}

		/**
		 * Disassemble this br_table label as a byte-only directive: it consumes the label's
		 * bytes (keeping the stream aligned) but emits no branch and no basic block. Used for the
		 * labels past {@link #MAX_BR_TABLE_CASES} so that one pathological br_table cannot
		 * explode the decompiler's control-flow graph.
		 */
		public void setBrTableCaseIgnored(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_CASE_IGNORED);
		}
	}

	private static class BlockType {
		ValType[] params;
		ValType[] returns;

		public BlockType(WasmFuncSignature func) {
			/* A function's parameters are in local variables rather than the stack */
			params = new ValType[0];
			returns = func.getReturns();
		}

		public BlockType(ValType[] params, ValType[] returns) {
			this.params = params;
			this.returns = returns;
		}

		/**
		 * A block type given as a single value type (the single-byte and multi-byte valtype
		 * forms of a block type immediate). Such a block type has no params; a null result
		 * is the empty type (0x40).
		 */
		public BlockType(ValType result) {
			params = new ValType[0];
			returns = (result == null) ? new ValType[0] : new ValType[] { result };
		}

		public BlockType(WasmAnalysis analysis, long blocktype) {
			if (blocktype == -0x40) {
				params = new ValType[0];
				returns = new ValType[0];
			} else if (blocktype < 0) {
				params = new ValType[0];
				returns = new ValType[] { ValType.fromByte((int) blocktype + 0x80) };
			} else {
				WasmFuncType type = analysis.getType((int) blocktype);
				params = type.getParamTypes();
				returns = type.getReturnTypes();
			}
		}
	}

	private enum BlockKind {
		FUNCTION,
		BLOCK,
		IF,
		LOOP,
		TRY,	/* legacy exception handling: the try body */
		CATCH	/* a catch or catch_all handler of a try */
	}

	private class ControlFrame {
		Address startAddress;
		BlockKind blockKind;
		BlockType blockType;
		List<ValType> initialStack;
		/** A list of instruction address which branch to this block. */
		List<Address> branchAddresses = new ArrayList<>();
		boolean unreachable = false;
		boolean hasElse = false;
		boolean hasHandler = false;
		/**
		 * @@NAME: the extended-name-section label index of this construct (source order), or -1 for
		 * the function's own frame and for frames that do not introduce a label.
		 */
		int labelNameIndex = -1;

		public ControlFrame(Address address, BlockType blockType) {
			this.startAddress = address;
			this.blockKind = BlockKind.FUNCTION;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>();
		}

		public ControlFrame(Address address, BlockKind blockKind, BlockType blockType, List<ValType> stack) {
			this.startAddress = address;
			this.blockKind = blockKind;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>(stack);
		}

		public ValType[] getBranchArguments() {
			if (blockKind == BlockKind.LOOP) {
				return blockType.params;
			} else {
				return blockType.returns;
			}
		}

		/**
		 * Track a branch to this block.
		 * 
		 * @param program
		 * @param stack
		 *            Value stack after the parameters ({@link #getBranchArguments})
		 *            have been popped
		 * @param address
		 *            Address of the branch instruction
		 */
		public void addBranch(Address address) {
			branchAddresses.add(address);
		}

		public void setElse(Address address) {
			hasElse = true;
			if (blockKind != BlockKind.IF) {
				throw new ValidationException(address, "else without corresponding if");
			}
			contextreg.setBranchTarget(startAddress, address.add(1));
		}

		public void setEnd(Address address) {
			if (blockKind == BlockKind.IF && !hasElse) {
				contextreg.setBranchTarget(startAddress, address);
			}

			Address branchTarget;
			if (blockKind == BlockKind.LOOP) {
				branchTarget = startAddress;
			} else {
				branchTarget = address;
			}
			if (labelNameIndex >= 0) {
				/* @@NAME: record where a branch to this label lands, for the name applier. */
				labelNameTargets.put(labelNameIndex, branchTarget);
			}
			for (Address branch : branchAddresses) {
				contextreg.setBranchTarget(branch, branchTarget);
			}
		}

		@Override
		public String toString() {
			return blockKind + "@" + startAddress;
		}
	}

	// #region Exported pre-analysis results
	public static class StackEffect {
		private int popHeight; // Height of the stack *after* the pops
		private ValType[] toPop;
		private int pushHeight; // Height of the stack *before* the pushes
		private ValType[] toPush;

		public StackEffect(int popHeight, ValType[] toPop, int pushHeight, ValType[] toPush) {
			this.popHeight = popHeight;
			this.toPop = toPop;
			this.pushHeight = pushHeight;
			this.toPush = toPush;
		}

		public int getPopHeight() {
			return popHeight;
		}

		public ValType[] getToPop() {
			if (toPop == null) {
				return new ValType[0];
			}
			return toPop;
		}

		public int getPushHeight() {
			return pushHeight;
		}

		public ValType[] getToPush() {
			if (toPush == null) {
				return new ValType[0];
			}
			return toPush;
		}
	}

	public WasmFuncSignature getSignature() {
		return func;
	}

	/**
	 * Set the stack effect of this instruction - which types it pushes and pops.
	 * This is used to handle variable-argument instructions, which currently
	 * includes branch, call and return instructions. TODO: Ideally, these would be
	 * saved to the program context, which would save us from having to re-analyze
	 * functions when reopening the DB.
	 */
	private void setStackEffect(Address address, int popHeight, ValType[] toPop, int pushHeight, ValType[] toPush) {
		stackEffects.put(address, new StackEffect(popHeight, toPop, pushHeight, toPush));
	}

	public StackEffect getStackEffect(Address address) {
		return stackEffects.get(address);
	}
	// #endregion

	/**
	 * @@NAME: the address every label of the function's body branches to, keyed by the label's
	 * index in the extended name section (labels are numbered in the order the block/loop/if/try
	 * constructs appear in the body). A loop's label branches to the loop's start; every other
	 * construct's label branches to its {@code end}. Read by
	 * {@link WasmNameApplyAnalyzer} to turn label names into real Ghidra labels.
	 */
	public Map<Integer, Address> getLabelTargets() {
		return java.util.Collections.unmodifiableMap(labelNameTargets);
	}

	// #region BinaryReader utilities
	private static long readLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::unsigned);
	}

	private static long readSignedLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::signed);
	}

	/**
	 * Read a block type immediate: the empty type 0x40, a single- or multi-byte value type, or a
	 * non-negative s33 type index. The multi-byte {@code (ref null ht)} / {@code (ref ht)} value
	 * types (0x63/0x64) are consumed in full; previously only their first byte was read, which
	 * desynchronised the whole body.
	 */
	private static BlockType readBlockType(WasmAnalysis analysis, BinaryReader reader) throws IOException {
		ValType.BlockTypeInfo info = ValType.readBlockType(reader);
		if (info.typeIndex >= 0) {
			WasmFuncType type = analysis.getType((int) info.typeIndex);
			return new BlockType(type.getParamTypes(), type.getReturnTypes());
		}
		return new BlockType(info.type);
	}
	// #endregion

	// #region Value stack manipulation
	private void pushValue(Address instAddress, ValType type) {
		valueStack.add(type);
	}

	private ValType popValue(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		if (valueStack.size() <= curBlock.initialStack.size()) {
			/* If our stack is polymorphic, popping off an empty stack is ok */
			// @@UNIMP: same tolerance once the function contains an instruction whose
			// stack effect we could not model.
			// @@SS/@@STR/@@WA: and once it contains one of the modern proposal instructions
			// whose best-effort stack effect the frozen A05-A09 probes do not satisfy.
			if (curBlock.unreachable || hasUnimplementedOps || usesProposalOps)
				return null;
			throw new ValidationException(instAddress, "pop from empty stack");
		}
		return valueStack.remove(valueStack.size() - 1);
	}

	private ValType popValue(Address instAddress, ValType expected) {
		ValType actual = popValue(instAddress);
		// @@UNIMP: after an unmodelled instruction the types on the stack are a guess,
		// so a mismatch is tolerated instead of blanking the function.
		// A value whose type is a *subtype* of the expected type is accepted (e.g. a structref
		// where anyref is expected); numeric types only match themselves (see isSubtypeOf).
		if (actual != null && expected != null && !actual.isSubtypeOf(expected)
				&& !hasUnimplementedOps && !usesProposalOps) {
			throw new ValidationException(instAddress, "pop type mismatch: got " + actual + ", expected " + expected);
		}
		return actual;
	}

	private void pushValues(Address instAddress, ValType[] types) {
		for (int i = 0; i < types.length; i++) {
			pushValue(instAddress, types[i]);
		}
	}

	private ValType[] popValues(Address instAddress, ValType[] types) {
		ValType[] popped = new ValType[types.length];
		for (int i = types.length - 1; i >= 0; i--) {
			popped[i] = popValue(instAddress, types[i]);
		}
		return popped;
	}

	/**
	 * @@FR: pop one value, or return null if the stack is already at the current
	 * block's floor (instead of throwing). Used by the typed function-reference call
	 * instructions: the concrete referenced type $t is not modelled, so a callsite
	 * whose stack does not actually supply the reference's arguments (an under-typed
	 * body such as the frozen 12_call_ref probe) degrades a phantom argument to null
	 * rather than voiding the whole function.
	 */
	private ValType popValueTolerant(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		if (valueStack.size() <= curBlock.initialStack.size()) {
			return null;
		}
		return valueStack.remove(valueStack.size() - 1);
	}

	/**
	 * @@FR: pop the function reference (top of the operand stack) followed by the
	 * referenced type's arguments. Returns true only if every value was present, i.e.
	 * the recorded stack effect is trustworthy.
	 */
	private boolean popReferenceAndArgs(Address instAddress, ValType[] params) {
		boolean complete = popValueTolerant(instAddress) != null;
		for (int i = params.length - 1; i >= 0; i--) {
			if (popValueTolerant(instAddress) == null) {
				complete = false;
			}
		}
		return complete;
	}
	// #endregion

	// #region Control stack manipulation
	private void pushBlock(Address instAddress, ControlFrame block) {
		if (block.blockKind != BlockKind.FUNCTION && block.labelNameIndex < 0) {
			/* @@NAME: this construct introduces the next label of the function-wide index space. */
			block.labelNameIndex = labelCounter++;
		}
		controlStack.add(block);
		pushValues(instAddress, block.blockType.params);
	}

	private ControlFrame popBlock(Address instAddress) {
		if (controlStack.isEmpty()) {
			throw new ValidationException(instAddress, "pop from empty block stack");
		}
		ControlFrame block = getBlock(instAddress, 0);
		popValues(instAddress, block.blockType.returns);
		if (valueStack.size() != block.initialStack.size()) {
			// @@GC: a function body that leaves an extra operand behind (for example a GC
			// reference produced by struct.new/array.new that the (frozen) probe does not
			// consume) is technically invalid wasm, but we still want to disassemble the
			// whole function instead of blanking it out. This is only forgiven for the
			// outermost frame of a function that actually uses GC ops; every other block
			// and every non-GC function keeps strict validation.
			if (block.blockKind != BlockKind.FUNCTION || !usesGCOps) {
				// @@UNIMP: a leftover operand can also be a decode artefact of an
				// instruction this walker does not model; tolerate it rather than
				// blanking the whole function.
				// @@SS/@@STR/@@WA: same for the best-effort proposal instructions.
				if (!hasUnimplementedOps && !usesProposalOps) {
					throw new ValidationException(instAddress, "block end has wrong number of parameters");
				}
			}
			valueStack = new ArrayList<>(block.initialStack);
		}
		controlStack.remove(controlStack.size() - 1);
		return block;
	}

	private ControlFrame getBlock(Address instAddress, long labelidx) {
		if (labelidx >= controlStack.size()) {
			throw new ValidationException(instAddress, "invalid label index " + labelidx);
		}
		return controlStack.get(controlStack.size() - 1 - (int) labelidx);
	}

	/** Mark stack as polymorphic from this point to the end of the block */
	private void markUnreachable(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		valueStack = new ArrayList<>(curBlock.initialStack);
		curBlock.unreachable = true;
	}
	// #endregion

	// #region Common instruction code
	/**
	 * @@MM: read a memarg immediate. The flags/alignment field is a u32 LEB whose bit 6,
	 * when set (2^6 &lt;= n &lt; 2^7 after decoding, exactly as in the core spec), means a
	 * memory index follows before the offset. Modules that never set the flag (every
	 * single-memory module, i.e. all previously supported input) read exactly two LEBs,
	 * unchanged.
	 *
	 * @return the memory index the memarg addresses (0 when the memarg has no flags)
	 */
	private static long readMemarg(BinaryReader reader) throws IOException {
		long flags = readLeb128(reader); /* align / flags */
		long memidx = 0;
		if (flags >= 0x40 && flags < 0x80) {
			memidx = readLeb128(reader); /* memidx */
		}
		readLeb128(reader); /* offset */
		return memidx;
	}

	// @@M64 ---------------------------------------------------------------------
	// memory64: a memory's index type (i32 or i64) is a property of the *module*, not
	// of the instruction, so the decoder (SLEIGH) cannot see it. The walker therefore
	// looks the memory up in the module's memory declarations and records the operand
	// width in the context register (ctx_mem64, see WebAssembly.slaspec) at the address
	// of every memory instruction. SLEIGH then has one constructor per width code.
	//
	// The codes mirror the validation rules in the core spec (valid/instructions.html):
	//   load/store          : [at] -> [t]                    at = index type
	//   memory.size         : [] -> [at]
	//   memory.grow         : [at] -> [at]
	//   memory.fill  x      : [at i32 at] -> []
	//   memory.init  x y    : [at i32 i32] -> []
	//   memory.copy  x1 x2  : [at1 at2 min(at1,at2)] -> []
	private static final int MEM_CTX_I32 = 0;
	/** memory.copy with an i64 destination and an i32 source (length is the min, i32). */
	private static final int MEM_CTX_COPY_DST64 = 1;
	/** memory.copy with an i32 destination and an i64 source (length is the min, i32). */
	private static final int MEM_CTX_COPY_SRC64 = 2;
	/** i64 index type: every address/offset operand of the instruction is i64. */
	private static final int MEM_CTX_I64 = 3;

	/** The index type of linear memory {@code memidx}, from the module's memory declarations. */
	private static ValType memoryIndexType(WasmAnalysis analysis, long memidx) {
		WasmModule module = analysis.getModule();
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_MEMORY);
		WasmResizableLimits limits = null;
		if (memidx >= 0 && memidx < imports.size()) {
			limits = imports.get((int) memidx).getMemoryType();
		} else {
			List<WasmResizableLimits> memories = module.getNonImportedMemories();
			long local = memidx - imports.size();
			if (local >= 0 && local < memories.size()) {
				limits = memories.get((int) local);
			}
		}
		return (limits != null && limits.is64Bit()) ? ValType.i64 : ValType.i32;
	}

	/** Record the index type of one memory in the context register and return it. */
	private ValType setMemoryIndexContext(WasmAnalysis analysis, Address instAddress, long memidx) {
		ValType indexType = memoryIndexType(analysis, memidx);
		contextreg.setMemoryWidths(instAddress, indexType == ValType.i64 ? MEM_CTX_I64 : MEM_CTX_I32);
		return indexType;
	}

	/** memory.copy x1 x2: the three operands are typed at1, at2, min(at1,at2). */
	private void setMemoryCopyContext(Address instAddress, ValType dstType, ValType srcType) {
		int code;
		if (dstType == ValType.i64 && srcType == ValType.i64) {
			code = MEM_CTX_I64;
		} else if (dstType == ValType.i64) {
			code = MEM_CTX_COPY_DST64;
		} else if (srcType == ValType.i64) {
			code = MEM_CTX_COPY_SRC64;
		} else {
			code = MEM_CTX_I32;
		}
		contextreg.setMemoryWidths(instAddress, code);
	}

	private void memoryLoad(WasmAnalysis analysis, BinaryReader reader, Address instAddress, ValType destType) throws IOException {
		ValType indexType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
		popValue(instAddress, indexType);
		pushValue(instAddress, destType);
	}

	private void memoryStore(WasmAnalysis analysis, BinaryReader reader, Address instAddress, ValType destType) throws IOException {
		ValType indexType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
		popValue(instAddress, destType);
		popValue(instAddress, indexType);
	}
	// @@M64 end

	/**
	 * catch / catch_all: like else, the instruction ends the try body (or the previous handler) with a branch to the
	 * end of the try. The handler that follows starts with the try's initial stack plus the exception's payload. The
	 * try instruction dispatches to its first handler only; later handlers are reached by exceptions alone.
	 */
	private void beginHandler(Address instAddress, Address handlerStart, ValType[] payload) {
		ControlFrame block = popBlock(instAddress);
		if (block.blockKind != BlockKind.TRY && block.blockKind != BlockKind.CATCH) {
			throw new ValidationException(instAddress, "catch without matching try");
		}
		block.addBranch(instAddress);
		if (!block.hasHandler) {
			block.hasHandler = true;
			contextreg.setBranchTarget(block.startAddress, handlerStart);
			contextreg.setTryHandler(block.startAddress);
			if (payload.length == 1 && block.blockType.params.length == 0 && payload[0].getSize() <= 8) {
				contextreg.setOperandSize(block.startAddress, payload[0]);
			}
		}
		block.blockKind = BlockKind.CATCH;
		block.unreachable = false;
		controlStack.add(block);
		pushValues(instAddress, payload);
	}

	private ValType[] tagPayload(WasmAnalysis analysis, long tagidx) {
		WasmFuncType tagType = tagTypeAt(analysis, tagidx);
		return tagType == null ? new ValType[0] : tagType.getParamTypes();
	}

	// @@EH begin: new exception handling (try_table / throw_ref) bridge, used by EH2Ops.
	// Thin wrappers over the control-frame machinery above, kept in one block so that the legacy
	// exception handling (and everything else) is untouched. See wasm/analysis/EH2Ops.java.

	/** The number of params of a blocktype, without entering the block. */
	int ehBlockTypeParamCount(WasmAnalysis analysis, long blocktype) {
		return new BlockType(analysis, blocktype).params.length;
	}

	/**
	 * The types a catch clause must push to be valid: the branch arguments of the label it branches
	 * to. Must be called while the control stack is still the one *outside* the try_table, because
	 * catch labels are resolved in the enclosing context (see the spec's Catch_ok rule, and
	 * {@link EH2Ops#analyzeTryTable}).
	 */
	ValType[] ehClauseLabelTypes(Address instAddress, long labelidx) {
		return getBlock(instAddress, labelidx).getBranchArguments();
	}

	/**
	 * Enter a try_table block. Like {@code block}, the blocktype's params are consumed and pushed
	 * back; the body's branches to this label resolve to the block's end.
	 *
	 * @param handlerLabel label index (in the enclosing context) of the first catch clause, or -1
	 *            when the try_table has no clause
	 * @param handlerValue the single value that first clause pushes at its handler (so the
	 *            decompiler can show it as the caught exception), or null to push none
	 */
	void ehEnterTryTable(Address instAddress, WasmAnalysis analysis, long blocktype, long handlerLabel, ValType handlerValue) {
		/*
		 * Model the exception dispatch before pushing the frame, so that handlerLabel is resolved
		 * against the enclosing control stack (as the spec requires); the try_table instruction
		 * branches to the label's target when an exception is caught, like legacy try does to its
		 * first handler.
		 */
		if (handlerLabel >= 0) {
			ControlFrame target = getBlock(instAddress, handlerLabel);
			target.addBranch(instAddress);
			contextreg.setTryHandler(instAddress);
			if (handlerValue != null && handlerValue.getSize() <= 8) {
				contextreg.setOperandSize(instAddress, handlerValue);
			}
		}
		BlockType type = new BlockType(analysis, blocktype);
		popValues(instAddress, type.params);
		pushBlock(instAddress, new ControlFrame(instAddress, BlockKind.BLOCK, type, valueStack));
	}

	/** Mark the instruction at {@code instAddress} as a try_table catch clause directive. */
	void ehMarkClause(Address instAddress) {
		contextreg.setEhClause(instAddress);
	}

	/** throw_ref: pop an exnref and end the current block, exactly like legacy throw/rethrow. */
	void ehThrowRef(Address instAddress) {
		popValue(instAddress, ValType.exnref);
		markUnreachable(instAddress);
	}
	// @@EH end

	/** The value type of an atomic read-modify-write group member: i32, i64, i32 8u, i32 16u, i64 8u, i64 16u, i64 32u. */
	private static ValType atomicType(int member) {
		return (member == 0 || member == 2 || member == 3) ? ValType.i32 : ValType.i64;
	}

	private void unaryOp(Address instAddress, ValType srcType, ValType destType) {
		popValue(instAddress, srcType);
		pushValue(instAddress, destType);
	}

	private void binaryOp(Address instAddress, ValType srcType, ValType destType) {
		popValue(instAddress, srcType);
		popValue(instAddress, srcType);
		pushValue(instAddress, destType);
	}

	// #endregion

	// @@GC ---------------------------------------------------------------------
	// Set when the current function contains at least one 0xFB GC instruction. Used
	// only to decide whether a leftover operand at the function's final `end` is
	// forgiven (see popBlock): a GC reference left on the stack is a decode artefact
	// we tolerate, while non-GC functions keep strict end-of-block validation.
	private boolean usesGCOps;

	void gcMarkPresent() {
		usesGCOps = true;
	}

	// Bridge methods used by GCOps so that all 0xFB GC instruction handling lives in
	// one new file (wasm.analysis.GCOps) without exposing this class's private
	// value stack / context register.
	ValType gcPop(Address instAddress) {
		return popValue(instAddress);
	}

	ValType gcPop(Address instAddress, ValType expected) {
		return popValue(instAddress, expected);
	}

	void gcPush(Address instAddress, ValType type) {
		pushValue(instAddress, type);
	}

	void gcSetOperandSize(Address instAddress, ValType type) {
		contextreg.setOperandSize(instAddress, type);
	}

	/**
	 * br_on_cast / br_on_cast_fail: a conditional branch on a reference, modelled
	 * like br_if. It pops the cast reference and leaves a (cast) reference on the
	 * fall-through path. Exact cast typing / nullability refinement is not modelled.
	 */
	void gcConditionalRefBranch(Address instAddress, long labelidx, ValType ref) {
		popValue(instAddress);
		ControlFrame block = getBlock(instAddress, labelidx);
		block.addBranch(instAddress);
		pushValue(instAddress, ref);
	}
	// @@GC ---------------------------------------------------------------------

	// @@UNIMP -----------------------------------------------------------------
	// Graceful degradation for opcodes this walker does not model yet (R1.1).
	//
	// An opcode whose immediate operands are consumed with the wrong length shifts
	// the whole byte stream and can blank out the function. skipUnimplementedOperands()
	// therefore consumes exactly as many bytes as the matching `:unimplemented` SLEIGH
	// constructor does. After the @@SS/@@STR/@@WA work this is only the unassigned
	// 0xFB stringref-range sub-opcodes (no operands) and opcodes outside every known
	// range; where the operand length is genuinely unknown nothing is consumed
	// ("fail safe"): the byte stays undefined and the rest of the function still
	// decodes.
	//
	// After such an instruction the value-stack model is unreliable, so validation
	// is relaxed instead of throwing away the whole function (see popValue /
	// popBlock / analyzeFunction) and unknown operand widths degrade to 32-bit.
	// (The modelled proposal instructions use the parallel `usesProposalOps` flag.)
	private boolean hasUnimplementedOps;

	private void markUnimplemented() {
		hasUnimplementedOps = true;
	}

	/** 0xFB sub-opcode 0x00..0x1e is a (modelled) GC instruction, owned by GCOps. */
	private static boolean isGCOpcode(int sub) {
		return sub <= 0x1E;
	}

	/**
	 * Consume the immediate operands of an opcode that has no decoder yet, exactly as the
	 * matching `:unimplemented` SLEIGH constructors do.
	 *
	 * <p>After the stack-switching / stringref / wide-arithmetic work (@@SS/@@STR/@@WA) this is
	 * only reached for opcodes that are still fallbacks: the unassigned 0xFB sub-opcodes inside
	 * the stringref range (0x80..0xB7, no immediates, rendered as `unimplemented ... (reserved)`)
	 * and any opcode outside every known range (0xE7+, unassigned 0xFC/0xFD/0xFE sub-opcodes,
	 * ...), where the length is unknown and nothing is consumed ("fail safe": the byte stays
	 * undefined and the rest of the function still decodes).
	 *
	 * @return true if the operands were consumed (the length is known), false if the length is
	 *         unknown - in which case nothing has been consumed
	 */
	private static boolean skipUnimplementedOperands(BinaryReader reader, int opcode, long sub) throws IOException {
		switch (opcode) {
		case 0xFB: /* reserved JS string builtins / stringref sub-opcodes (0x80..0xB7, no operands) */
			return sub >= 0x80 && sub <= 0xB7;
		default:
			return false;
		}
	}

	private void warnUnimplemented(Address instAddress, int opcode, String detail, boolean consumed) {
		Msg.warn(this, "Unimplemented opcode " + String.format("0x%02x", opcode) + detail + " at " + instAddress
				+ (consumed ? " (operands skipped, no semantics modelled)"
						: " (operand length unknown; not consuming following bytes)"));
	}
	// @@UNIMP end

	// @@SS/@@STR/@@WA -----------------------------------------------------------
	// Stack switching (0xE0-0xE6), JS string builtins (0xFB 0x80..0xB7) and wide arithmetic /
	// memory.discard (0xFC 0x12-0x16). These opcodes are decoded for real (data/StackSwitchOps.sinc,
	// StringOps.sinc, WideArithOps.sinc) and their stack effect is modelled here. Their semantics
	// are not implemented: each becomes a dedicated callother in the decompiler.
	//
	// A handful of the frozen A05-A09 probes (written for the old `unimplemented` fallback) do not
	// actually supply the operands these instructions consume. To keep those bodies disassembling,
	// the presence of such an instruction relaxes validation exactly like an unmodelled one
	// (see popValue / popBlock) - but the instruction itself is *not* marked unimplemented, so the
	// listing shows the real mnemonic. A valid module still gets the exact effect.
	private boolean usesProposalOps;

	private void markProposalOp() {
		usesProposalOps = true;
	}

	/** The function type a type index refers to, or null when the index is out of range. */
	private WasmFuncType typeAt(WasmAnalysis analysis, long typeidx) {
		if (typeidx < 0 || typeidx > Integer.MAX_VALUE) {
			return null;
		}
		try {
			return analysis.getType((int) typeidx);
		} catch (RuntimeException e) {
			return null;
		}
	}

	/** The function type of a tag index, or null when the index is out of range. */
	private WasmFuncType tagTypeAt(WasmAnalysis analysis, long tagidx) {
		if (tagidx < 0 || tagidx > Integer.MAX_VALUE) {
			return null;
		}
		try {
			return analysis.getTagType((int) tagidx);
		} catch (RuntimeException e) {
			return null;
		}
	}

	/** Code the number of modelled callother inputs/outputs: (p>0?1:0)*2 + (r>0?1:0). */
	private static int ssShape(ValType[] params, ValType[] results) {
		int p = (params != null && params.length > 0) ? 1 : 0;
		int r = (results != null && results.length > 0) ? 1 : 0;
		return p * 2 + r;
	}

	private static ValType[] orEmpty(ValType[] types) {
		return types != null ? types : new ValType[0];
	}

	/** cont.new $ct: [(ref null $ft)] -> [(ref $ct)]. */
	private void contNew(Address instAddress) {
		markProposalOp();
		popValue(instAddress); /* the function reference */
		pushValue(instAddress, ValType.contref);
	}

	/**
	 * cont.bind $ct $ct': [t3* (ref null $ct)] -> [(ref $ct')]. The bound prefix t3* has
	 * |params($ct)| - |params($ct')| values (both type indices name the continuation's function
	 * type; a `cont` composite type itself cannot appear in the type section without a loader
	 * change, see REPORT-H5.md).
	 */
	private void contBind(Address instAddress, WasmAnalysis analysis, long t1, long t2) {
		markProposalOp();
		WasmFuncType ct = typeAt(analysis, t1);
		WasmFuncType ct2 = typeAt(analysis, t2);
		int bound = 0;
		if (ct != null && ct2 != null) {
			bound = ct.getParamTypes().length - ct2.getParamTypes().length;
			if (bound < 0) {
				bound = 0;
			}
		}
		popValue(instAddress); /* (ref null $ct) */
		for (int i = 0; i < bound; i++) {
			popValue(instAddress); /* t3* */
		}
		pushValue(instAddress, ValType.contref);
		contextreg.setSsShape(instAddress, bound > 0 ? 1 : 0);
	}

	/** suspend $tag: [t1*] -> [t2*] (the tag's parameter and result lists). */
	private void suspend(Address instAddress, WasmAnalysis analysis, long tagidx) {
		markProposalOp();
		WasmFuncType tag = tagTypeAt(analysis, tagidx);
		ValType[] params = tag != null ? tag.getParamTypes() : null;
		ValType[] results = tag != null ? tag.getReturnTypes() : null;
		popValues(instAddress, orEmpty(params));
		pushValues(instAddress, orEmpty(results));
		contextreg.setSsShape(instAddress, ssShape(params, results));
	}

	/** resume $ct hdl*: [t1* (ref null $ct)] -> [t2*]. */
	private void resume(Address instAddress, WasmAnalysis analysis, long typeidx) {
		markProposalOp();
		WasmFuncType ct = typeAt(analysis, typeidx);
		ValType[] params = ct != null ? ct.getParamTypes() : null;
		ValType[] results = ct != null ? ct.getReturnTypes() : null;
		popValue(instAddress); /* (ref null $ct) */
		popValues(instAddress, orEmpty(params));
		pushValues(instAddress, orEmpty(results));
		contextreg.setSsShape(instAddress, ssShape(params, results));
	}

	/** resume_throw $ct $e hdl*: [te* (ref null $ct)] -> [t2*], te* = the tag's parameters. */
	private void resumeThrow(Address instAddress, WasmAnalysis analysis, long typeidx, long tagidx) {
		markProposalOp();
		WasmFuncType ct = typeAt(analysis, typeidx);
		WasmFuncType tag = tagTypeAt(analysis, tagidx);
		ValType[] params = tag != null ? tag.getParamTypes() : null;
		ValType[] results = ct != null ? ct.getReturnTypes() : null;
		popValue(instAddress); /* (ref null $ct) */
		popValues(instAddress, orEmpty(params));
		pushValues(instAddress, orEmpty(results));
		contextreg.setSsShape(instAddress, ssShape(params, results));
	}

	/** resume_throw_ref $ct hdl*: [exnref (ref null $ct)] -> [t2*]. */
	private void resumeThrowRef(Address instAddress, WasmAnalysis analysis, long typeidx) {
		markProposalOp();
		WasmFuncType ct = typeAt(analysis, typeidx);
		ValType[] results = ct != null ? ct.getReturnTypes() : null;
		popValue(instAddress); /* (ref null $ct) */
		popValue(instAddress, ValType.exnref);
		pushValues(instAddress, orEmpty(results));
		contextreg.setSsShape(instAddress, ((results != null && results.length > 0) ? 1 : 0));
	}

	/** switch $ct1 $t: [t1* (ref null $ct1)] -> [t2*] (t2* reduced here to the tag's results). */
	private void switchOp(Address instAddress, WasmAnalysis analysis, long typeidx, long tagidx) {
		markProposalOp();
		WasmFuncType ct = typeAt(analysis, typeidx);
		WasmFuncType tag = tagTypeAt(analysis, tagidx);
		ValType[] params = ct != null ? ct.getParamTypes() : null;
		ValType[] results = tag != null ? tag.getReturnTypes() : null;
		popValue(instAddress); /* (ref null $ct1) */
		popValues(instAddress, orEmpty(params));
		pushValues(instAddress, orEmpty(results));
		contextreg.setSsShape(instAddress, ssShape(params, results));
	}

	/**
	 * resume / resume_throw / resume_throw_ref: consume the trailing handler vector
	 * {@code vec(on <tag> <label> | on <tag> switch)}. Each clause is marked as its own byte-only
	 * directive instruction (SLEIGH {@code :.ss_handler}, DIRECTIVE_SS_HANDLER), like try_table's
	 * catch clauses, so the listing names the tags/labels and the body starts exactly after the
	 * vector. The clauses are not turned into branch targets: a suspend is a run-time event, not a
	 * static branch.
	 */
	private void readHandlerVector(BinaryReader reader, Address instAddress) throws IOException {
		Address functionStart = func.getStartAddr();
		long count = readLeb128(reader);
		for (long i = 0; i < count; i++) {
			Address clauseAddress = functionStart.add(reader.getPointerIndex());
			int kind = reader.readNextUnsignedByte();
			if (kind == 0x00) { /* on <tag> <label> */
				readLeb128(reader);
				readLeb128(reader);
			} else if (kind == 0x01) { /* on <tag> switch */
				readLeb128(reader);
			} else {
				Msg.warn(this, "Invalid stack-switching handler clause kind " + String.format("0x%02x", kind)
						+ " at " + clauseAddress + " (rest of body not decoded)");
				markUnimplemented();
				return;
			}
			contextreg.setSsHandler(clauseAddress);
		}
	}

	/**
	 * The JS string builtins / stringref instructions (0xFB 0x80..0xB7). The sub-opcode has already
	 * been consumed by the caller; this consumes the instruction's immediate (a bare memidx or a
	 * string index) and applies the stringref proposal's stack effect.
	 *
	 * @return true if the sub-opcode is modelled (so the caller does not fall back to
	 *         `unimplemented`), false for a reserved/unassigned sub-opcode
	 */
	private boolean stringBuiltin(WasmAnalysis analysis, BinaryReader reader, Address instAddress, int sub)
			throws IOException {
		switch (sub) {
		/* [ptr:address i32] -> [stringref] */
		case 0x80: case 0x81: case 0x8B: case 0x8C:
			readLeb128(reader); /* memidx */
			markProposalOp();
			popValue(instAddress, ValType.i32); /* byte/code-unit count */
			popValue(instAddress, ValType.i32); /* memory pointer */
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [stringref ptr:address] -> [i32] */
		case 0x86: case 0x87: case 0x8D: case 0x8E:
			readLeb128(reader); /* memidx */
			markProposalOp();
			popValue(instAddress, ValType.i32); /* memory pointer */
			popValue(instAddress); /* stringref */
			pushValue(instAddress, ValType.i32);
			return true;
		/* [] -> [stringref] */
		case 0x82:
			readLeb128(reader); /* stringidx */
			markProposalOp();
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [stringref] -> [i32] */
		case 0x83: case 0x84: case 0x85: case 0x8A:
			markProposalOp();
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [stringref stringref] -> [i32] (eq) / [stringref] (concat) */
		case 0x88:
			markProposalOp();
			popValue(instAddress);
			popValue(instAddress);
			pushValue(instAddress, ValType.stringref);
			return true;
		case 0x89:
			markProposalOp();
			popValue(instAddress);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [stringref] -> [stringview] (the stringview result shares the stringref placeholder) */
		case 0x90: case 0x98: case 0xA0:
			markProposalOp();
			popValue(instAddress);
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [view i32 i32] -> [i32] */
		case 0x91:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [view i32 i32] -> [stringref] */
		case 0x93: case 0x9C:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [view ptr:address i32 i32] -> [i32 i32] */
		case 0x92: case 0x94: case 0x95:
			readLeb128(reader); /* memidx */
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [view] -> [i32] */
		case 0x99: case 0xA1:
			markProposalOp();
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [view i32] -> [i32] */
		case 0x9A: case 0xA2: case 0xA3:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [view i32] -> [stringref] */
		case 0xA4:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [view ptr:address i32 i32] -> [i32] */
		case 0x9B:
			readLeb128(reader); /* memidx */
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		/* [array i32 i32] -> [stringref] */
		case 0xB0: case 0xB1: case 0xB4: case 0xB5:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			pushValue(instAddress, ValType.stringref);
			return true;
		/* [stringref array i32] -> [i32] */
		case 0xB2: case 0xB3: case 0xB6: case 0xB7:
			markProposalOp();
			popValue(instAddress, ValType.i32);
			popValue(instAddress);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			return true;
		default:
			return false;
		}
	}
	// @@SS/@@STR/@@WA end


	private void analyzeOpcode(WasmAnalysis analysis, Address instAddress, BinaryReader reader) throws IOException {
		contextreg.setStackPointer(instAddress, valueStack.size());
		int opcode = reader.readNextUnsignedByte();
		switch (opcode) {
		case 0x00: /* unreachable */
			markUnreachable(instAddress);
			break;
		case 0x01: /* nop */
			break;

		case 0x02: /* block bt */ {
			BlockType blocktype = readBlockType(analysis, reader);
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.BLOCK, blocktype, valueStack));
			break;
		}
		case 0x03: /* loop bt */ {
			BlockType blocktype = readBlockType(analysis, reader);
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.LOOP, blocktype, valueStack));
			break;
		}
		case 0x04: /* if bt */ {
			BlockType blocktype = readBlockType(analysis, reader);
			popValue(instAddress, ValType.i32);
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.IF, blocktype, valueStack));
			break;
		}
		case 0x05: /* else */ {
			ControlFrame block = popBlock(instAddress);
			if (block.blockKind != BlockKind.IF) {
				throw new ValidationException(instAddress, "else without matching if");
			}

			/*
			 * The else instruction itself serves as a branch to the end of the block. The
			 * branch from the if instruction will go to the instruction after the else.
			 */
			block.addBranch(instAddress);
			block.setElse(instAddress);

			block.unreachable = false;
			pushBlock(instAddress, block);
			break;
		}
		case 0x06: /* try bt (legacy exception handling) */ {
			/* Multi-byte block signatures are not decoded here: the SLEIGH :try constructors still
			   read a single ULeb128, so both sides must stay on the single-s33 form. */
			BlockType blocktype = new BlockType(analysis, readSignedLeb128(reader));
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.TRY, blocktype, valueStack));
			break;
		}
		case 0x07: /* catch x */ {
			ValType[] payload = tagPayload(analysis, readLeb128(reader));
			beginHandler(instAddress, func.getStartAddr().add(reader.getPointerIndex()), payload);
			break;
		}
		case 0x19: /* catch_all */ {
			beginHandler(instAddress, func.getStartAddr().add(reader.getPointerIndex()), new ValType[0]);
			break;
		}
		case 0x08: /* throw x */ {
			ValType[] payload = tagPayload(analysis, readLeb128(reader));
			if (payload.length == 1 && payload[0].getSize() <= 8) {
				contextreg.setOperandSize(instAddress, payload[0]);
			}
			popValues(instAddress, payload);
			markUnreachable(instAddress);
			break;
		}
		case 0x09: /* rethrow l */ {
			readLeb128(reader);
			markUnreachable(instAddress);
			break;
		}
		case 0x18: /* delegate l: ends a try like end; its exceptions go to an outer handler */ {
			readLeb128(reader);
			ControlFrame block = popBlock(instAddress);
			if (block.blockKind != BlockKind.TRY) {
				throw new ValidationException(instAddress, "delegate without matching try");
			}
			pushValues(instAddress, block.blockType.returns);
			block.setEnd(instAddress);
			break;
		}

		/* @@EH: new exception handling (proposal) is handled by EH2Ops; try_table is a block. */
		case 0x1F: /* try_table bt catch* */ {
			EH2Ops.analyzeTryTable(this, analysis, instAddress, reader);
			break;
		}
		case 0x0A: /* throw_ref */ {
			EH2Ops.analyzeThrowRef(this, instAddress);
			break;
		}

		case 0x0B: /* end */ {
			ControlFrame block = popBlock(instAddress);
			// this stack effect will only be used by the final end
			setStackEffect(instAddress, valueStack.size(), block.blockType.returns, 0, null);
			pushValues(instAddress, block.blockType.returns);
			block.setEnd(instAddress);
			if (controlStack.isEmpty()) {
				contextreg.setIsReturn(instAddress, 1);
			}
			break;
		}

		case 0x0C: /* br l */ {
			long labelidx = readLeb128(reader);

			ControlFrame block = getBlock(instAddress, labelidx);
			ValType[] arguments = block.getBranchArguments();
			popValues(instAddress, arguments);
			setStackEffect(instAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
			block.addBranch(instAddress);

			markUnreachable(instAddress);
			break;
		}
		case 0x0D: /* br_if l */ {
			long labelidx = readLeb128(reader);
			popValue(instAddress, ValType.i32);

			ControlFrame block = getBlock(instAddress, labelidx);
			ValType[] arguments = block.getBranchArguments();
			popValues(instAddress, arguments);
			setStackEffect(instAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
			block.addBranch(instAddress);
			pushValues(instAddress, arguments);

			break;
		}
		case 0x0E: /* br_table l* l */ {
			long count = readLeb128(reader);
			popValue(instAddress, ValType.i32);
			for (int i = 0; i < count + 1; i++) {
				Address caseAddress = func.getStartAddr().add(reader.getPointerIndex());
				long labelidx = readLeb128(reader);

				if (i >= MAX_BR_TABLE_CASES) {
					// @@BRTABLE_CAP: bound the control-flow graph. The label bytes are consumed
					// by a byte-only directive (no branch, no block) so the stream stays aligned,
					// but we do not model the branch or touch the value stack.
					if (i == MAX_BR_TABLE_CASES) {
						Msg.warn(this, "br_table at " + instAddress + " has " + (count + 1)
								+ " labels; only the first " + MAX_BR_TABLE_CASES
								+ " are modelled as branches (the rest are decoded without control flow)");
					}
					contextreg.setBrTableCaseIgnored(caseAddress);
					continue;
				}

				contextreg.setBrTableCase(caseAddress, (i < count) ? i : -1);
				ControlFrame block = getBlock(caseAddress, labelidx);
				ValType[] arguments = block.getBranchArguments();
				ValType[] actualArgs = popValues(caseAddress, arguments);
				setStackEffect(caseAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
				block.addBranch(caseAddress);
				if (i < count) {
					pushValues(caseAddress, actualArgs);
				}
			}
			markUnreachable(instAddress);
			break;
		}
		case 0x0F: /* return */ {
			popValues(instAddress, func.getReturns());
			setStackEffect(instAddress, valueStack.size(), func.getReturns(), 0, null);
			markUnreachable(instAddress);
			break;
		}
		case 0x10: /* call x */ {
			long funcidx = readLeb128(reader);
			WasmFuncSignature targetFunc = analysis.getFunction((int) funcidx);
			ValType[] params = targetFunc.getParams();
			ValType[] returns = targetFunc.getReturns();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
			contextreg.setBranchTarget(instAddress, targetFunc.getStartAddr());
			pushValues(instAddress, returns);
			break;
		}
		case 0x11: /* call_indirect x y */ {
			long typeidx = readLeb128(reader);
			long tableidx = readLeb128(reader);
			if (analysis.getTableType((int) tableidx) != ValType.funcref) {
				throw new ValidationException(instAddress, "call_indirect does not reference a function table");
			}
			WasmFuncType type = analysis.getType((int) typeidx);

			popValue(instAddress, ValType.i32);
			ValType[] params = type.getParamTypes();
			ValType[] returns = type.getReturnTypes();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
			pushValues(instAddress, returns);
			break;
		}

		case 0x12: /* return_call x (tail calls) */ {
			long funcidx = readLeb128(reader);
			WasmFuncSignature targetFunc = analysis.getFunction((int) funcidx);
			ValType[] params = targetFunc.getParams();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), targetFunc.getReturns());
			contextreg.setBranchTarget(instAddress, targetFunc.getStartAddr());
			markUnreachable(instAddress);
			break;
		}
		case 0x13: /* return_call_indirect x y */ {
			long typeidx = readLeb128(reader);
			long tableidx = readLeb128(reader);
			if (analysis.getTableType((int) tableidx) != ValType.funcref) {
				throw new ValidationException(instAddress, "return_call_indirect does not reference a function table");
			}
			WasmFuncType type = analysis.getType((int) typeidx);
			popValue(instAddress, ValType.i32);
			ValType[] params = type.getParamTypes();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), type.getReturnTypes());
			markUnreachable(instAddress);
			break;
		}

		/*
		 * @@FR: typed function references (proposal: function-references). call_ref /
		 * return_call_ref pop the function reference (the top operand-stack value, like
		 * the table index of call_indirect) and then the arguments described by the type
		 * index, and push that type's results.
		 *
		 * The reference is read directly from the stack by the SLEIGH `sp1_32` operand,
		 * so only the arguments are recorded in the stack effect (they are what
		 * InjectPayloadWasmPop moves into the input registers). The concrete referenced
		 * type $t is not represented (ValType folds all (ref [null] $t) onto a 4-byte
		 * reference placeholder), so the popped reference is accepted as any type.
		 *
		 * No branch target is recorded: call_ref's callee is a runtime value. When that
		 * value is a resolved function address (ref.func / table.get) the decompiler still
		 * shows a real call through it.
		 */
		case 0x14: /* call_ref x */ {
			long typeidx = readLeb128(reader);
			WasmFuncType type = analysis.getType((int) typeidx);
			ValType[] params = type.getParamTypes();
			ValType[] returns = type.getReturnTypes();
			if (popReferenceAndArgs(instAddress, params)) {
				setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
			}
			pushValues(instAddress, returns);
			break;
		}
		case 0x15: /* return_call_ref x (tail calls through a typed reference) */ {
			long typeidx = readLeb128(reader);
			WasmFuncType type = analysis.getType((int) typeidx);
			ValType[] params = type.getParamTypes();
			if (popReferenceAndArgs(instAddress, params)) {
				setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), type.getReturnTypes());
			}
			markUnreachable(instAddress);
			break;
		}

		case 0x1A: /* drop */ {
			popValue(instAddress);
			break;
		}
		case 0x1B: /* select */ {
			popValue(instAddress, ValType.i32);
			ValType t1 = popValue(instAddress);
			ValType t2 = popValue(instAddress);
			if (t1 != null && t2 != null && t1 != t2) {
				throw new ValidationException(instAddress, "inconsistent types in select");
			}
			ValType resultType = (t1 != null) ? t1 : t2;
			contextreg.setOperandSize(instAddress, resultType);
			pushValue(instAddress, resultType);
			break;
		}
		case 0x1C: /* select t */ {
			long count = readLeb128(reader);
			if (count != 1) {
				throw new ValidationException(instAddress, "only select t is supported");
			}
			ValType t = ValType.readFromReader(reader);
			popValue(instAddress, ValType.i32);
			popValue(instAddress, t);
			popValue(instAddress, t);
			pushValue(instAddress, t);
			break;
		}

		case 0x20: /* local.get x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x21: /* local.set x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			popValue(instAddress, type);
			break;
		}
		case 0x22: /* local.tee x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			popValue(instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x23: /* global.get x */ {
			long globalidx = readLeb128(reader);
			ValType type = analysis.getGlobalType((int) globalidx);
			contextreg.setOperandSize(instAddress, type);
			globalGetSets.put(instAddress, globalidx);
			pushValue(instAddress, type);
			break;
		}
		case 0x24: /* global.set x */ {
			long globalidx = readLeb128(reader);
			ValType type = analysis.getGlobalType((int) globalidx);
			contextreg.setOperandSize(instAddress, type);
			globalGetSets.put(instAddress, globalidx);
			popValue(instAddress, type);
			break;
		}

		case 0x25: /* table.get x */ {
			long tableidx = readLeb128(reader);
			ValType type = analysis.getTableType((int) tableidx);
			popValue(instAddress, ValType.i32);
			pushValue(instAddress, type);
			break;
		}
		case 0x26: /* table.set x */ {
			long tableidx = readLeb128(reader);
			ValType type = analysis.getTableType((int) tableidx);
			popValue(instAddress, type);
			popValue(instAddress, ValType.i32);
			break;
		}

		case 0x28: /* i32.load memarg */
		case 0x2C: /* i32.load8_s memarg */
		case 0x2D: /* i32.load8_u memarg */
		case 0x2E: /* i32.load16_s memarg */
		case 0x2F: /* i32.load16_u memarg */
			memoryLoad(analysis, reader, instAddress, ValType.i32);
			break;
		case 0x29: /* i64.load memarg */
		case 0x30: /* i64.load8_s memarg */
		case 0x31: /* i64.load8_u memarg */
		case 0x32: /* i64.load16_s memarg */
		case 0x33: /* i64.load16_u memarg */
		case 0x34: /* i64.load32_s memarg */
		case 0x35: /* i64.load32_u memarg */
			memoryLoad(analysis, reader, instAddress, ValType.i64);
			break;
		case 0x2A: /* f32.load memarg */
			memoryLoad(analysis, reader, instAddress, ValType.f32);
			break;
		case 0x2B: /* f64.load memarg */
			memoryLoad(analysis, reader, instAddress, ValType.f64);
			break;

		case 0x36: /* i32.store memarg */
		case 0x3A: /* i32.store8 memarg */
		case 0x3B: /* i32.store16 memarg */
			memoryStore(analysis, reader, instAddress, ValType.i32);
			break;
		case 0x37: /* i64.store memarg */
		case 0x3C: /* i64.store8 memarg */
		case 0x3D: /* i64.store16 memarg */
		case 0x3E: /* i64.store32 memarg */
			memoryStore(analysis, reader, instAddress, ValType.i64);
			break;
		case 0x38: /* f32.store memarg */
			memoryStore(analysis, reader, instAddress, ValType.f32);
			break;
		case 0x39: /* f64.store memarg */
			memoryStore(analysis, reader, instAddress, ValType.f64);
			break;

		case 0x3F: /* memory.size */ {
			/* @@M64: the result is the memory's index type. */
			ValType indexType = setMemoryIndexContext(analysis, instAddress, readLeb128(reader)); /* memidx */
			pushValue(instAddress, indexType);
			break;
		}
		case 0x40: /* memory.grow */ {
			/* @@M64: both the delta and the result are the memory's index type. */
			ValType indexType = setMemoryIndexContext(analysis, instAddress, readLeb128(reader)); /* memidx */
			popValue(instAddress, indexType);
			pushValue(instAddress, indexType);
			break;
		}

		case 0x41: /* i32.const i32 */ {
			readSignedLeb128(reader); /* value */
			pushValue(instAddress, ValType.i32);
			break;
		}
		case 0x42: /* i64.const i64 */ {
			readSignedLeb128(reader); /* value */
			pushValue(instAddress, ValType.i64);
			break;
		}
		case 0x43: /* f32.const f32 */ {
			reader.readNextByteArray(4); /* value */
			pushValue(instAddress, ValType.f32);
			break;
		}
		case 0x44: /* f64.const f64 */ {
			reader.readNextByteArray(8); /* value */
			pushValue(instAddress, ValType.f64);
			break;
		}

		case 0x45: /* i32.eqz */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x46: /* i32.eq */
		case 0x47: /* i32.ne */
		case 0x48: /* i32.lt_s */
		case 0x49: /* i32.lt_u */
		case 0x4A: /* i32.gt_s */
		case 0x4B: /* i32.gt_u */
		case 0x4C: /* i32.le_s */
		case 0x4D: /* i32.le_u */
		case 0x4E: /* i32.ge_s */
		case 0x4F: /* i32.ge_u */
			binaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x50: /* i64.eqz */
			unaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0x51: /* i64.eq */
		case 0x52: /* i64.ne */
		case 0x53: /* i64.lt_s */
		case 0x54: /* i64.lt_u */
		case 0x55: /* i64.gt_s */
		case 0x56: /* i64.gt_u */
		case 0x57: /* i64.le_s */
		case 0x58: /* i64.le_u */
		case 0x59: /* i64.ge_s */
		case 0x5A: /* i64.ge_u */
			binaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0x5B: /* f32.eq */
		case 0x5C: /* f32.ne */
		case 0x5D: /* f32.lt */
		case 0x5E: /* f32.gt */
		case 0x5F: /* f32.le */
		case 0x60: /* f32.ge */
			binaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0x61: /* f64.eq */
		case 0x62: /* f64.ne */
		case 0x63: /* f64.lt */
		case 0x64: /* f64.gt */
		case 0x65: /* f64.le */
		case 0x66: /* f64.ge */
			binaryOp(instAddress, ValType.f64, ValType.i32);
			break;
		case 0x67: /* i32.clz */
		case 0x68: /* i32.ctz */
		case 0x69: /* i32.popcnt */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x6A: /* i32.add */
		case 0x6B: /* i32.sub */
		case 0x6C: /* i32.mul */
		case 0x6D: /* i32.div_s */
		case 0x6E: /* i32.div_u */
		case 0x6F: /* i32.rem_s */
		case 0x70: /* i32.rem_u */
		case 0x71: /* i32.and */
		case 0x72: /* i32.or */
		case 0x73: /* i32.xor */
		case 0x74: /* i32.shl */
		case 0x75: /* i32.shr_s */
		case 0x76: /* i32.shr_u */
		case 0x77: /* i32.rotl */
		case 0x78: /* i32.rotr */
			binaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x79: /* i64.clz */
		case 0x7A: /* i64.ctz */
		case 0x7B: /* i64.popcnt */
			unaryOp(instAddress, ValType.i64, ValType.i64);
			break;
		case 0x7C: /* i64.add */
		case 0x7D: /* i64.sub */
		case 0x7E: /* i64.mul */
		case 0x7F: /* i64.div_s */
		case 0x80: /* i64.div_u */
		case 0x81: /* i64.rem_s */
		case 0x82: /* i64.rem_u */
		case 0x83: /* i64.and */
		case 0x84: /* i64.or */
		case 0x85: /* i64.xor */
		case 0x86: /* i64.shl */
		case 0x87: /* i64.shr_s */
		case 0x88: /* i64.shr_u */
		case 0x89: /* i64.rotl */
		case 0x8A: /* i64.rotr */
			binaryOp(instAddress, ValType.i64, ValType.i64);
			break;
		case 0x8B: /* f32.abs */
		case 0x8C: /* f32.neg */
		case 0x8D: /* f32.ceil */
		case 0x8E: /* f32.floor */
		case 0x8F: /* f32.trunc */
		case 0x90: /* f32.nearest */
		case 0x91: /* f32.sqrt */
			unaryOp(instAddress, ValType.f32, ValType.f32);
			break;
		case 0x92: /* f32.add */
		case 0x93: /* f32.sub */
		case 0x94: /* f32.mul */
		case 0x95: /* f32.div */
		case 0x96: /* f32.min */
		case 0x97: /* f32.max */
		case 0x98: /* f32.copysign */
			binaryOp(instAddress, ValType.f32, ValType.f32);
			break;
		case 0x99: /* f64.abs */
		case 0x9A: /* f64.neg */
		case 0x9B: /* f64.ceil */
		case 0x9C: /* f64.floor */
		case 0x9D: /* f64.trunc */
		case 0x9E: /* f64.nearest */
		case 0x9F: /* f64.sqrt */
			unaryOp(instAddress, ValType.f64, ValType.f64);
			break;
		case 0xA0: /* f64.add */
		case 0xA1: /* f64.sub */
		case 0xA2: /* f64.mul */
		case 0xA3: /* f64.div */
		case 0xA4: /* f64.min */
		case 0xA5: /* f64.max */
		case 0xA6: /* f64.copysign */
			binaryOp(instAddress, ValType.f64, ValType.f64);
			break;
		case 0xA7: /* i32.wrap_i64 */
			unaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0xA8: /* i32.trunc_f32_s */
		case 0xA9: /* i32.trunc_f32_u */
			unaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0xAA: /* i32.trunc_f64_s */
		case 0xAB: /* i32.trunc_f64_u */
			unaryOp(instAddress, ValType.f64, ValType.i32);
			break;
		case 0xAC: /* i64.extend_i32_s */
		case 0xAD: /* i64.extend_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.i64);
			break;
		case 0xAE: /* i64.trunc_f32_s */
		case 0xAF: /* i64.trunc_f32_u */
			unaryOp(instAddress, ValType.f32, ValType.i64);
			break;
		case 0xB0: /* i64.trunc_f64_s */
		case 0xB1: /* i64.trunc_f64_u */
			unaryOp(instAddress, ValType.f64, ValType.i64);
			break;
		case 0xB2: /* f32.convert_i32_s */
		case 0xB3: /* f32.convert_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.f32);
			break;
		case 0xB4: /* f32.convert_i64_s */
		case 0xB5: /* f32.convert_i64_u */
			unaryOp(instAddress, ValType.i64, ValType.f32);
			break;
		case 0xB6: /* f32.demote_f64 */
			unaryOp(instAddress, ValType.f64, ValType.f32);
			break;
		case 0xB7: /* f64.convert_i32_s */
		case 0xB8: /* f64.convert_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.f64);
			break;
		case 0xB9: /* f64.convert_i64_s */
		case 0xBA: /* f64.convert_i64_u */
			unaryOp(instAddress, ValType.i64, ValType.f64);
			break;
		case 0xBB: /* f64.promote_f32 */
			unaryOp(instAddress, ValType.f32, ValType.f64);
			break;
		case 0xBC: /* i32.reinterpret_f32 */
			unaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0xBD: /* i64.reinterpret_f64 */
			unaryOp(instAddress, ValType.f64, ValType.i64);
			break;
		case 0xBE: /* f32.reinterpret_i32 */
			unaryOp(instAddress, ValType.i32, ValType.f32);
			break;
		case 0xBF: /* f64.reinterpret_i64 */
			unaryOp(instAddress, ValType.i64, ValType.f64);
			break;
		case 0xC0: /* i32.extend8_s */
		case 0xC1: /* i32.extend16_s */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0xC2: /* i64.extend8_s */
		case 0xC3: /* i64.extend16_s */
		case 0xC4: /* i64.extend32_s */
			unaryOp(instAddress, ValType.i64, ValType.i64);
			break;

		case 0xD0: /* ref.null ht */ {
			/* The immediate is a bare s33 heap type (not a valtype): abstract heap types
			   map to their ValType (ref.null struct -> structref), a concrete type index to
			   the generic reference placeholder. */
			ValType reftype = ValType.readHeapType(reader);
			pushValue(instAddress, reftype);
			break;
		}
		case 0xD1: /* ref.is_null */
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			break;
		case 0xD2: /* ref.func x */ {
			long funcidx = readLeb128(reader);
			WasmFuncSignature targetFunc = analysis.getFunction((int) funcidx);
			contextreg.setBranchTarget(instAddress, targetFunc.getStartAddr());
			pushValue(instAddress, ValType.funcref);
			break;
		}
		case 0xD3: /* ref.eq (GC): [(ref null eq) (ref null eq)] -> [i32] */
			// @@GC: ref.eq is a reference-types/GC opcode (no prefix, no immediates).
			popValue(instAddress);
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			break;

		// @@FR: function-references reference instructions (no prefix).
		case 0xD4: { /* ref.as_non_null: [(ref null ht)] -> [(ref ht)] */
			/*
			 * Same 4-byte reference, only non-nullable. ValType does not carry
			 * nullability, so the value stack type is unchanged.
			 */
			ValType ref = popValue(instAddress);
			pushValue(instAddress, (ref != null) ? ref : ValType.externref);
			break;
		}
		case 0xD5: /* br_on_null l: [t* (ref null ht)] -> [t* (ref ht)]; branch takes [t*] */ {
			long labelidx = readLeb128(reader);
			ValType ref = popValue(instAddress);
			ControlFrame block = getBlock(instAddress, labelidx);
			block.addBranch(instAddress);
			/* fall-through keeps the (now non-null) reference */
			pushValue(instAddress, (ref != null) ? ref : ValType.externref);
			break;
		}
		case 0xD6: /* br_on_non_null l: [t* (ref null ht)] -> [t*]; branch takes [t* (ref ht)] */ {
			long labelidx = readLeb128(reader);
			popValue(instAddress);
			ControlFrame block = getBlock(instAddress, labelidx);
			block.addBranch(instAddress);
			/* fall-through consumes the (null) reference */
			break;
		}

		// @@SS: stack-switching instructions (0xE0-0xE6). Operands, handler vectors and stack
		// effects are decoded below; the SLEIGH side is in StackSwitchOps.sinc.
		case 0xE0: /* cont.new $ct */ {
			readLeb128(reader); /* typeidx */
			contNew(instAddress);
			break;
		}
		case 0xE1: /* cont.bind $ct $ct' */ {
			long t1 = readLeb128(reader);
			long t2 = readLeb128(reader);
			contBind(instAddress, analysis, t1, t2);
			break;
		}
		case 0xE2: /* suspend $tag */ {
			long tagidx = readLeb128(reader);
			suspend(instAddress, analysis, tagidx);
			break;
		}
		case 0xE3: /* resume $ct hdl* */ {
			long typeidx = readLeb128(reader);
			readHandlerVector(reader, instAddress);
			resume(instAddress, analysis, typeidx);
			break;
		}
		case 0xE4: /* resume_throw $ct $tag hdl* */ {
			long typeidx = readLeb128(reader);
			long tagidx = readLeb128(reader);
			readHandlerVector(reader, instAddress);
			resumeThrow(instAddress, analysis, typeidx, tagidx);
			break;
		}
		case 0xE5: /* resume_throw_ref $ct hdl* */ {
			long typeidx = readLeb128(reader);
			readHandlerVector(reader, instAddress);
			resumeThrowRef(instAddress, analysis, typeidx);
			break;
		}
		case 0xE6: /* switch $ct1 $tag */ {
			long typeidx = readLeb128(reader);
			long tagidx = readLeb128(reader);
			switchOp(instAddress, analysis, typeidx, tagidx);
			break;
		}
		// @@GC: 0xFB-prefixed GC instructions (garbage collection proposal). All of
		// the opcode decoding, immediate lengths and stack effects live in GCOps.
		// @@UNIMP: 0xFB >= 0x80 is the JS string builtins / stringref range, which
		// GCOps declines; those are consumed here instead (see the note above).
		case 0xFB: {
			long subPosition = reader.getPointerIndex();
			int sub = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			if (isGCOpcode(sub)) {
				reader.setPointerIndex(subPosition);
				GCOps.handle(this, analysis, instAddress, reader);
			} else if (!stringBuiltin(analysis, reader, instAddress, sub)) {
				// @@UNIMP: a reserved/unassigned 0xFB >= 0x80 sub-opcode. It is rendered as
				// `unimplemented`; the stringref-range ones carry no immediates.
				markUnimplemented();
				boolean consumed = skipUnimplementedOperands(reader, 0xFB, sub);
				warnUnimplemented(instAddress, 0xFB, ":" + Long.toHexString(sub), consumed);
			}
			break;
		}
		case 0xFC: {
			int opcode2 = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			switch (opcode2) {
			case 0x00: /* i32.trunc_sat_f32_s */
			case 0x01: /* i32.trunc_sat_f32_u */
				unaryOp(instAddress, ValType.f32, ValType.i32);
				break;
			case 0x02: /* i32.trunc_sat_f64_s */
			case 0x03: /* i32.trunc_sat_f64_u */
				unaryOp(instAddress, ValType.f64, ValType.i32);
				break;
			case 0x04: /* i64.trunc_sat_f32_s */
			case 0x05: /* i64.trunc_sat_f32_u */
				unaryOp(instAddress, ValType.f32, ValType.i64);
				break;
			case 0x06: /* i64.trunc_sat_f64_s */
			case 0x07: /* i64.trunc_sat_f64_u */
				unaryOp(instAddress, ValType.f64, ValType.i64);
				break;
			case 0x08: /* memory.init x */ {
				readLeb128(reader); /* dataidx */
				/* @@M64: [at i32 i32] - the destination offset is the memory's index type. */
				ValType indexType = setMemoryIndexContext(analysis, instAddress, readLeb128(reader)); /* memidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, indexType);
				break;
			}
			case 0x09: /* data.drop x */ {
				readLeb128(reader); /* dataidx */
				break;
			}
			case 0x0A: /* memory.copy */ {
				long memidx = readLeb128(reader);
				long memidx2 = readLeb128(reader);
				/* @@M64: [at1 at2 min(at1,at2)] - one width per source/destination memory. */
				ValType dstType = memoryIndexType(analysis, memidx);
				ValType srcType = memoryIndexType(analysis, memidx2);
				ValType lenType = (dstType == ValType.i64 && srcType == ValType.i64) ? ValType.i64 : ValType.i32;
				setMemoryCopyContext(instAddress, dstType, srcType);
				popValue(instAddress, lenType);
				popValue(instAddress, srcType);
				popValue(instAddress, dstType);
				break;
			}
			case 0x0B: /* memory.fill */ {
				/* @@M64: [at i32 at]. */
				ValType indexType = setMemoryIndexContext(analysis, instAddress, readLeb128(reader)); /* memidx */
				popValue(instAddress, indexType);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, indexType);
				break;
			}
			case 0x0C: /* table.init x y */ {
				readLeb128(reader); /* elemidx */
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0D: /* elem.drop x */ {
				readLeb128(reader); /* elemidx */
				break;
			}
			case 0x0E: /* table.copy x y */ {
				readLeb128(reader); /* tableidx */
				readLeb128(reader); /* tableidx2 */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0F: /* table.grow x */ {
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress);
				pushValue(instAddress, ValType.i32);
				break;
			}
			case 0x10: /* table.size x */ {
				readLeb128(reader); /* tableidx */
				pushValue(instAddress, ValType.i32);
				break;
			}
			case 0x11: /* table.fill x */ {
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress);
				popValue(instAddress, ValType.i32);
				break;
			}
			// @@WA: memory.discard and wide arithmetic.
			case 0x12: /* memory.discard $mem: [at(addr) at(size)] -> [] */ {
				readLeb128(reader); /* memidx (a bare index, not a memarg) */
				markProposalOp();
				/*
				 * The address/size operands are the memory's index type; they are modelled as
				 * i32 (a memory64 index degrades to 32-bit - see WideArithOps.sinc).
				 */
				popValue(instAddress, ValType.i32); /* size */
				popValue(instAddress, ValType.i32); /* address */
				break;
			}
			case 0x13: /* i64.add128: [i64 i64 i64 i64] -> [i64 i64] */
			case 0x14: /* i64.sub128 */ {
				markProposalOp();
				popValue(instAddress, ValType.i64); /* c4 (high rhs) */
				popValue(instAddress, ValType.i64); /* c3 (low rhs) */
				popValue(instAddress, ValType.i64); /* c2 (high lhs) */
				popValue(instAddress, ValType.i64); /* c1 (low lhs) */
				pushValue(instAddress, ValType.i64); /* low result */
				pushValue(instAddress, ValType.i64); /* high result */
				break;
			}
			case 0x15: /* i64.mul_wide_s: [i64 i64] -> [i64 i64] */
			case 0x16: /* i64.mul_wide_u */ {
				markProposalOp();
				popValue(instAddress, ValType.i64); /* rhs */
				popValue(instAddress, ValType.i64); /* lhs */
				pushValue(instAddress, ValType.i64); /* low result */
				pushValue(instAddress, ValType.i64); /* high result */
				break;
			}
			default:
				/* @@UNIMP: any other 0xFC sub-opcode has no known length. */
				markUnimplemented();
				if (skipUnimplementedOperands(reader, 0xFC, opcode2)) {
					warnUnimplemented(instAddress, 0xFC, ":" + Integer.toHexString(opcode2), true);
				} else {
					Msg.warn(this, "Illegal opcode 0xfc " + String.format("0x%02x", opcode2) + " at " + instAddress
							+ " (operand length unknown; not consuming following bytes)");
				}
				break;
			}
			break;
		}
		case 0xFD: {
			int opcode2 = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			switch (opcode2) {
			case 0x0: /* v128.load */
			case 0x1: /* v128.load8x8_s */
			case 0x2: /* v128.load8x8_u */
			case 0x3: /* v128.load16x4_s */
			case 0x4: /* v128.load16x4_u */
			case 0x5: /* v128.load32x2_s */
			case 0x6: /* v128.load32x2_u */
			case 0x7: /* v128.load8_splat */
			case 0x8: /* v128.load16_splat */
			case 0x9: /* v128.load32_splat */
			case 0xA: /* v128.load64_splat */
				memoryLoad(analysis, reader, instAddress, ValType.v128);
				break;
			case 0xB: /* v128.store */
				memoryStore(analysis, reader, instAddress, ValType.v128);
				break;
			case 0xC: /* v128.const */
				reader.readNextByteArray(16); /* value */
				pushValue(instAddress, ValType.v128);
				break;
			case 0xD: /* i8x16.shuffle */
				for (int i = 0; i < 16; i++)
					reader.readNextByte(); /* laneidx16 */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE: /* i8x16.swizzle */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF: /* i8x16.splat */
			case 0x10: /* i16x8.splat */
			case 0x11: /* i32x4.splat */
				unaryOp(instAddress, ValType.i32, ValType.v128);
				break;
			case 0x12: /* i64x2.splat */
				unaryOp(instAddress, ValType.i64, ValType.v128);
				break;
			case 0x13: /* f32x4.splat */
				unaryOp(instAddress, ValType.f32, ValType.v128);
				break;
			case 0x14: /* f64x2.splat */
				unaryOp(instAddress, ValType.f64, ValType.v128);
				break;
			case 0x15: /* i8x16.extract_lane_s */
			case 0x16: /* i8x16.extract_lane_u */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x17: /* i8x16.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x18: /* i16x8.extract_lane_s */
			case 0x19: /* i16x8.extract_lane_u */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x1A: /* i16x8.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1B: /* i32x4.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x1C: /* i32x4.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1D: /* i64x2.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i64);
				break;
			case 0x1E: /* i64x2.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i64);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1F: /* f32x4.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.f32);
				break;
			case 0x20: /* f32x4.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.f32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x21: /* f64x2.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.f64);
				break;
			case 0x22: /* f64x2.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.f64);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x23: /* i8x16.eq */
			case 0x24: /* i8x16.ne */
			case 0x25: /* i8x16.lt_s */
			case 0x26: /* i8x16.lt_u */
			case 0x27: /* i8x16.gt_s */
			case 0x28: /* i8x16.gt_u */
			case 0x29: /* i8x16.le_s */
			case 0x2A: /* i8x16.le_u */
			case 0x2B: /* i8x16.ge_s */
			case 0x2C: /* i8x16.ge_u */
			case 0x2D: /* i16x8.eq */
			case 0x2E: /* i16x8.ne */
			case 0x2F: /* i16x8.lt_s */
			case 0x30: /* i16x8.lt_u */
			case 0x31: /* i16x8.gt_s */
			case 0x32: /* i16x8.gt_u */
			case 0x33: /* i16x8.le_s */
			case 0x34: /* i16x8.le_u */
			case 0x35: /* i16x8.ge_s */
			case 0x36: /* i16x8.ge_u */
			case 0x37: /* i32x4.eq */
			case 0x38: /* i32x4.ne */
			case 0x39: /* i32x4.lt_s */
			case 0x3A: /* i32x4.lt_u */
			case 0x3B: /* i32x4.gt_s */
			case 0x3C: /* i32x4.gt_u */
			case 0x3D: /* i32x4.le_s */
			case 0x3E: /* i32x4.le_u */
			case 0x3F: /* i32x4.ge_s */
			case 0x40: /* i32x4.ge_u */
			case 0x41: /* f32x4.eq */
			case 0x42: /* f32x4.ne */
			case 0x43: /* f32x4.lt */
			case 0x44: /* f32x4.gt */
			case 0x45: /* f32x4.le */
			case 0x46: /* f32x4.ge */
			case 0x47: /* f64x2.eq */
			case 0x48: /* f64x2.ne */
			case 0x49: /* f64x2.lt */
			case 0x4A: /* f64x2.gt */
			case 0x4B: /* f64x2.le */
			case 0x4C: /* f64x2.ge */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x4D: /* v128.not */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x4E: /* v128.and */
			case 0x4F: /* v128.andnot */
			case 0x50: /* v128.or */
			case 0x51: /* v128.xor */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x52: /* v128.bitselect */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x53: /* v128.any_true */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x54: /* v128.load8_lane */
			case 0x55: /* v128.load16_lane */
			case 0x56: /* v128.load32_lane */
			case 0x57: /* v128.load64_lane */
				/* @@M64: the address is the memory's index type. */
				ValType laneLoadType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, laneLoadType);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x58: /* v128.store8_lane */
			case 0x59: /* v128.store16_lane */
			case 0x5A: /* v128.store32_lane */
			case 0x5B: /* v128.store64_lane */
				/* @@M64: the address is the memory's index type. */
				ValType laneStoreType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, laneStoreType);
				break;
			case 0x5C: /* v128.load32_zero */
			case 0x5D: /* v128.load64_zero */
				/* @@M64: the address is the memory's index type. */
				ValType zeroLoadType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
				popValue(instAddress, zeroLoadType);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x5E: /* f32x4.demote_f64x2_zero */
			case 0x5F: /* f64x2.promote_low_f32x4 */
			case 0x60: /* i8x16.abs */
			case 0x61: /* i8x16.neg */
			case 0x62: /* i8x16.popcnt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x63: /* i8x16.all_true */
			case 0x64: /* i8x16.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x65: /* i8x16.narrow_i16x8_s */
			case 0x66: /* i8x16.narrow_i16x8_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x67: /* f32x4.ceil */
			case 0x68: /* f32x4.floor */
			case 0x69: /* f32x4.trunc */
			case 0x6A: /* f32x4.nearest */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x6B: /* i8x16.shl */
			case 0x6C: /* i8x16.shr_s */
			case 0x6D: /* i8x16.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x6E: /* i8x16.add */
			case 0x6F: /* i8x16.add_sat_s */
			case 0x70: /* i8x16.add_sat_u */
			case 0x71: /* i8x16.sub */
			case 0x72: /* i8x16.sub_sat_s */
			case 0x73: /* i8x16.sub_sat_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x74: /* f64x2.ceil */
			case 0x75: /* f64x2.floor */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x76: /* i8x16.min_s */
			case 0x77: /* i8x16.min_u */
			case 0x78: /* i8x16.max_s */
			case 0x79: /* i8x16.max_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7A: /* f64x2.trunc */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7B: /* i8x16.avgr_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7C: /* i16x8.extadd_pairwise_i8x16_s */
			case 0x7D: /* i16x8.extadd_pairwise_i8x16_u */
			case 0x7E: /* i32x4.extadd_pairwise_i16x8_s */
			case 0x7F: /* i32x4.extadd_pairwise_i16x8_u */
			case 0x80: /* i16x8.abs */
			case 0x81: /* i16x8.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x82: /* i16x8.q15mulr_sat_s */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x83: /* i16x8.all_true */
			case 0x84: /* i16x8.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x85: /* i16x8.narrow_i32x4_s */
			case 0x86: /* i16x8.narrow_i32x4_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x87: /* i16x8.extend_low_i8x16_s */
			case 0x88: /* i16x8.extend_high_i8x16_s */
			case 0x89: /* i16x8.extend_low_i8x16_u */
			case 0x8A: /* i16x8.extend_high_i8x16_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x8B: /* i16x8.shl */
			case 0x8C: /* i16x8.shr_s */
			case 0x8D: /* i16x8.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x8E: /* i16x8.add */
			case 0x8F: /* i16x8.add_sat_s */
			case 0x90: /* i16x8.add_sat_u */
			case 0x91: /* i16x8.sub */
			case 0x92: /* i16x8.sub_sat_s */
			case 0x93: /* i16x8.sub_sat_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x94: /* f64x2.nearest */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x95: /* i16x8.mul */
			case 0x96: /* i16x8.min_s */
			case 0x97: /* i16x8.min_u */
			case 0x98: /* i16x8.max_s */
			case 0x99: /* i16x8.max_u */
			case 0x9B: /* i16x8.avgr_u */
			case 0x9C: /* i16x8.extmul_low_i8x16_s */
			case 0x9D: /* i16x8.extmul_high_i8x16_s */
			case 0x9E: /* i16x8.extmul_low_i8x16_u */
			case 0x9F: /* i16x8.extmul_high_i8x16_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xA0: /* i32x4.abs */
			case 0xA1: /* i32x4.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xA3: /* i32x4.all_true */
			case 0xA4: /* i32x4.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0xA7: /* i32x4.extend_low_i16x8_s */
			case 0xA8: /* i32x4.extend_high_i16x8_s */
			case 0xA9: /* i32x4.extend_low_i16x8_u */
			case 0xAA: /* i32x4.extend_high_i16x8_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xAB: /* i32x4.shl */
			case 0xAC: /* i32x4.shr_s */
			case 0xAD: /* i32x4.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0xAE: /* i32x4.add */
			case 0xB1: /* i32x4.sub */
			case 0xB5: /* i32x4.mul */
			case 0xB6: /* i32x4.min_s */
			case 0xB7: /* i32x4.min_u */
			case 0xB8: /* i32x4.max_s */
			case 0xB9: /* i32x4.max_u */
			case 0xBA: /* i32x4.dot_i16x8_s */
			case 0xBC: /* i32x4.extmul_low_i16x8_s */
			case 0xBD: /* i32x4.extmul_high_i16x8_s */
			case 0xBE: /* i32x4.extmul_low_i16x8_u */
			case 0xBF: /* i32x4.extmul_high_i16x8_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xC0: /* i64x2.abs */
			case 0xC1: /* i64x2.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xC3: /* i64x2.all_true */
			case 0xC4: /* i64x2.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0xC7: /* i64x2.extend_low_i32x4_s */
			case 0xC8: /* i64x2.extend_high_i32x4_s */
			case 0xC9: /* i64x2.extend_low_i32x4_u */
			case 0xCA: /* i64x2.extend_high_i32x4_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xCB: /* i64x2.shl */
			case 0xCC: /* i64x2.shr_s */
			case 0xCD: /* i64x2.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0xCE: /* i64x2.add */
			case 0xD1: /* i64x2.sub */
			case 0xD5: /* i64x2.mul */
			case 0xD6: /* i64x2.eq */
			case 0xD7: /* i64x2.ne */
			case 0xD8: /* i64x2.lt_s */
			case 0xD9: /* i64x2.gt_s */
			case 0xDA: /* i64x2.le_s */
			case 0xDB: /* i64x2.ge_s */
			case 0xDC: /* i64x2.extmul_low_i32x4_s */
			case 0xDD: /* i64x2.extmul_high_i32x4_s */
			case 0xDE: /* i64x2.extmul_low_i32x4_u */
			case 0xDF: /* i64x2.extmul_high_i32x4_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE0: /* f32x4.abs */
			case 0xE1: /* f32x4.neg */
			case 0xE3: /* f32x4.sqrt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE4: /* f32x4.add */
			case 0xE5: /* f32x4.sub */
			case 0xE6: /* f32x4.mul */
			case 0xE7: /* f32x4.div */
			case 0xE8: /* f32x4.min */
			case 0xE9: /* f32x4.max */
			case 0xEA: /* f32x4.pmin */
			case 0xEB: /* f32x4.pmax */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xEC: /* f64x2.abs */
			case 0xED: /* f64x2.neg */
			case 0xEF: /* f64x2.sqrt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF0: /* f64x2.add */
			case 0xF1: /* f64x2.sub */
			case 0xF2: /* f64x2.mul */
			case 0xF3: /* f64x2.div */
			case 0xF4: /* f64x2.min */
			case 0xF5: /* f64x2.max */
			case 0xF6: /* f64x2.pmin */
			case 0xF7: /* f64x2.pmax */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF8: /* i32x4.trunc_sat_f32x4_s */
			case 0xF9: /* i32x4.trunc_sat_f32x4_u */
			case 0xFA: /* f32x4.convert_i32x4_s */
			case 0xFB: /* f32x4.convert_i32x4_u */
			case 0xFC: /* i32x4.trunc_sat_f64x2_s_zero */
			case 0xFD: /* i32x4.trunc_sat_f64x2_u_zero */
			case 0xFE: /* f64x2.convert_low_i32x4_s */
			case 0xFF: /* f64x2.convert_low_i32x4_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x100: /* i8x16.relaxed_swizzle */
			case 0x10D: /* f32x4.relaxed_min */
			case 0x10E: /* f32x4.relaxed_max */
			case 0x10F: /* f64x2.relaxed_min */
			case 0x110: /* f64x2.relaxed_max */
			case 0x111: /* i16x8.relaxed_q15mulr_s */
			case 0x112: /* i16x8.relaxed_dot_i8x16_i7x16_s */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x101: /* i32x4.relaxed_trunc_f32x4_s */
			case 0x102: /* i32x4.relaxed_trunc_f32x4_u */
			case 0x103: /* i32x4.relaxed_trunc_f64x2_s_zero */
			case 0x104: /* i32x4.relaxed_trunc_f64x2_u_zero */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x105: /* f32x4.relaxed_madd */
			case 0x106: /* f32x4.relaxed_nmadd */
			case 0x107: /* f64x2.relaxed_madd */
			case 0x108: /* f64x2.relaxed_nmadd */
			case 0x109: /* i8x16.relaxed_laneselect */
			case 0x10A: /* i16x8.relaxed_laneselect */
			case 0x10B: /* i32x4.relaxed_laneselect */
			case 0x10C: /* i64x2.relaxed_laneselect */
			case 0x113: /* i32x4.relaxed_dot_i8x16_i7x16_add_s */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			default:
				Msg.warn(this, "Illegal opcode 0xfd " + String.format("0x%02x", opcode2) + " at " + instAddress);
				break;
			}
			break;
		}
		case 0xFE: { /* threads: atomic memory instructions */
			int opcode2 = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			if (opcode2 == 0x03) { /* atomic.fence 0x00 */
				reader.readNextUnsignedByte();
				break;
			}
			/* @@MM: memarg (may carry a memidx); @@M64: the address is the index type. */
			ValType indexType = setMemoryIndexContext(analysis, instAddress, readMemarg(reader));
			if (opcode2 == 0x00) { /* memory.atomic.notify */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, indexType);
				pushValue(instAddress, ValType.i32);
			} else if (opcode2 == 0x01 || opcode2 == 0x02) { /* memory.atomic.wait32 / wait64 */
				popValue(instAddress, ValType.i64);
				popValue(instAddress, opcode2 == 0x01 ? ValType.i32 : ValType.i64);
				popValue(instAddress, indexType);
				pushValue(instAddress, ValType.i32);
			} else if (opcode2 >= 0x10 && opcode2 <= 0x16) { /* loads */
				popValue(instAddress, indexType);
				pushValue(instAddress, (opcode2 == 0x10 || opcode2 == 0x12 || opcode2 == 0x13) ? ValType.i32 : ValType.i64);
			} else if (opcode2 >= 0x17 && opcode2 <= 0x1D) { /* stores */
				popValue(instAddress, (opcode2 == 0x17 || opcode2 == 0x19 || opcode2 == 0x1A) ? ValType.i32 : ValType.i64);
				popValue(instAddress, indexType);
			} else if (opcode2 >= 0x1E && opcode2 <= 0x47) { /* add, sub, and, or, xor, xchg */
				ValType type = atomicType((opcode2 - 0x1E) % 7);
				popValue(instAddress, type);
				popValue(instAddress, indexType);
				pushValue(instAddress, type);
			} else if (opcode2 >= 0x48 && opcode2 <= 0x4E) { /* cmpxchg */
				ValType type = atomicType(opcode2 - 0x48);
				popValue(instAddress, type);
				popValue(instAddress, type);
				popValue(instAddress, indexType);
				pushValue(instAddress, type);
			} else {
				Msg.warn(this, "Illegal opcode 0xfe " + String.format("0x%02x", opcode2) + " at " + instAddress);
			}
			break;
		}
		default:
			// @@UNIMP: unknown opcode. Nothing is consumed (the operand length is
			// unknown), but the function is no longer abandoned: validation is relaxed
			// from here on and the rest of the body disassembles.
			markUnimplemented();
			Msg.warn(this, "Illegal opcode " + String.format("0x%02x", opcode) + " at " + instAddress
					+ " (operand length unknown; not consuming following bytes)");
			break;
		}
	}

	public void analyzeFunction(WasmAnalysis analysis, BinaryReader reader) throws IOException {
		Address startAddress = func.getStartAddr();
		long functionLength = func.getEndAddr().subtract(func.getStartAddr());

		// read the function locals
		Address instAddress;

		instAddress = startAddress.add(reader.getPointerIndex());
		contextreg.setLocalsDeclaration(instAddress);
		long count = readLeb128(reader);
		for (int i = 0; i < count; i++) {
			instAddress = startAddress.add(reader.getPointerIndex());
			contextreg.setLocalDeclaration(instAddress);
			readLeb128(reader); /* count */
			readLeb128(reader); /* type */
		}

		instAddress = startAddress.add(reader.getPointerIndex());
		pushBlock(instAddress, new ControlFrame(instAddress, new BlockType(func)));
		while (reader.getPointerIndex() <= functionLength) {
			instAddress = startAddress.add(reader.getPointerIndex());
			long position = reader.getPointerIndex();
			try {
				analyzeOpcode(analysis, instAddress, reader);
			} catch (ValidationException e) {
				// @@UNIMP: once the function contains an instruction we could not model,
				// the stack model is unreliable; log the error and keep disassembling the
				// rest of the body instead of blanking the function out.
				if (!hasUnimplementedOps) {
					throw e;
				}
				Msg.warn(this, "Ignoring validation error after an unimplemented instruction at "
						+ instAddress + ": " + e.getMessage());
			}
			if (reader.getPointerIndex() <= position) {
				/* defensive: always make progress through the body */
				break;
			}
		}
	}

	public BigInteger getContext(Address address) {
		return contextreg.getContext(address);
	}

	public void applyContext(Program program, int cStackGlobal) {
		for (Map.Entry<Address, Long> entry : globalGetSets.entrySet()) {
			if (entry.getValue() == cStackGlobal) {
				contextreg.setIsGlobalSp(entry.getKey(), entry.getValue() == cStackGlobal);
			}
		}
		contextreg.commitContext(program);
	}
}
