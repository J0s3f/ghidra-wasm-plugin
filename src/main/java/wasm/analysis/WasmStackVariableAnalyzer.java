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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.Float8DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates C stack variables for Wasm functions.
 * <p>
 * The frame is modelled as a single aggregate (the region of the guessed C stack the function
 * touches) and then split into <em>atoms</em> by SROA - one atom per distinct observed
 * (width, offset) access. The rule (see the NotDec paper §3.2.3 and the Decompilation Wiki's
 * Aggregate Structure Identification recipe):
 * <ul>
 * <li>a repeated access at the same offset with the same width merges into one atom;</li>
 * <li>a wider access covering a smaller one wins - the two atoms are unified into the wider
 * extent and the wider access's datatype is kept (the split is recorded);</li>
 * <li>overlapping/unaligned accesses (e.g. an i32 at 0 and an i64 at 2) widen the atom to the
 * union and fall back to an undefined blob of exactly that size, so the result is deterministic
 * and never depends on instruction order;</li>
 * <li>a fixed-offset access from the C stack pointer is a structure field; strided patterns are
 * left as separate atoms (array recovery is a separate item).</li>
 * </ul>
 * The accesses are collected first, atomized, and only then applied (a second pass over the
 * accesses adds the stack references), so overlapping or unaligned accesses cannot produce
 * duplicate variables or an exception.
 */
public class WasmStackVariableAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Stack Analyzer";
	private static final String DESCRIPTION = "Creates C stack variables for Wasm functions.";

	public WasmStackVariableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.initialize(program.getFunctionManager().getFunctionCount());

		int functionsWithAtoms = 0;
		int totalAccesses = 0;
		int totalAtoms = 0;
		int totalSplits = 0;
		int totalMerges = 0;

		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.setMessage("C Stack " + function.getName());
			monitor.incrementProgress(1);

			Stats stats = createStackPointerVariables(program, function, monitor);
			totalAccesses += stats.accesses;
			totalAtoms += stats.atoms;
			totalSplits += stats.splits;
			totalMerges += stats.merges;
			if (stats.atoms > 0) {
				functionsWithAtoms++;
				Msg.info(this, "SROA " + function.getName() + " aggregate=[" + stats.low + "," + stats.high +
					") accesses=" + stats.accesses + " atoms=" + stats.atoms + " splits=" + stats.splits +
					" merges=" + stats.merges);
			}
		}

		Msg.info(this, "SROA-TOTAL functions_with_atoms=" + functionsWithAtoms + " accesses=" + totalAccesses +
			" atoms=" + totalAtoms + " splits=" + totalSplits + " merges=" + totalMerges);
		return true;
	}

	private static DataType getMemoryDataType(String mnemonic) {
		switch (mnemonic) {
		case "i32.load":
		case "i32.store":
			return Undefined4DataType.dataType;
		case "i64.load":
		case "i64.store":
			return Undefined8DataType.dataType;
		case "f32.store":
		case "f32.load":
			return Float4DataType.dataType;
		case "f64.store":
		case "f64.load":
			return Float8DataType.dataType;
		case "i32.load8_s":
		case "i64.load8_s":
			return CharDataType.dataType;
		case "i32.load8_u":
		case "i64.load8_u":
			return ByteDataType.dataType;
		case "i32.store8":
		case "i64.store8":
			return Undefined1DataType.dataType;
		case "i32.load16_s":
		case "i64.load16_s":
			return ShortDataType.dataType;
		case "i32.load16_u":
		case "i64.load16_u":
			return UnsignedShortDataType.dataType;
		case "i32.store16":
		case "i64.store16":
			return Undefined2DataType.dataType;
		case "i64.load32_s":
			return IntegerDataType.dataType;
		case "i64.load32_u":
			return UnsignedIntegerDataType.dataType;
		case "i64.store32":
			return Undefined4DataType.dataType;
		case "v128.load":
		case "v128.store":
			return Undefined.getUndefinedDataType(16);
		case "v128.load8_lane":
		case "v128.load8_splat":
		case "v128.store8_lane":
			return Undefined1DataType.dataType;
		case "v128.load16_lane":
		case "v128.load16_splat":
		case "v128.store16_lane":
			return Undefined2DataType.dataType;
		case "v128.load32_lane":
		case "v128.load32_splat":
		case "v128.load32_zero":
		case "v128.store32_lane":
			return Undefined4DataType.dataType;
		case "v128.load64_lane":
		case "v128.load64_splat":
		case "v128.load64_zero":
		case "v128.store64_lane":
			return Undefined8DataType.dataType;
		case "v128.load8x8_s":
			return new ArrayDataType(SignedByteDataType.dataType, 8, 1);
		case "v128.load8x8_u":
			return new ArrayDataType(ByteDataType.dataType, 8, 1);
		case "v128.load16x4_s":
			return new ArrayDataType(ShortDataType.dataType, 4, 2);
		case "v128.load16x4_u":
			return new ArrayDataType(UnsignedShortDataType.dataType, 4, 2);
		case "v128.load32x2_s":
			return new ArrayDataType(IntegerDataType.dataType, 2, 4);
		case "v128.load32x2_u":
			return new ArrayDataType(UnsignedIntegerDataType.dataType, 2, 4);
		}
		return DefaultDataType.dataType;
	}

	/** An undefined datatype of exactly {@code size} bytes (arrays of undefined1 above 8). */
	private static DataType sizedUndefined(int size) {
		if (size < 1) {
			size = 1;
		}
		DataType dt = Undefined.getUndefinedDataType(size);
		if (dt == null || dt.getLength() != size) {
			dt = new ArrayDataType(Undefined1DataType.dataType, size, 1);
		}
		return dt;
	}

	/**
	 * One observed access to the frame: a (width, offset) pair plus the reference that has to be
	 * added for it. The offset is relative to the guessed C stack pointer (the `SP` register),
	 * in bytes.
	 */
	private static final class Access {
		final int offset;
		final int size;
		final DataType dataType;
		final RefType refType;
		final Instruction instruction;
		final int opIndex;

		Access(int offset, int size, DataType dataType, RefType refType, Instruction instruction, int opIndex) {
			this.offset = offset;
			this.size = size;
			this.dataType = dataType;
			this.refType = refType;
			this.instruction = instruction;
			this.opIndex = opIndex;
		}
	}

	/** One SROA atom: a maximal, non-overlapping (width, offset) region of the frame. */
	private static final class Atom {
		int offset;
		int size;
		DataType dataType;
		int merged;
		boolean widened;

		Atom(int offset, int size, DataType dataType) {
			this.offset = offset;
			this.size = size;
			this.dataType = dataType;
		}

		int end() {
			return offset + size;
		}
	}

	/** Per-function counters for the SROA log line. */
	private static final class Stats {
		int accesses;
		int atoms;
		int splits;
		int merges;
		int low;
		int high;
	}

	private Variable createVar(Function func, int frameOffset, int offset, DataType dataType) throws InvalidInputException, DuplicateNameException {
		StackFrame frame = func.getStackFrame();
		int frameLoc = offset + frameOffset;
		Variable var = frame.getVariableContaining(frameLoc);
		if (var == null) {
			var = frame.createVariable(null, frameLoc, dataType, SourceType.ANALYSIS);
		} else if (var.getStackOffset() == frameLoc) {
			DataType oldDt = var.getDataType();
			if ((Undefined.isUndefined(oldDt) && !Undefined.isUndefined(dataType)) ||
			(oldDt == DefaultDataType.DEFAULT && dataType != DefaultDataType.DEFAULT)) {
				var.setDataType(dataType, SourceType.ANALYSIS);
			}
		}
		return var;
	}

	// Get registers sorted by position within the register file
	private List<Register> getRegisters(Object[] collection) {
		List<Register> registers = new ArrayList<>();
		for (Object obj : collection) {
			if (obj instanceof Register) {
				registers.add((Register) obj);
			}
		}
		Collections.sort(registers);
		return registers;
	}

	/**
	 * The first register among an instruction's input objects, or null when there is none.
	 * <p>
	 * {@link Instruction#getInputObjects()} can contain non-register objects (for example a
	 * dynamic Address for an exported register access), and a load/store instruction can have
	 * no register input object at all. Callers must tolerate a null/empty result instead of
	 * indexing or casting unconditionally (see REPORT-SF.md, finding 2).
	 */
	private Register firstRegister(Object[] collection) {
		for (Object obj : collection) {
			if (obj instanceof Register) {
				return (Register) obj;
			}
		}
		return null;
	}

	/**
	 * The first pass: walk the function once and collect every access to the frame. Nothing is
	 * written to the program here, so the access set does not depend on the order in which the
	 * variables are created.
	 */
	private List<Access> collectAccesses(Program program, Function func, TaskMonitor monitor, Stats stats) throws CancelledException {
		List<Access> accesses = new ArrayList<>();
		CallDepthChangeInfo info = new CallDepthChangeInfo(func, monitor);

		InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();

			try {
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.contains(".load") || mnemonic.contains(".store")) {
					// Note: inputObjects is not sorted in any particular order (it may be derived
					// from a HashSet)
					List<Register> registers = getRegisters(instr.getInputObjects());
					if (registers.isEmpty()) {
						continue;
					}
					Register base = registers.get(0);
					// get offset from "align=A offset=O" operand
					Scalar offset = getMemoryOffset(instr);
					if (offset == null) {
						continue;
					}
					int stackOffset = info.getRegDepth(instr.getMinAddress(), base);
					if (stackOffset == Function.INVALID_STACK_DEPTH_CHANGE) {
						continue;
					}
					DataType dataType = getMemoryDataType(mnemonic);
					int size = dataType.getLength();
					if (size < 1) {
						// An opcode this analyzer does not model (e.g. an atomic load) still has a
						// frame access; fall back to a 1-byte undefined placeholder so the atom has
						// a positive width.
						size = 1;
						dataType = sizedUndefined(size);
					}
					RefType refType = mnemonic.contains(".load") ? RefType.READ : RefType.WRITE;
					int frameOffset = (int) (stackOffset + offset.getUnsignedValue());
					accesses.add(new Access(frameOffset, size, dataType, refType, instr, 0));
				} else if (mnemonic.equals("local.get") || mnemonic.equals("local.set")) {
					// These instructions will only have one input, but the input object may be a
					// dynamic Address rather than a Register (the local register is exported as
					// `*[register]`), so pick the register out of the list instead of casting [0].
					Register input = firstRegister(instr.getInputObjects());
					if (input == null) {
						continue;
					}
					int stackOffset = info.getRegDepth(instr.getMinAddress(), input);
					if (stackOffset == Function.INVALID_STACK_DEPTH_CHANGE) {
						continue;
					}
					if (stackOffset == info.getDepth(instr.getMinAddress()) || stackOffset == 0) {
						/*
						 * Heuristically, avoid simple references to the frame or stack base, as they're
						 * likely to be operands for a later operation
						 */
						continue;
					}
					int size = input.getNumBytes();
					accesses.add(new Access(stackOffset, size, sizedUndefined(size), RefType.DATA, instr, 0));
				}
			} catch (Exception e) {
				Msg.warn(this, "Failed to process instruction at " + instr.getMinAddress() + ": " + instr + ": " + e.getMessage());
			}
		}

		stats.accesses = accesses.size();
		return accesses;
	}

	/** The `offset=O` operand of a load/store instruction, or null if it is not present. */
	private static Scalar getMemoryOffset(Instruction instr) {
		Object[] operands = instr.getOpObjects(0);
		if (operands.length < 2 || !(operands[operands.length - 1] instanceof Scalar)) {
			return null;
		}
		return (Scalar) operands[operands.length - 1];
	}

	private static boolean overlaps(Atom atom, Access access) {
		return access.offset < atom.end() && atom.offset < access.offset + access.size;
	}

	private static boolean overlaps(Atom a, Atom b) {
		return b.offset < a.end() && a.offset < b.end();
	}

	/**
	 * Split the collected accesses into atoms. One atom is created per distinct (width, offset)
	 * access; an overlapping access widens the atom it hits (the wider access's datatype wins),
	 * and the widening is repeated to a fixpoint because a widened atom can newly overlap another.
	 */
	private List<Atom> atomize(List<Access> accesses, Stats stats) {
		List<Atom> atoms = new ArrayList<>();
		for (Access access : accesses) {
			Atom hit = null;
			for (Atom atom : atoms) {
				if (overlaps(atom, access)) {
					hit = atom;
					break;
				}
			}
			if (hit == null) {
				atoms.add(new Atom(access.offset, access.size, access.dataType));
				continue;
			}
			merge(hit, access, stats);
		}

		// A widened atom can overlap an atom it did not overlap before; unify until stable.
		boolean changed = true;
		while (changed) {
			changed = false;
			for (int i = 0; i < atoms.size() && !changed; i++) {
				for (int j = i + 1; j < atoms.size(); j++) {
					if (overlaps(atoms.get(i), atoms.get(j))) {
						Atom keep = atoms.get(i);
						Atom other = atoms.get(j);
						unify(keep, other, stats);
						atoms.remove(j);
						stats.splits++;
						changed = true;
						break;
					}
				}
			}
		}

		for (Atom atom : atoms) {
			atom.dataType = typeForAtom(atom);
			stats.merges += atom.merged;
		}
		stats.atoms = atoms.size();
		return atoms;
	}

	/** Fold one access into an atom, widening the atom to the union when it grows. */
	private static void merge(Atom atom, Access access, Stats stats) {
		int end = atom.end();
		int lo = Math.min(atom.offset, access.offset);
		int hi = Math.max(end, access.offset + access.size);
		boolean grew = (lo != atom.offset || hi != end);
		if (access.size >= atom.size) {
			// The wider access (or an equal one) wins the datatype.
			atom.dataType = access.dataType;
		}
		if (grew) {
			atom.offset = lo;
			atom.size = hi - lo;
			atom.widened = true;
			stats.splits++;
		}
		atom.merged++;
	}

	/** Unify two overlapping atoms (used by the fixpoint pass). */
	private static void unify(Atom keep, Atom other, Stats stats) {
		int lo = Math.min(keep.offset, other.offset);
		int hi = Math.max(keep.end(), other.end());
		if (other.size >= keep.size) {
			keep.dataType = other.dataType;
		}
		keep.offset = lo;
		keep.size = hi - lo;
		keep.widened = true;
		keep.merged += other.merged;
	}

	/**
	 * The datatype of an atom: the winning access's datatype when it is exactly the atom's width,
	 * otherwise an undefined blob of exactly the atom's width (an unaligned/overlapping union no
	 * single access describes).
	 */
	private static DataType typeForAtom(Atom atom) {
		DataType dt = atom.dataType;
		if (dt != null && dt.getLength() == atom.size && !Undefined.isUndefined(dt) &&
			dt != DefaultDataType.DEFAULT) {
			return dt;
		}
		return sizedUndefined(atom.size);
	}

	/**
	 * The second pass: materialize one variable per atom and add one stack reference per observed
	 * access. Because every access lies inside exactly one atom, an unaligned or overlapping
	 * access cannot create a duplicate variable or an out-of-range reference.
	 */
	private void applyAtoms(Program program, Function func, List<Access> accesses, List<Atom> atoms) {
		atoms.sort((a, b) -> Integer.compare(a.offset, b.offset));
		for (Atom atom : atoms) {
			try {
				createVar(func, 0, atom.offset, atom.dataType);
			} catch (Exception e) {
				Msg.warn(this, "Failed to create stack variable at " + atom.offset + ": " + e.getMessage());
			}
		}

		ReferenceManager refMgr = program.getReferenceManager();
		for (Access access : accesses) {
			try {
				Reference ref = access.instruction.getPrimaryReference(access.opIndex);
				if (ref != null && ref instanceof StackReference) {
					continue;
				}
				refMgr.addStackReference(access.instruction.getMinAddress(), access.opIndex, access.offset,
					access.refType, SourceType.ANALYSIS);
			} catch (Exception e) {
				Msg.warn(this, "Failed to add stack reference at " + access.instruction.getMinAddress() + ": " + e.getMessage());
			}
		}
	}

	private Stats createStackPointerVariables(Program program, Function func, TaskMonitor monitor) throws CancelledException {
		Stats stats = new Stats();
		List<Access> accesses = collectAccesses(program, func, monitor, stats);
		if (accesses.isEmpty()) {
			return stats;
		}

		// Model the frame as ONE aggregate: the observed extent [low, high) relative to SP.
		int low = Integer.MAX_VALUE;
		int high = Integer.MIN_VALUE;
		for (Access access : accesses) {
			low = Math.min(low, access.offset);
			high = Math.max(high, access.offset + access.size);
		}
		stats.low = low;
		stats.high = high;

		List<Atom> atoms = atomize(accesses, stats);
		applyAtoms(program, func, accesses, atoms);
		return stats;
	}
}
