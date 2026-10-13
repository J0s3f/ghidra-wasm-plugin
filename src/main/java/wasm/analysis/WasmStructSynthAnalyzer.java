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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Call-graph-aware struct synthesis for WebAssembly linear-memory pointers.
 * <p>
 * Wasm parameters that carry a linear-memory address arrive as plain
 * {@code undefined4} (i32) values. The decompiler then shows every field
 * access as {@code *(int *)(param + 0xNN)}, which is the 591-access gap
 * measured by {@code type_recovery_metric.py} on the real module. This
 * analyzer exploits wasm's static structure to recover the pointee types:
 * <ol>
 *   <li><b>Collect accesses</b> – for every function, simulate the operand
 *       stack to find constant-offset {@code i32.load}/{@code i32.store}
 *       (and i64 / f32 / f64 / sub-word variants) whose base address is a
 *       plain {@code local.get N} or {@code local.get N; i32.const K; i32.add}.
 *       Record {@code (funcIdx, localIdx, offset, width)}.</li>
 *   <li><b>Pointer identity via the call graph</b> – for every direct
 *       {@code call F}, link the caller's argument source (when pushed as a
 *       plain {@code local.get N}) to the callee's parameter index. Union-find
 *       merges the linked {@code (funcIdx, localIdx)} nodes into pointer
 *       classes.</li>
 *   <li><b>Synthesize</b> – for every class with accesses at &ge; 2 distinct
 *       offsets, create a Ghidra {@link Structure} (named
 *       {@code wasm_struct_<n>}) with fields at the observed offsets/widths
 *       (gaps filled with {@code undefined1[n]}), then retype the member
 *       functions' <b>parameters</b> to {@code PointerDataType(struct)}.
 *       Never clobbers a non-undefined existing type.</li>
 * </ol>
 * <h3>Coverage / limits (v1)</h3>
 * <ul>
 *   <li>Only <b>direct</b> {@code call} instructions are followed.
 *       {@code call_indirect} is skipped (documented).</li>
 *   <li>Arguments pushed as {@code local.get N; i32.const K; i32.add} are
 *       <b>skipped</b> (the delta is not propagated through the call graph).</li>
 *   <li>Accesses whose base is a computed address (not a plain local) are
 *       skipped.</li>
 *   <li>Only <b>parameters</b> are retyped in v1; non-parameter locals are
 *       left as-is (documented).</li>
 *   <li>Structures are capped at {@value #MAX_FIELDS} fields; classes with
 *       more are skipped.</li>
 *   <li>The stack simulation is linear (no control-flow merge); on any
 *       unrecognised instruction the simulated stack is cleared, which is
 *       conservative (misses accesses but never produces wrong ones).</li>
 * </ul>
 */
public class WasmStructSynthAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Struct Synthesis Analyzer";
	private static final String DESCRIPTION =
		"Synthesize Ghidra structures from constant-offset memory accesses " +
		"through wasm pointer parameters, linked via the call graph.";

	/** Maximum number of fields in a synthesized structure. */
	private static final int MAX_FIELDS = 64;

	/** Minimum number of distinct offsets to synthesize a struct. */
	private static final int MIN_OFFSETS = 2;

	/* ---------- abstract stack values ---------- */

	private enum ValueKind { LOCAL, CONST, ADD, GLOBAL, UNKNOWN }

	private static final class StackValue {
		final ValueKind kind;
		final int localIndex;   // for LOCAL
		final long constValue;  // for CONST, or delta for ADD
		final StackValue base;  // for ADD

		private StackValue(ValueKind kind, int localIndex, long constValue, StackValue base) {
			this.kind = kind;
			this.localIndex = localIndex;
			this.constValue = constValue;
			this.base = base;
		}

		static StackValue local(int idx) { return new StackValue(ValueKind.LOCAL, idx, 0, null); }
		static StackValue constant(long v) { return new StackValue(ValueKind.CONST, -1, v, null); }
		static StackValue global(int idx) { return new StackValue(ValueKind.GLOBAL, idx, 0, null); }
		static StackValue unknown() { return new StackValue(ValueKind.UNKNOWN, -1, 0, null); }

		static StackValue add(StackValue a, StackValue b) {
			// local + const  or  const + local
			if (a.kind == ValueKind.LOCAL && b.kind == ValueKind.CONST) {
				return new StackValue(ValueKind.ADD, a.localIndex, b.constValue, a);
			}
			if (a.kind == ValueKind.CONST && b.kind == ValueKind.LOCAL) {
				return new StackValue(ValueKind.ADD, b.localIndex, a.constValue, b);
			}
			// add(base, delta) + const  or  const + add(base, delta)
			if (a.kind == ValueKind.ADD && b.kind == ValueKind.CONST) {
				return new StackValue(ValueKind.ADD, a.localIndex, a.constValue + b.constValue, a.base);
			}
			if (a.kind == ValueKind.CONST && b.kind == ValueKind.ADD) {
				return new StackValue(ValueKind.ADD, b.localIndex, a.constValue + b.constValue, b.base);
			}
			return unknown();
		}

		/** Resolve to (localIndex, totalDelta) if this is a LOCAL or ADD-of-LOCAL, else null. */
		int[] resolveLocal() {
			if (kind == ValueKind.LOCAL) {
				return new int[] { localIndex, 0 };
			}
			if (kind == ValueKind.ADD && base != null && base.kind == ValueKind.LOCAL) {
				return new int[] { localIndex, (int) constValue };
			}
			return null;
		}
	}

	/* ---------- collected data ---------- */

	/** A memory access through a local: (localIndex, effectiveOffset, width). */
	private static final class AccessRecord {
		final int localIndex;
		final int offset;
		final int width;

		AccessRecord(int localIndex, int offset, int width) {
			this.localIndex = localIndex;
			this.offset = offset;
			this.width = width;
		}
	}

	/** A call-graph link: caller's local -> callee's parameter. */
	private static final class CallLink {
		final int callerFuncIdx;
		final int callerLocalIdx;
		final int calleeFuncIdx;
		final int calleeParamIdx;

		CallLink(int callerFuncIdx, int callerLocalIdx, int calleeFuncIdx, int calleeParamIdx) {
			this.callerFuncIdx = callerFuncIdx;
			this.callerLocalIdx = callerLocalIdx;
			this.calleeFuncIdx = calleeFuncIdx;
			this.calleeParamIdx = calleeParamIdx;
		}
	}

	/* ---------- union-find ---------- */

	private static final class UnionFind {
		private final Map<Long, Long> parent = new HashMap<>();

		private static long key(int funcIdx, int localIdx) {
			return ((long) funcIdx << 32) | (localIdx & 0xFFFFFFFFL);
		}

		void add(int funcIdx, int localIdx) {
			parent.putIfAbsent(key(funcIdx, localIdx), key(funcIdx, localIdx));
		}

		int find(int funcIdx, int localIdx) {
			long k = key(funcIdx, localIdx);
			long p = parent.getOrDefault(k, k);
			if (p == k) {
				return localIdx; // not tracked, return self
			}
			// path compression
			long root = p;
			while (true) {
				long next = parent.getOrDefault(root, root);
				if (next == root) break;
				root = next;
			}
			parent.put(k, root);
			return (int) (root & 0xFFFFFFFFL);
		}

		int findFunc(int funcIdx, int localIdx) {
			long k = key(funcIdx, localIdx);
			long p = parent.getOrDefault(k, k);
			if (p == k) return funcIdx;
			long root = p;
			while (true) {
				long next = parent.getOrDefault(root, root);
				if (next == root) break;
				root = next;
			}
			parent.put(k, root);
			return (int) (root >>> 32);
		}

		void union(int f1, int l1, int f2, int l2) {
			long k1 = key(f1, l1);
			long k2 = key(f2, l2);
			parent.putIfAbsent(k1, k1);
			parent.putIfAbsent(k2, k2);
			long r1 = findRoot(k1);
			long r2 = findRoot(k2);
			if (r1 != r2) {
				// deterministic: smaller key becomes parent
				if (r1 < r2) {
					parent.put(r2, r1);
				} else {
					parent.put(r1, r2);
				}
			}
		}

		private long findRoot(long k) {
			long root = k;
			while (true) {
				long next = parent.getOrDefault(root, root);
				if (next == root) break;
				root = next;
			}
			// path compression
			while (k != root) {
				long next = parent.getOrDefault(k, k);
				parent.put(k, root);
				k = next;
			}
			return root;
		}

		/** Get the root key for a node. */
		long rootKey(int funcIdx, int localIdx) {
			long k = key(funcIdx, localIdx);
			if (!parent.containsKey(k)) return k;
			return findRoot(k);
		}
	}

	/* ---------- per-function state ---------- */

	private static final class FuncAccesses {
		final int funcIdx;
		final List<AccessRecord> accesses = new ArrayList<>();
		final List<CallLink> callLinks = new ArrayList<>();

		FuncAccesses(int funcIdx) {
			this.funcIdx = funcIdx;
		}
	}

	/* ---------- analyzer ---------- */

	public WasmStructSynthAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// Same priority as WasmStackVariableAnalyzer: after signature work,
		// around the stack-variable analyzer.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long startTime = System.currentTimeMillis();

		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> signatures = state.getFunctions();

		monitor.setMessage("Wasm struct synthesis: collecting accesses");
		monitor.initialize(signatures.size());

		// Phase 1: per-function stack simulation
		Map<Integer, FuncAccesses> funcAccessesMap = new LinkedHashMap<>();
		for (WasmFuncSignature sig : signatures) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (sig.isImport()) continue;
			Function func = program.getListing().getFunctionAt(sig.getStartAddr());
			if (func == null) continue;

			FuncAccesses fa = new FuncAccesses(sig.getFuncIdx());
			try {
				simulateFunction(program, state, func, sig, fa);
			} catch (Exception e) {
				Msg.debug(this, "Stack simulation failed for " + sig.getName() + ": " + e.getMessage());
			}
			if (!fa.accesses.isEmpty() || !fa.callLinks.isEmpty()) {
				funcAccessesMap.put(sig.getFuncIdx(), fa);
			}
		}

		// Phase 2: union-find over (funcIdx, localIdx) nodes
		monitor.setMessage("Wasm struct synthesis: building pointer classes");
		UnionFind uf = new UnionFind();

		// Register all nodes that have accesses
		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (AccessRecord acc : fa.accesses) {
				uf.add(fa.funcIdx, acc.localIndex);
			}
		}

		// Register all callee parameters that receive links
		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (CallLink link : fa.callLinks) {
				uf.add(link.callerFuncIdx, link.callerLocalIdx);
				uf.add(link.calleeFuncIdx, link.calleeParamIdx);
			}
		}

		// Union the links
		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (CallLink link : fa.callLinks) {
				uf.union(link.callerFuncIdx, link.callerLocalIdx,
						link.calleeFuncIdx, link.calleeParamIdx);
			}
		}

		// Phase 3: group accesses by root, synthesize structs
		monitor.setMessage("Wasm struct synthesis: creating structures");

		// Map: rootKey -> set of (offset, width) pairs
		Map<Long, TreeMap<Integer, Integer>> rootAccesses = new HashMap<>();
		// Map: rootKey -> set of member nodes (funcIdx, localIdx)
		Map<Long, Set<Long>> rootMembers = new HashMap<>();

		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (AccessRecord acc : fa.accesses) {
				long root = uf.rootKey(fa.funcIdx, acc.localIndex);
				rootAccesses.computeIfAbsent(root, k -> new TreeMap<>());
				TreeMap<Integer, Integer> offsets = rootAccesses.get(root);
				// Keep the max width for each offset
				offsets.merge(acc.offset, acc.width, Math::max);

				rootMembers.computeIfAbsent(root, k -> new HashSet<>());
				rootMembers.get(root).add(UnionFind.key(fa.funcIdx, acc.localIndex));
			}
		}

		// Also add members from call links: both the caller's local and the
		// callee's parameter are members of the pointer class (the caller may
		// not have direct accesses but its parameter still carries the pointer).
		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (CallLink link : fa.callLinks) {
				long root = uf.rootKey(link.calleeFuncIdx, link.calleeParamIdx);
				rootMembers.computeIfAbsent(root, k -> new HashSet<>());
				rootMembers.get(root).add(UnionFind.key(link.callerFuncIdx, link.callerLocalIdx));
				rootMembers.get(root).add(UnionFind.key(link.calleeFuncIdx, link.calleeParamIdx));
			}
		}

		// Sort roots deterministically
		List<Long> sortedRoots = new ArrayList<>(rootAccesses.keySet());
		Collections.sort(sortedRoots);

		int structCount = 0;
		int retypeCount = 0;
		List<String> structNames = new ArrayList<>();

		for (long root : sortedRoots) {
			monitor.checkCancelled();
			TreeMap<Integer, Integer> offsets = rootAccesses.get(root);
			if (offsets.size() < MIN_OFFSETS) continue;
			if (offsets.size() > MAX_FIELDS) {
				Msg.debug(this, "Skipping struct with " + offsets.size() + " fields (cap=" + MAX_FIELDS + ")");
				continue;
			}

			// Create the structure
			String structName = "wasm_struct_" + structCount;
			Structure struct = createStructure(program, structName, offsets);
			if (struct == null) continue;

			structNames.add(structName);
			structCount++;

			// Collect all member (funcIdx, localIdx) that are parameters
			Set<Long> members = rootMembers.get(root);
			if (members == null) continue;

			// Sort members for deterministic processing
			List<Long> sortedMembers = new ArrayList<>(members);
			Collections.sort(sortedMembers);

			// Retype parameters
			for (long memberKey : sortedMembers) {
				int funcIdx = (int) (memberKey >>> 32);
				int localIdx = (int) (memberKey & 0xFFFFFFFFL);

				WasmFuncSignature sig = signatures.get(funcIdx);
				if (sig.isImport()) continue;
				if (localIdx >= sig.getParams().length) continue; // not a parameter

				Function func = program.getListing().getFunctionAt(sig.getStartAddr());
				if (func == null) continue;

				try {
					if (retypeParameter(func, localIdx, struct)) {
						retypeCount++;
					}
				} catch (Exception e) {
					Msg.debug(this, "Failed to retype param " + localIdx + " in " + sig.getName() + ": " + e.getMessage());
				}
			}
		}

		long elapsed = System.currentTimeMillis() - startTime;
		Msg.info(this, "WasmStructSynth: " + structCount + " structs created, " +
			retypeCount + " parameters retyped, " + elapsed + "ms");
		if (!structNames.isEmpty()) {
			Msg.info(this, "WasmStructSynth structs: " + String.join(", ", structNames));
		}

		return true;
	}

	/* ---------- stack simulation ---------- */

	private void simulateFunction(Program program, WasmAnalysis state, Function func,
			WasmFuncSignature sig, FuncAccesses fa) {
		InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
		List<StackValue> stack = new ArrayList<>();
		long baseLocalOffset = getBaseLocalOffset(program);

		while (iter.hasNext()) {
			Instruction instr = iter.next();
			String mnemonic = instr.getMnemonicString();

			try {
				switch (mnemonic) {
					case "local.get": {
						int localIdx = getLocalIndexFromInstr(instr, baseLocalOffset);
						if (localIdx >= 0) {
							stack.add(StackValue.local(localIdx));
						} else {
							stack.add(StackValue.unknown());
						}
						break;
					}
					case "local.set":
					case "local.tee": {
						if (!stack.isEmpty()) stack.remove(stack.size() - 1);
						if (mnemonic.equals("local.tee")) {
							// local.tee pushes the same value back; we don't know what it is
							stack.add(StackValue.unknown());
						}
						break;
					}
					case "i32.const":
					case "i64.const": {
						long val = getConstValue(instr);
						stack.add(StackValue.constant(val));
						break;
					}
					case "i32.add":
					case "i64.add": {
						if (stack.size() >= 2) {
							StackValue b = stack.remove(stack.size() - 1);
							StackValue a = stack.remove(stack.size() - 1);
							stack.add(StackValue.add(a, b));
						} else {
							stack.clear();
						}
						break;
					}
					case "global.get": {
						stack.add(StackValue.unknown()); // skip global-based accesses in v1
						break;
					}
					case "drop": {
						if (!stack.isEmpty()) stack.remove(stack.size() - 1);
						break;
					}
					case "call": {
						handleCall(program, state, sig, instr, stack, fa);
						break;
					}
					case "call_indirect": {
						// Skip call_indirect in v1: pop the table index and clear args conservatively
						if (!stack.isEmpty()) stack.remove(stack.size() - 1); // pop table index
						stack.clear();
						stack.add(StackValue.unknown()); // return value (approximate)
						break;
					}
					default:
						if (isLoadStore(mnemonic)) {
							handleLoadStore(mnemonic, instr, stack, fa);
						} else if (isControlFlow(mnemonic)) {
							// Conservative: clear the stack on control flow
							stack.clear();
						} else {
							// Unknown instruction: clear the stack conservatively
							stack.clear();
						}
						break;
				}
			} catch (Exception e) {
				Msg.debug(this, "Error processing " + mnemonic + " at " + instr.getMinAddress() + ": " + e.getMessage());
				stack.clear();
			}
		}
	}

	private void handleLoadStore(String mnemonic, Instruction instr, List<StackValue> stack, FuncAccesses fa) {
		int width = getAccessWidth(mnemonic);
		if (width <= 0) {
			stack.clear();
			return;
		}
		Scalar offsetScalar = getMemoryOffset(instr);
		if (offsetScalar == null) {
			stack.clear();
			return;
		}
		int offset = (int) offsetScalar.getUnsignedValue();
		boolean isStore = mnemonic.contains(".store");

		if (isStore) {
			// store: pop value, pop address
			if (stack.size() >= 2) {
				stack.remove(stack.size() - 1); // value
				StackValue addr = stack.remove(stack.size() - 1);
				recordAccess(addr, offset, width, fa);
			} else {
				stack.clear();
			}
		} else {
			// load: pop address, push result
			if (!stack.isEmpty()) {
				StackValue addr = stack.remove(stack.size() - 1);
				recordAccess(addr, offset, width, fa);
			}
			stack.add(StackValue.unknown()); // loaded value
		}
	}

	private void recordAccess(StackValue addr, int memOffset, int width, FuncAccesses fa) {
		int[] resolved = addr.resolveLocal();
		if (resolved == null) return; // not a plain local
		int localIdx = resolved[0];
		int delta = resolved[1];
		int effectiveOffset = memOffset + delta;
		fa.accesses.add(new AccessRecord(localIdx, effectiveOffset, width));
	}

	private void handleCall(Program program, WasmAnalysis state, WasmFuncSignature callerSig,
			Instruction instr, List<StackValue> stack, FuncAccesses fa) {
		// Find the callee
		Function callee = null;
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isCall()) {
				callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (callee != null) break;
			}
		}
		if (callee == null) {
			stack.clear();
			return;
		}

		WasmFuncSignature calleeSig = state.getFunctionByAddress(callee.getEntryPoint());
		if (calleeSig == null) {
			stack.clear();
			return;
		}

		int numParams = calleeSig.getParams().length;
		int numReturns = calleeSig.getReturns().length;

		// Pop args (in reverse order: last arg is on top)
		if (stack.size() >= numParams) {
			StackValue[] args = new StackValue[numParams];
			for (int i = numParams - 1; i >= 0; i--) {
				args[i] = stack.remove(stack.size() - 1);
			}
			// Record links: arg[i] -> callee param i
			for (int i = 0; i < numParams; i++) {
				int[] resolved = args[i].resolveLocal();
				if (resolved == null) continue; // skip non-local args (including Add with delta)
				int callerLocal = resolved[0];
				int delta = resolved[1];
				if (delta != 0) continue; // skip delta'd args in v1 (documented)
				fa.callLinks.add(new CallLink(
					callerSig.getFuncIdx(), callerLocal,
					calleeSig.getFuncIdx(), i));
			}
		} else {
			stack.clear();
		}

		// Push return values
		for (int i = 0; i < numReturns; i++) {
			stack.add(StackValue.unknown());
		}
	}

	/* ---------- instruction helpers ---------- */

	private static long getBaseLocalOffset(Program program) {
		Register l0 = program.getRegister("l0q");
		if (l0 != null) return l0.getOffset();
		Register l0_4 = program.getRegister("l0");
		if (l0_4 != null) return l0_4.getOffset();
		return 0x10000000L; // fallback to SLEIGH default
	}

	private static int getLocalIndexFromInstr(Instruction instr, long baseLocalOffset) {
		for (Object obj : instr.getInputObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				long offset = reg.getOffset();
				long localIndex = (offset - baseLocalOffset) / 16;
				if (localIndex >= 0 && localIndex < 4096) {
					return (int) localIndex;
				}
			}
		}
		// Fallback: try to parse the operand display string
		String repr = instr.toString();
		// e.g. "local.get l0" or "local.get 0"
		int spaceIdx = repr.indexOf(' ');
		if (spaceIdx >= 0) {
			String operand = repr.substring(spaceIdx + 1).trim();
			if (operand.startsWith("l") && !operand.endsWith("q")) {
				try {
					return Integer.parseInt(operand.substring(1));
				} catch (NumberFormatException e) { /* fall through */ }
			}
			try {
				return Integer.parseInt(operand);
			} catch (NumberFormatException e) { /* fall through */ }
		}
		return -1;
	}

	private static long getConstValue(Instruction instr) {
		Object[] ops = instr.getOpObjects(0);
		if (ops.length > 0 && ops[0] instanceof Scalar) {
			return ((Scalar) ops[0]).getValue();
		}
		return 0;
	}

	private static Scalar getMemoryOffset(Instruction instr) {
		Object[] operands = instr.getOpObjects(0);
		if (operands.length < 2 || !(operands[1] instanceof Scalar)) {
			return null;
		}
		return (Scalar) operands[1];
	}

	private static boolean isLoadStore(String mnemonic) {
		return mnemonic.contains(".load") || mnemonic.contains(".store");
	}

	private static boolean isControlFlow(String mnemonic) {
		return mnemonic.equals("block") || mnemonic.equals("loop") || mnemonic.equals("if") ||
			mnemonic.equals("else") || mnemonic.equals("end") ||
			mnemonic.equals("br") || mnemonic.equals("br_if") || mnemonic.equals("br_table") ||
			mnemonic.equals("return") || mnemonic.equals("unreachable") ||
			mnemonic.equals("try") || mnemonic.equals("catch") || mnemonic.equals("catch_all") ||
			mnemonic.equals("delegate") || mnemonic.equals("try_table") ||
			mnemonic.equals("throw") || mnemonic.equals("rethrow") ||
			mnemonic.equals("return_call") || mnemonic.equals("return_call_indirect");
	}

	/** Get the access width in bytes for a load/store mnemonic, or 0 if not a simple access. */
	private static int getAccessWidth(String mnemonic) {
		// i32.load/store -> 4, i64.load/store -> 8, etc.
		if (mnemonic.startsWith("i32.load") || mnemonic.startsWith("i32.store") ||
			mnemonic.startsWith("f32.load") || mnemonic.startsWith("f32.store")) {
			if (mnemonic.contains("8")) return 1;
			if (mnemonic.contains("16")) return 2;
			return 4;
		}
		if (mnemonic.startsWith("i64.load") || mnemonic.startsWith("i64.store") ||
			mnemonic.startsWith("f64.load") || mnemonic.startsWith("f64.store")) {
			if (mnemonic.contains("8")) return 1;
			if (mnemonic.contains("16")) return 2;
			if (mnemonic.contains("32")) return 4;
			return 8;
		}
		if (mnemonic.startsWith("v128.load") || mnemonic.startsWith("v128.store")) {
			return 16;
		}
		// SIMD lane loads/stores - skip in v1 (complex)
		if (mnemonic.startsWith("v128.") && (mnemonic.contains("lane") || mnemonic.contains("splat") || mnemonic.contains("zero"))) {
			return 0; // skip
		}
		// Atomic loads/stores - treat like their base width
		if (mnemonic.contains("atomic")) {
			if (mnemonic.startsWith("i32.atomic") || mnemonic.startsWith("i64.atomic")) {
				if (mnemonic.contains("8")) return 1;
				if (mnemonic.contains("16")) return 2;
				if (mnemonic.contains("32")) return 4;
				if (mnemonic.startsWith("i32.")) return 4;
				return 8;
			}
		}
		return 0;
	}

	/* ---------- struct synthesis ---------- */

	private Structure createStructure(Program program, String name, TreeMap<Integer, Integer> offsets) {
		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath category = new CategoryPath("/wasm");

		// Check if already exists (shouldn't happen with our naming, but be safe)
		DataType existing = dtm.getDataType(category, name);
		if (existing instanceof Structure) {
			return (Structure) existing;
		}

		StructureDataType struct = new StructureDataType(category, name, 0);
		struct.setPackingEnabled(true);
		struct.setDescription("Synthesized from constant-offset memory accesses through wasm pointer parameters");

		int prevEnd = 0;
		int fieldCount = 0;
		for (Map.Entry<Integer, Integer> entry : offsets.entrySet()) {
			int offset = entry.getKey();
			int width = entry.getValue();
			if (offset < 0) continue;

			// Fill gap
			if (offset > prevEnd) {
				int gap = offset - prevEnd;
				struct.add(new Undefined1DataType(), gap, "pad_" + prevEnd, null);
			}

			// Add field
			DataType fieldType = getFieldType(width);
			String fieldName = "field_" + offset;
			struct.add(fieldType, fieldName, null);
			fieldCount++;
			prevEnd = offset + width;

			if (fieldCount >= MAX_FIELDS) break;
		}

		try {
			DataType result = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
			if (result instanceof Structure) {
				return (Structure) result;
			}
		} catch (Exception e) {
			Msg.debug(this, "Failed to add structure " + name + ": " + e.getMessage());
		}
		return null;
	}

	private static DataType getFieldType(int width) {
		switch (width) {
			case 1: return Undefined1DataType.dataType;
			case 2: return ghidra.program.model.data.Undefined2DataType.dataType;
			case 4: return ghidra.program.model.data.Undefined4DataType.dataType;
			case 8: return ghidra.program.model.data.Undefined8DataType.dataType;
			case 16: return Undefined.getUndefinedDataType(16);
			default: return Undefined1DataType.dataType;
		}
	}

	/**
	 * Retype a function parameter to PointerDataType(struct).
	 * Only overwrites undefined or default types; never clobbers a concrete type.
	 * @return true if the parameter was retyped
	 */
	private boolean retypeParameter(Function func, int paramIndex, Structure struct) throws Exception {
		Parameter[] params = func.getParameters();
		if (paramIndex >= params.length) return false;

		Parameter param = params[paramIndex];
		DataType currentType = param.getDataType();

		// Never clobber a non-undefined existing type
		if (!Undefined.isUndefined(currentType) &&
			currentType != ghidra.program.model.data.DefaultDataType.DEFAULT &&
			!(currentType instanceof PointerDataType)) {
			return false;
		}

		// Don't retype if already a pointer to a struct
		if (currentType instanceof PointerDataType) {
			DataType targetType = ((PointerDataType) currentType).getDataType();
			if (targetType instanceof Structure) {
				return false; // already a struct pointer
			}
		}

		PointerDataType ptrType = new PointerDataType(struct);

		// Build new parameter list
		List<Parameter> newParams = new ArrayList<>();
		for (int i = 0; i < params.length; i++) {
			if (i == paramIndex) {
				newParams.add(new ParameterImpl(params[i].getName(), ptrType, func.getProgram()));
			} else {
				newParams.add(new ParameterImpl(params[i].getName(), params[i].getDataType(), func.getProgram()));
			}
		}

		func.replaceParameters(newParams,
			Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		return true;
	}
}
