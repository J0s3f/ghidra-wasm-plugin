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
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers conservative structure views from constant-offset linear-memory accesses.
 * Weighted call constraints preserve interior pointers; inconsistent alias cycles are
 * discarded. Unknown control flow and indirect targets intentionally stop inference.
 */
public class WasmStructSynthAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Struct Synthesis Analyzer";
	private static final String DESCRIPTION =
		"Synthesize Ghidra structures from constant-offset memory accesses " +
		"through wasm pointers, linked via weighted call constraints.";

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
		static StackValue global(int idx) { return new StackValue(ValueKind.GLOBAL, -idx-1, 0, null); }
		static StackValue unknown() { return new StackValue(ValueKind.UNKNOWN, -1, 0, null); }

		static StackValue add(StackValue a, StackValue b) {
			// local + const  or  const + local
			if ((a.kind == ValueKind.LOCAL || a.kind == ValueKind.GLOBAL) && b.kind == ValueKind.CONST) {
				return new StackValue(ValueKind.ADD, a.localIndex, b.constValue, a);
			}
			if (a.kind == ValueKind.CONST && (b.kind == ValueKind.LOCAL || b.kind == ValueKind.GLOBAL)) {
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

		/** Resolve a local or global pointer plus a representable constant displacement. */
		int[] resolveLocal() {
			if (kind == ValueKind.LOCAL || kind == ValueKind.GLOBAL) {
				return new int[] { localIndex, 0 };
			}
			if (kind == ValueKind.ADD && base != null && (base.kind == ValueKind.LOCAL || base.kind == ValueKind.GLOBAL)) {
				if(constValue<Integer.MIN_VALUE || constValue>Integer.MAX_VALUE) return null;
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
		final DataType type;
		final int memory;

		AccessRecord(int localIndex, int offset, int width, DataType type, int memory) {
			this.localIndex = localIndex;
			this.offset = offset;
			this.width = width;
			this.type = type;
			this.memory = memory;
		}
	}

	/** A call-graph link: caller's local -> callee's parameter. */
	private static final class CallLink {
		final int callerFuncIdx;
		final int callerLocalIdx;
		final int calleeFuncIdx;
		final int calleeParamIdx;
		final int delta;

		CallLink(int callerFuncIdx, int callerLocalIdx, int calleeFuncIdx, int calleeParamIdx, int delta) {
			this.callerFuncIdx = callerFuncIdx;
			this.callerLocalIdx = callerLocalIdx;
			this.calleeFuncIdx = calleeFuncIdx;
			this.calleeParamIdx = calleeParamIdx;
			this.delta = delta;
		}
	}

	/* ---------- union-find ---------- */

	private static final class UnionFind {
		private final Map<Long, Long> parent = new HashMap<>(), weights = new HashMap<>();
		private final Set<Long> inconsistent = new HashSet<>();
		private static long key(int f, int l) { return ((long) (l<0?-1:f) << 32) | (l & 0xffffffffL); }
		void add(int f, int l) { long k=key(f,l); parent.putIfAbsent(k,k); weights.putIfAbsent(k,0L); }
		private long findRoot(long key) {
			long root=key,total=0;
			while(parent.getOrDefault(root,root)!=root) {
				total=Math.addExact(total,weights.get(root));root=parent.get(root);
			}
			while(key!=root) {
				long next=parent.get(key),edge=weights.get(key);
				parent.put(key,root);weights.put(key,total);
				total=Math.subtractExact(total,edge);key=next;
			}
			return root;
		}

		long rootKey(int f,int l) { add(f,l); return findRoot(key(f,l)); }
		long displacement(int f,int l) { rootKey(f,l); return weights.get(key(f,l)); }
		boolean valid(long root) { return !inconsistent.contains(root); }
		// Address(callee) = address(caller) + delta.
		void union(int f1,int l1,int f2,int l2,long delta) {
			long r1=rootKey(f1,l1),w1=displacement(f1,l1),r2=rootKey(f2,l2),w2=displacement(f2,l2);
			long shift=Math.subtractExact(Math.addExact(w1,delta),w2);
			if(r1==r2) { if(shift!=0) inconsistent.add(r1); return; }
			parent.put(r2,r1); weights.put(r2,shift);
			if(inconsistent.contains(r2)) inconsistent.add(r1);
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
		boolean mutableTables=tableMayChange(program);
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
				simulateFunction(program, state, func, sig, fa, mutableTables);
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
						link.calleeFuncIdx, link.calleeParamIdx, link.delta);
			}
		}

		// Phase 3: group accesses by root, synthesize structs
		monitor.setMessage("Wasm struct synthesis: creating structures");

		// Map: rootKey -> set of (offset, width) pairs
		Map<Long, TreeMap<Integer, Integer>> rootAccesses = new HashMap<>();
		Map<Long, Map<Integer, DataType>> rootTypes = new HashMap<>();
		Map<Long, Set<Integer>> rootMemories = new HashMap<>();
		// Map: rootKey -> set of member nodes (funcIdx, localIdx)
		Map<Long, Set<Long>> rootMembers = new HashMap<>();

		for (FuncAccesses fa : funcAccessesMap.values()) {
			for (AccessRecord acc : fa.accesses) {
				long root = uf.rootKey(fa.funcIdx, acc.localIndex);
				rootAccesses.computeIfAbsent(root, k -> new TreeMap<>());
				TreeMap<Integer, Integer> offsets = rootAccesses.get(root);
				// Keep the max width for each offset
				long position = Math.addExact(uf.displacement(fa.funcIdx, acc.localIndex), acc.offset);
				if (position < Integer.MIN_VALUE || position > Integer.MAX_VALUE) continue;
				int offset=(int) position;
				offsets.merge(offset, acc.width, Math::max);
				rootTypes.computeIfAbsent(root,k->new HashMap<>()).merge(offset, acc.type,
					(a,b)->a.isEquivalent(b)?a:getFieldType(Math.max(a.getLength(),b.getLength())));
				rootMemories.computeIfAbsent(root,k->new HashSet<>()).add(acc.memory);

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
			if (!uf.valid(root) || rootMemories.get(root).size()!=1) continue;
			if (offsets.size() < MIN_OFFSETS) continue;
			if (offsets.size() > MAX_FIELDS) {
				Msg.debug(this, "Skipping struct with " + offsets.size() + " fields (cap=" + MAX_FIELDS + ")");
				continue;
			}

			// Create the structure
			String structName = "wasm_struct_" + structCount;
			Structure struct = createStructure(program, structName, offsets, rootTypes.get(root));
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

				if(funcIdx==-1) {
					int global=-localIdx-1;
					var address=wasm.WasmLoader.getGlobalAddress(program.getAddressFactory(),global);
					var data=program.getListing().getDataAt(address);
					if(data!=null && Undefined.isUndefined(data.getDataType()) && (data.getLength()==4 || data.getLength()==8)) {
						var pointer=new PointerDataType(struct,data.getLength(),program.getDataTypeManager());
						program.getListing().clearCodeUnits(address,address.add(data.getLength()-1),false);
						try {program.getListing().createData(address,pointer);retypeCount++;}
						catch(ghidra.program.model.util.CodeUnitInsertionException e) {Msg.debug(this,"Could not retype global",e);}
					}
					continue;
				}
				WasmFuncSignature sig = signatures.get(funcIdx);
				if (sig.isImport()) continue;
				if(localIdx>=sig.getLocals().length) continue;

				Function func = program.getListing().getFunctionAt(sig.getStartAddr());
				if (func == null) continue;

				try {
					long displacement=uf.displacement(funcIdx,localIdx);
					Structure view=struct;
					if(displacement!=0) {
						TreeMap<Integer,Integer> shifted=new TreeMap<>();
						Map<Integer,DataType> shiftedTypes=new HashMap<>();
						for(var field:offsets.entrySet()) {
							long offset=field.getKey()-displacement;
							if(offset>=0 && offset<=Integer.MAX_VALUE) {
								shifted.put((int)offset,field.getValue());
								shiftedTypes.put((int)offset,rootTypes.get(root).get(field.getKey()));
							}
						}
						if(shifted.size()<MIN_OFFSETS) continue;
						view=createStructure(program,structName+"_view_"+Long.toHexString(memberKey),shifted,shiftedTypes);
					}
					if (view!=null && retypeLocal(func, sig, localIdx, view)) {
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
			WasmFuncSignature sig, FuncAccesses fa, boolean mutableTables) {
		InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
		List<StackValue> stack = new ArrayList<>();

		while (iter.hasNext()) {
			Instruction instr = iter.next();
			String mnemonic = instr.getMnemonicString();

			try {
				switch (mnemonic) {
					case "local.get": {
						int localIdx = (int)readIndex(instr,1);
						if (localIdx >= 0) {
							stack.add(StackValue.local(localIdx));
						} else {
							stack.add(StackValue.unknown());
						}
						break;
					}
					case "local.set":
					case "local.tee": {
						StackValue value=stack.isEmpty()?StackValue.unknown():stack.remove(stack.size()-1);
						int index=(int)readIndex(instr,1);
						int[] source=value.resolveLocal();
						if(source!=null) fa.callLinks.add(new CallLink(sig.getFuncIdx(),source[0],sig.getFuncIdx(),index,source[1]));
						if(mnemonic.equals("local.tee")) stack.add(StackValue.local(index));
						break;
					}
					case "v128.const":
					case "f32.const":
					case "f64.const":
						stack.add(StackValue.unknown());break;
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
						stack.add(StackValue.global((int)readIndex(instr,1)));
						break;
					}
					case "global.set":
					case "drop": {
						if (!stack.isEmpty()) stack.remove(stack.size() - 1);
						break;
					}
					case "call": {
						handleCall(program, state, sig, instr, stack, fa);
						break;
					}
					case "call_indirect": {
						StackValue index=stack.isEmpty()?StackValue.unknown():stack.remove(stack.size()-1);
						long table=readIndex(instr,2);
						WasmFuncSignature target=null;
						if(index.kind==ValueKind.CONST && index.constValue>=0 && !mutableTables) {
							long address=Integer.toUnsignedLong(program.getMemory().getInt(wasm.WasmLoader.getTableAddress(program.getAddressFactory(),(int)table,index.constValue)));
							target=state.getFunctionByAddress(program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
						}
						if(target!=null && new wasm.format.WasmTypeGraph(state.getModule()).isHeapSubtype(state.getModule().getFunctionTypeIndex(target.getFuncIdx()),readIndex(instr,1))) linkArguments(sig,target,stack,fa);
						else stack.clear();
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
		long rawOffset=offsetScalar.getUnsignedValue();
		if(rawOffset<0 || rawOffset>Integer.MAX_VALUE) {stack.clear();return;}
		int offset = (int) rawOffset;
		boolean isStore = mnemonic.contains(".store");
		if(!isStore && mnemonic.endsWith("_lane")) {
			if(stack.isEmpty()) return;
			stack.remove(stack.size()-1); // lane loads consume the old vector too
		}

		if (isStore) {
			// store: pop value, pop address
			if (stack.size() >= 2) {
				stack.remove(stack.size() - 1); // value
				StackValue addr = stack.remove(stack.size() - 1);
				recordAccess(addr, offset, width, accessType(mnemonic,width), memoryIndex(instr), fa);
			} else {
				stack.clear();
			}
		} else {
			// load: pop address, push result
			if (!stack.isEmpty()) {
				StackValue addr = stack.remove(stack.size() - 1);
				recordAccess(addr, offset, width, accessType(mnemonic,width), memoryIndex(instr), fa);
			}
			stack.add(StackValue.unknown()); // loaded value
		}
	}

	private void recordAccess(StackValue addr, int memOffset, int width, DataType type, int memory, FuncAccesses fa) {
		int[] resolved = addr.resolveLocal();
		if (resolved == null) return; // not a plain local
		int localIdx = resolved[0];
		int delta = resolved[1];
		long effectiveOffset = (long)memOffset + delta;
		if(effectiveOffset<0 || effectiveOffset+width>Integer.MAX_VALUE) return;
		fa.accesses.add(new AccessRecord(localIdx, (int)effectiveOffset, width, type, memory));
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

		linkArguments(callerSig,calleeSig,stack,fa);
	}
	private void linkArguments(WasmFuncSignature callerSig,WasmFuncSignature calleeSig,List<StackValue> stack,FuncAccesses fa) {

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
				if (resolved == null) continue; // skip non-local/global sources
				int callerLocal = resolved[0];
				int delta = resolved[1];

				fa.callLinks.add(new CallLink(
					callerSig.getFuncIdx(), callerLocal,
					calleeSig.getFuncIdx(), i, delta));
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

	private static long getConstValue(Instruction instr) {
		Object[] ops = instr.getOpObjects(0);
		if (ops.length > 0 && ops[0] instanceof Scalar) {
			return ((Scalar) ops[0]).getValue();
		}
		return 0;
	}

	private static Scalar getMemoryOffset(Instruction instr) {
		Object[] operands = instr.getOpObjects(0);
		if (operands.length < 2 || !(operands[operands.length - 1] instanceof Scalar)) {
			return null;
		}
		return (Scalar) operands[operands.length - 1];
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
			if(mnemonic.contains("8x8") || mnemonic.contains("16x4") || mnemonic.contains("32x2")) return 8;
			if(mnemonic.contains("8_")) return 1;
			if(mnemonic.contains("16_")) return 2;
			if(mnemonic.contains("32_")) return 4;
			if(mnemonic.contains("64_")) return 8;
			return 16;
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

	private static long readIndex(Instruction instruction,int which) {
		try {
			var reader=new ghidra.app.util.bin.BinaryReader(new ghidra.app.util.bin.ByteArrayProvider(instruction.getBytes()),true);
			reader.readNextByte();long value=0;
			for(int i=0;i<which;i++) value=reader.readNext(ghidra.program.model.data.LEB128::unsigned);
			return value;
		} catch(Exception e) {throw new IllegalArgumentException(e);}
	}
	private static boolean tableMayChange(Program program) {
		for(var ins:program.getListing().getInstructions(true)) {
			String op=ins.getMnemonicString();
			if(op.startsWith("table.") && !op.equals("table.get") && !op.equals("table.size")) return true;
		}
		var module=WasmAnalysis.getState(program).getModule();
		return !module.getImports(wasm.format.WasmEnums.WasmExternalKind.EXT_TABLE).isEmpty() || !module.getExports(wasm.format.WasmEnums.WasmExternalKind.EXT_TABLE).isEmpty();
	}
	private boolean retypeLocal(Function function,WasmFuncSignature signature,int index,Structure structure) throws Exception {
		if(index<signature.getParams().length) return retypeParameter(function,index,structure);
		int size=signature.getLocals()[index].getSize();
		if(size!=4 && size!=8) return false;
		long offset=getBaseLocalOffset(function.getProgram())+index*16L;
		for(var variable:function.getLocalVariables()) if(variable.isRegisterVariable() && variable.getRegister().getOffset()==offset) {
			if(!Undefined.isUndefined(variable.getDataType())) return false;
			variable.setDataType(new PointerDataType(structure,size,function.getProgram().getDataTypeManager()),SourceType.ANALYSIS);return true;
		}
		var register=function.getProgram().getLanguage().getRegister(function.getProgram().getAddressFactory().getRegisterSpace().getAddress(offset),size);
		if(register==null) return false;
		function.addLocalVariable(new ghidra.program.model.listing.LocalVariableImpl("local_"+index,0,
			new PointerDataType(structure,size,function.getProgram().getDataTypeManager()),register,function.getProgram()),SourceType.ANALYSIS);
		return true;
	}

	private static int memoryIndex(Instruction instruction) {
		var value=instruction.getProgram().getProgramContext().getValue(instruction.getProgram().getRegister("ctx_case_index"),instruction.getAddress(),false);
		return value==null?0:value.intValue();
	}
	private static DataType accessType(String mnemonic,int width) {
		DataType type=WasmStackVariableAnalyzer.getMemoryDataType(mnemonic);
		return type.getLength()==width?type:getFieldType(width);
	}

	/* ---------- struct synthesis ---------- */

	private Structure createStructure(Program program, String name, TreeMap<Integer, Integer> offsets) {
		return createStructure(program,name,offsets,Map.of());
	}
	private Structure createStructure(Program program, String name, TreeMap<Integer, Integer> offsets, Map<Integer,DataType> types) {
		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath category = new CategoryPath("/wasm");

		// Check if already exists (shouldn't happen with our naming, but be safe)
		DataType existing = dtm.getDataType(category, name);
		if (existing instanceof Structure) {
			return (Structure) existing;
		}

		StructureDataType struct = new StructureDataType(category, name, 0);
		struct.setPackingEnabled(false);
		struct.setDescription("Synthesized from constant-offset memory accesses through wasm pointer parameters");
		// Coalesce overlapping observations into one storage span. This preserves the
		// full observed extent, including a later access that crosses an earlier field.
		TreeMap<Integer, Integer> spans = new TreeMap<>();
		for (Map.Entry<Integer, Integer> entry : offsets.entrySet()) {
			int offset = entry.getKey();
			int width = entry.getValue();
			if (offset < 0 || width <= 0 || (long) offset + width > Integer.MAX_VALUE) { continue; }
			Map.Entry<Integer, Integer> previous = spans.lastEntry();
			if (previous != null && offset < previous.getKey() + previous.getValue()) {
				spans.put(previous.getKey(), Math.max(previous.getValue(), offset + width - previous.getKey()));
			} else {
				spans.put(offset, width);
			}
		}

		int prevEnd = 0;
		int fieldCount = 0;
		for (Map.Entry<Integer, Integer> entry : spans.entrySet()) {
			int offset = entry.getKey();
			int width = entry.getValue();

			// Fill gap
			if (offset > prevEnd) {
				int gap = offset - prevEnd;
				struct.growStructure(gap);
			}

			// Add field
			DataType fieldType=types.getOrDefault(offset,getFieldType(width));
			if(fieldType.getLength()!=width || offsets.subMap(offset,false,offset+width,false).size()>0) fieldType=getFieldType(width);
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
			default: return Undefined.getUndefinedDataType(width);
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
			if(param.getSource()==SourceType.USER_DEFINED || targetType!=null && !Undefined.isUndefined(targetType) && targetType!=ghidra.program.model.data.DefaultDataType.DEFAULT) return false;
			if (targetType instanceof Structure) {
				return false; // already a struct pointer
			}
		}

		PointerDataType ptrType = new PointerDataType(struct, currentType.getLength(), func.getProgram().getDataTypeManager());

		param.setDataType(ptrType, SourceType.ANALYSIS);

		return true;
	}
}
