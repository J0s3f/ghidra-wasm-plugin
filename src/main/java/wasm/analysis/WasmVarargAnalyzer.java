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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;

/**
 * Resolves variadic calls (printf/scanf families) that use the Emscripten
 * vararg ABI: the caller packs variadic arguments into a stack buffer and
 * passes a single pointer to it as the last parameter. Without help, the
 * decompiler shows printf(fmt, buffer_ptr).
 *
 * For each such callsite this analyzer:
 * 1. recovers the constant format-string address (SymbolicPropogator) and
 *    reads the string from the loaded data segments,
 * 2. derives the variadic argument types and va-buffer offsets from the
 *    format specifiers,
 * 3. records a WasmVarargInfo property consumed by
 *    InjectPayloadWasmCallPrologue, which injects p-code loading each vararg
 *    from the buffer into the artificial input registers,
 * 4. writes a callsite prototype override so the decompiler consumes those
 *    registers as real arguments (with correct types), and
 * 5. types the format string as a terminated C string.
 *
 * Result: printf("a+b=%d\n", x + y) instead of printf(fmt, buf), plus type
 * propagation onto the arguments (especially valuable for scanf: %d types the
 * pointed-to local as int).
 */
public class WasmVarargAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Vararg Analyzer";
	private static final String DESCRIPTION =
		"Resolves printf/scanf-family varargs passed via the Emscripten stack-buffer ABI, " +
		"so the decompiler shows the real argument values and types.";

	/* family: false = printf-like (values), true = scanf-like (pointers) */
	private static final Map<String, Boolean> VARARG_FUNCS = new HashMap<>();
	static {
		for (String s : new String[] { "printf", "iprintf", "__small_printf", "fprintf",
				"fiprintf", "__small_fprintf", "sprintf", "siprintf", "__small_sprintf",
				"snprintf", "sniprintf", "asprintf", "dprintf" }) {
			VARARG_FUNCS.put(s, false);
		}
		for (String s : new String[] { "scanf", "iscanf", "__small_scanf", "fscanf",
				"fiscanf", "sscanf", "siscanf", "__isoc99_scanf", "__isoc99_fscanf",
				"__isoc99_sscanf" }) {
			VARARG_FUNCS.put(s, true);
		}
	}

	private static final Pattern SPEC_PATTERN = Pattern.compile(
		"%[-+ #0']*(\\*|\\d+)?(?:\\.(\\*|\\d+))?(hh|h|ll|l|j|z|t|L)?([diouxXeEfFgGaAcspn%]|\\[\\^?\\]?[^\\]]*\\])");

	public WasmVarargAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		/* after WasmStackVariableAnalyzer */
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.initialize(program.getFunctionManager().getFunctionCount());
		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.setMessage("Wasm varargs " + function.getName());
			monitor.incrementProgress(1);
			try {
				processFunction(program, function, monitor);
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				Msg.warn(this, "Vararg analysis failed for " + function.getName() + ": " + e);
			}
		}
		return true;
	}

	private static class VarargCallsite {
		Instruction instr;
		Function callee;
		boolean isScanf;
		/*
		 * true when this call was NOT identified by a known printf/scanf name but
		 * only by structure (a constant %-format string in the last fixed arg).
		 * Such calls are rewritten only if the format string actually contains a
		 * conversion specifier, to avoid misfiring on ordinary functions that
		 * happen to take a string and a pointer.
		 */
		boolean structural;
	}

	private void processFunction(Program program, Function function, TaskMonitor monitor)
			throws Exception {
		/* collect variadic callsites first; skip the (expensive) constant
		 * propagation entirely if there are none */
		List<VarargCallsite> sites = new ArrayList<>();
		InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();
			if (!instr.getMnemonicString().equals("call"))
				continue;
			for (Reference ref : instr.getReferencesFrom()) {
				if (!ref.getReferenceType().isCall())
					continue;
				Function callee =
					program.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (callee == null)
					continue;
				Boolean isScanf = VARARG_FUNCS.get(callee.getName());
				VarargCallsite site = new VarargCallsite();
				site.instr = instr;
				site.callee = callee;
				if (isScanf != null) {
					/* known printf/scanf-family by name */
					site.isScanf = isScanf;
					site.structural = false;
				} else {
					/*
					 * Unknown name (e.g. stripped/release binary where the name
					 * section is gone, or a renamed wrapper). Treat as a
					 * structural candidate: processCallsite will only rewrite it
					 * if its last fixed argument is a constant format string with
					 * real conversion specifiers. Default to printf-style since
					 * scanf can't be told apart from the format string alone.
					 */
					site.isScanf = false;
					site.structural = true;
				}
				sites.add(site);
			}
		}
		if (sites.isEmpty())
			return;

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionAnalysis funcAnalysis =
			state.getFunctionAnalysis(function.getEntryPoint());
		if (funcAnalysis == null)
			return;

		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.flowConstants(function.getEntryPoint(), function.getBody(),
			new ContextEvaluatorAdapter(), true, monitor);

		for (VarargCallsite site : sites) {
			try {
				processCallsite(program, function, funcAnalysis, symEval, site);
			} catch (Exception e) {
				Msg.warn(this, "Vararg fix failed at " + site.instr.getMinAddress() + ": " + e);
			}
		}
	}

	private void processCallsite(Program program, Function caller,
			WasmFunctionAnalysis funcAnalysis, SymbolicPropogator symEval, VarargCallsite site)
			throws Exception {
		Address callAddr = site.instr.getMinAddress();
		WasmFuncSignature calleeSig =
			state(program).getFunctionByAddress(site.callee.getEntryPoint());
		if (calleeSig == null)
			return;
		int numParams = calleeSig.getParams().length;
		if (numParams < 2)
			return; /* no (fmt, va_buffer) pair */
		int fmtIdx = numParams - 2;
		int bufIdx = numParams - 1;

		StackEffect stackEffect = funcAnalysis.getStackEffect(callAddr);
		if (stackEffect == null || stackEffect.getToPop().length < numParams)
			return;
		int popHeight = stackEffect.getPopHeight();

		/* recover the constant format-string pointer from the operand stack */
		Register fmtReg = program.getRegister("s" + (popHeight + fmtIdx));
		if (fmtReg == null)
			return;
		SymbolicPropogator.Value val = symEval.getRegisterValue(callAddr, fmtReg);
		if (val == null || val.isRegisterRelativeValue())
			return;
		long fmtAddrOffset = val.getValue() & 0xFFFFFFFFL;
		Address fmtAddr =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(fmtAddrOffset);
		String fmt = readCString(program.getMemory(), fmtAddr);
		if (fmt == null)
			return;

		/* parse format specifiers into (type, size) slots */
		List<DataType> varargTypes = new ArrayList<>();
		List<Integer> varargSizes = new ArrayList<>();
		if (!parseFormat(program, fmt, site.isScanf, varargTypes, varargSizes))
			return;

		/*
		 * Structural (name-unknown) gate: require at least one conversion
		 * specifier before believing this is a variadic call. Also require the
		 * string to be reasonably printable to reject pointers into binary data
		 * that happen to constant-propagate here. Named calls skip this: a bare
		 * printf("done\n") with no specifiers is still a legitimate rewrite.
		 */
		if (site.structural) {
			if (varargTypes.isEmpty() || !looksLikeFormatString(fmt))
				return;
		}

		/* va-buffer offsets: 4-byte slots, 8-byte values 8-aligned */
		int[] offsets = new int[varargTypes.size()];
		int[] sizes = new int[varargTypes.size()];
		int cur = 0;
		for (int i = 0; i < varargTypes.size(); i++) {
			int size = varargSizes.get(i);
			if (size == 8)
				cur = (cur + 7) & ~7;
			offsets[i] = cur;
			sizes[i] = size;
			cur += size;
		}

		/* build the overridden prototype: fixed params (minus the va buffer)
		 * + one param per format specifier */
		List<ParameterDefinition> params = new ArrayList<>();
		for (int i = 0; i < fmtIdx; i++) {
			DataType dt = IntegerDataType.dataType;
			if (i < site.callee.getParameterCount()) {
				DataType cur2 = site.callee.getParameter(i).getDataType();
				if (cur2 != null && !(cur2 instanceof VoidDataType))
					dt = cur2;
			}
			params.add(new ParameterDefinitionImpl(null, dt, null));
		}
		params.add(new ParameterDefinitionImpl("format",
			new PointerDataType(CharDataType.dataType), null));
		for (DataType dt : varargTypes) {
			params.add(new ParameterDefinitionImpl(null, dt, null));
		}

		FunctionDefinitionDataType fdef =
			new FunctionDefinitionDataType(site.callee.getName());
		fdef.setReturnType(IntegerDataType.dataType);
		fdef.setArguments(params.toArray(new ParameterDefinition[0]));

		HighFunctionDBUtil.writeOverride(caller, callAddr, fdef);
		if (varargTypes.size() > 0) {
			WasmVarargInfo.put(program, callAddr,
				new WasmVarargInfo(bufIdx, offsets, sizes));
		}

		/* Make the format string render as a string literal. This address is
		 * demonstrably a C string (it was just parsed as this call's format
		 * string), so override any conflicting non-string data — e.g. when the
		 * string's own bytes happen to decode as a plausible address ("%d " =
		 * 0x00206425) and the address-table analyzer typed it as a pointer. */
		try {
			Data existing = program.getListing().getDefinedDataAt(fmtAddr);
			if (existing == null || !(existing.getDataType() instanceof AbstractStringDataType)) {
				DataUtilities.createData(program, fmtAddr, TerminatedStringDataType.dataType,
					-1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
		} catch (Exception e) {
			/* non-fatal */
		}
	}

	private static WasmAnalysis state(Program program) {
		return WasmAnalysis.getState(program);
	}

	/**
	 * Heuristic guard for structural detection: the string must be non-trivial
	 * and made of printable/whitespace characters, so we don't rewrite a call
	 * whose "format" is really a pointer into binary data.
	 */
	private static boolean looksLikeFormatString(String s) {
		if (s.length() < 2)
			return false;
		int printable = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c >= 0x20 && c < 0x7F)
				printable++;
			else if (c != '\n' && c != '\t' && c != '\r')
				return false; /* control/binary byte: not a format string */
		}
		return printable >= 2;
	}

	private static String readCString(Memory mem, Address addr) {
		StringBuilder sb = new StringBuilder();
		try {
			for (int i = 0; i < 4096; i++) {
				byte b = mem.getByte(addr.add(i));
				if (b == 0)
					return sb.toString();
				sb.append((char) (b & 0xFF));
			}
		} catch (Exception e) {
			return null;
		}
		return null;
	}

	/**
	 * Derive vararg types/sizes from a format string.
	 * Returns false if the format uses features we can't model statically.
	 */
	private static boolean parseFormat(Program program, String fmt, boolean isScanf,
			List<DataType> types, List<Integer> sizes) {
		DataType charPtr = new PointerDataType(CharDataType.dataType);
		DataType voidPtr = new PointerDataType(VoidDataType.dataType);
		Matcher m = SPEC_PATTERN.matcher(fmt);
		int end = 0;
		while (m.find()) {
			end = m.end();
			String width = m.group(1);
			String prec = m.group(2);
			String len = m.group(3) == null ? "" : m.group(3);
			String conv = m.group(4);
			if (conv.equals("%"))
				continue;
			if (isScanf) {
				if ("*".equals(width))
					continue; /* assignment-suppressed: consumes no argument */
				DataType base;
				switch (conv.charAt(0)) {
				case 'd': case 'i': case 'u': case 'o': case 'x': case 'X':
					if (len.equals("hh"))
						base = CharDataType.dataType;
					else if (len.equals("h"))
						base = ShortDataType.dataType;
					else if (len.equals("ll") || len.equals("j"))
						base = LongLongDataType.dataType;
					else
						base = IntegerDataType.dataType;
					break;
				case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A':
					base = len.equals("l") ? DoubleDataType.dataType
							: len.equals("L") ? DoubleDataType.dataType
							: FloatDataType.dataType;
					break;
				case 'c': case 's': case '[':
					types.add(charPtr);
					sizes.add(4);
					continue;
				case 'p':
					types.add(new PointerDataType(voidPtr));
					sizes.add(4);
					continue;
				case 'n':
					types.add(new PointerDataType(IntegerDataType.dataType));
					sizes.add(4);
					continue;
				default:
					return false;
				}
				types.add(new PointerDataType(base));
				sizes.add(4);
			} else {
				/* dynamic width/precision each consume an int argument */
				if ("*".equals(width)) {
					types.add(IntegerDataType.dataType);
					sizes.add(4);
				}
				if ("*".equals(prec)) {
					types.add(IntegerDataType.dataType);
					sizes.add(4);
				}
				switch (conv.charAt(0)) {
				case 'd': case 'i':
					if (len.equals("ll") || len.equals("j")) {
						types.add(LongLongDataType.dataType);
						sizes.add(8);
					} else {
						types.add(IntegerDataType.dataType);
						sizes.add(4);
					}
					break;
				case 'u': case 'o': case 'x': case 'X':
					if (len.equals("ll") || len.equals("j")) {
						types.add(UnsignedLongLongDataType.dataType);
						sizes.add(8);
					} else {
						types.add(UnsignedIntegerDataType.dataType);
						sizes.add(4);
					}
					break;
				case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A':
					/* float varargs are promoted to double */
					types.add(DoubleDataType.dataType);
					sizes.add(8);
					break;
				case 'c':
					types.add(CharDataType.dataType);
					sizes.add(4);
					break;
				case 's':
					types.add(charPtr);
					sizes.add(4);
					break;
				case 'p':
					types.add(voidPtr);
					sizes.add(4);
					break;
				case 'n':
					types.add(new PointerDataType(IntegerDataType.dataType));
					sizes.add(4);
					break;
				default:
					return false;
				}
			}
		}
		return true;
	}
}
