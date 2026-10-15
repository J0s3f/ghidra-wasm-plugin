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
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recognizes memory.copy instructions that materialize a .rodata initializer:
 * a copy of a constant number of bytes from a constant (read-only data-segment)
 * source into a destination buffer. For those it records the byte length so
 * InjectPayloadWasmMemoryCopy can unroll the copy, letting the decompiler fold
 * the read-only source into inline constant stores (recompilable) rather than
 * an opaque memory_copy() call. Dynamic copies (runtime src/len) are left alone
 * and retain an explicit Wasm copy intrinsic.
 */
public class WasmMemoryCopyAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Wasm Memory Copy Analyzer";
	private static final String DESCRIPTION =
		"Materializes constant .rodata initializers copied via memory.copy so they " +
		"decompile to inline array/struct initializers instead of memory_copy().";

	/* cap the unroll so a huge bulk copy doesn't explode into thousands of ops */
	private static final int MAX_BYTES = 1024;

	public WasmMemoryCopyAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
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
			monitor.incrementProgress(1);
			try {
				processFunction(program, function, monitor);
			} catch (CancelledException e) {
				throw e;
			} catch (Exception e) {
				Msg.warn(this, "memory.copy analysis failed for " + function.getName() + ": " + e);
			}
		}
		return true;
	}

	private void processFunction(Program program, Function function, TaskMonitor monitor)
			throws Exception {
		List<Instruction> sites = new ArrayList<>();
		InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();
			if (instr.getMnemonicString().equals("memory.copy")) {
				sites.add(instr);
			}
		}
		if (sites.isEmpty()) {
			return;
		}

		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.flowConstants(function.getEntryPoint(), function.getBody(),
			new ContextEvaluatorAdapter(), true, monitor);

		for (Instruction instr : sites) {
			try {
				processSite(program, symEval, instr);
			} catch (Exception e) {
				Msg.warn(this, "memory.copy fix failed at " + instr.getMinAddress() + ": " + e);
			}
		}
	}

	private void processSite(Program program, SymbolicPropogator symEval, Instruction instr) {
		Address addr = instr.getMinAddress();
		WasmMemoryCopyInfo.clear(program, addr);
		for (ghidra.program.model.pcode.PcodeOp op : instr.getPcode()) {
			if (op.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALLOTHER || op.getNumInputs() != 6) continue;
			int userop = (int) op.getInput(0).getOffset();
			if (!"memory_copy".equals(program.getLanguage().getUserDefinedOpName(userop))) continue;
			Long len = constantValue(program, symEval, addr, op.getInput(3));
			Long src = constantValue(program, symEval, addr, op.getInput(4));
			if (len == null || len < 1 || len > MAX_BYTES || src == null) return;
			int srcMemory = (int) op.getInput(2).getOffset();
			Address source = wasm.WasmLoader.getMemoryAddress(program.getAddressFactory(), srcMemory, src, op.getInput(4).getSize() == 8);
			ghidra.program.model.mem.MemoryBlock block = program.getMemory().getBlock(source);
			if (block != null && block.isInitialized() && !block.isWrite() && block.contains(source.add(len - 1))) {
				WasmMemoryCopyInfo.putLength(program, addr, len.intValue());
			}
			return;
		}
	}

	private static Long constantValue(Program program, SymbolicPropogator evaluator, Address site,
			ghidra.program.model.pcode.Varnode value) {
		if (value.isConstant()) return value.getOffset();
		Register register = program.getRegister(value);
		if (register == null) return null;
		SymbolicPropogator.Value result = evaluator.getRegisterValue(site, register);
		if (result == null || result.isRegisterRelativeValue()) return null;
		return value.getSize() == 4 ? result.getValue() & 0xffffffffL : result.getValue();
	}
}
