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
// Java-side verification driver for Wasm emulation, independent of PyGhidra.
//
// Loads a .wasm module, resolves an exported function and *invokes it through the
// emulator* (the same EmulatorHelper + WasmEmulationHelper path ghidra_scripts/spectest.py
// uses), printing the observed results. This exists so the
// "funcEntryCallOther requires two inputs" fix can be proven without a supported
// CPython for PyGhidra.
//
// Usage (headless; the module is imported with -noanalysis, the analysis is then run
// in-script so the "Wasm Pre-Analyzer.C Stack Pointer" option can be disabled exactly
// as spectest.py does):
//
//   analyzeHeadless <projDir> <projName> -import <module.wasm> -noanalysis \
//       -scriptPath <repo>\test-scripts -postScript EmulateExport.java <export> [arg ...]
//
// args: <exportName> [argHex ...]   (argHex: 32/64-bit hex or decimal; multiple args allowed)
//
// Prints:
//   FUNC      <name> @ <entry>
//   PCODE     one line per pcode op of the entry instruction (shows the CALLOTHER arity)
//   ARGS      the values written to i0..
//   RESULT    <hex bytes of the first 16 bytes at stack base s0>
//   RETURN    i32=<...> (decoded little-endian 32-bit) etc.
//   STATUS    ok | Emulation stopped: <error>
// @category Analysis.Wasm
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.emulation.WasmEmulationHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFuncSignature;
import wasm.format.WasmEnums.ValType;

public class EmulateExport extends GhidraScript {

    private static final long RET_ADDR = 0x80000000L;
    private static final long NULL_ADDR = 0x00000000L;

    private static String vn(Varnode v) {
        if (v == null) {
            return "null";
        }
        return v.getAddress() + ":" + v.getSize();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: EmulateExport.java <exportName> [argHex ...]");
            return;
        }
        String exportName = args[0];

        Program program = getCurrentProgram();

        // Mirror ghidra_scripts/spectest.py's import_program(): disable C stack pointer
        // analysis for wast tests, then (re)analyse.
        int tx = program.startTransaction("EmulateExport analysis");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            program.getOptions(Program.ANALYSIS_PROPERTIES)
                    .setInt("Wasm Pre-Analyzer.C Stack Pointer", -1);
            mgr.initializeOptions(program.getOptions(Program.ANALYSIS_PROPERTIES));
            mgr.reAnalyzeAll(null);
            mgr.waitForAnalysis(null, monitor);
        }
        finally {
            program.endTransaction(tx, true);
        }

        Address exportAddr = null;
        for (ghidra.program.model.symbol.Symbol s : program.getSymbolTable()
                .getSymbols(exportName)) {
            if (s.getAddress() != null) {
                exportAddr = s.getAddress();
                break;
            }
        }
        if (exportAddr == null) {
            println("STATUS    export not found: " + exportName);
            return;
        }
        Function func = program.getFunctionManager().getFunctionAt(exportAddr);
        if (func == null) {
            println("STATUS    export is not a function: " + exportName + " @ " + exportAddr);
            return;
        }
        println("FUNC      " + func.getName() + " @ " + func.getEntryPoint());

        // Dump the pcode of the entry instruction - this is the CALLOTHER the emulator's
        // OpBehaviorOther implementations receive the operands for.
        Instruction entry = getInstructionAt(func.getEntryPoint());
        if (entry != null) {
            for (PcodeOp op : entry.getPcode()) {
                StringBuilder sb = new StringBuilder();
                sb.append("PCODE     ").append(op.getMnemonic());
                Varnode out = op.getOutput();
                if (out != null) {
                    sb.append(" out=").append(vn(out));
                }
                sb.append(" in=[");
                Varnode[] ins = op.getInputs();
                for (int i = 0; i < ins.length; i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(vn(ins[i]));
                }
                sb.append("] (").append(ins.length).append(" input(s))");
                println(sb.toString());
            }
        }

        WasmAnalysis analysis = WasmAnalysis.getState(program);
        WasmFuncSignature sig = analysis.getFunctionByAddress(func.getEntryPoint());
        if (sig != null) {
            println("SIG       params=" + sig.getParams().length + " locals=" +
                sig.getLocals().length + " returns=" + sig.getReturns().length);
        }

        EmulatorHelper emu = new EmulatorHelper(program);
        WasmEmulationHelper helper = new WasmEmulationHelper(emu.getLanguage());
        AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
        Address retAddr = ram.getAddress(RET_ADDR);
        emu.setBreakpoint(retAddr);
        emu.setBreakpoint(ram.getAddress(NULL_ADDR));

        BigInteger[] inputs = new BigInteger[args.length - 1];
        StringBuilder argLine = new StringBuilder("ARGS     ");
        for (int i = 1; i < args.length; i++) {
            inputs[i - 1] = new BigInteger(args[i].replaceFirst("^0[xX]", ""), 16);
            argLine.append("i").append(i - 1).append("=")
                    .append(inputs[i - 1].toString(16)).append(" ");
        }
        println(argLine.toString());

        String status = "ok";
        try {
            helper.simulateCall(emu.getEmulator(), RET_ADDR, func.getEntryPoint().getOffset(),
                inputs);
            while (true) {
                if (!emu.run(monitor)) {
                    String err = emu.getLastError();
                    if (err != null && err.startsWith("Unimplemented CALLOTHER pcodeop (halt_trap)")) {
                        status = "trapped: unreachable";
                    }
                    else if (err != null && (err.equals("Divide by 0") || err.equals("Remainder by 0"))) {
                        status = "trapped: integer divide by zero";
                    }
                    else {
                        status = "Emulation stopped: " + err;
                    }
                    break;
                }
                if (emu.getExecutionAddress().equals(retAddr)) {
                    break;
                }
                if (emu.getExecutionAddress().equals(ram.getAddress(NULL_ADDR))) {
                    status = "trapped: uninitialized element";
                    break;
                }
            }

            if (status.equals("ok")) {
                Address stackBase = program.getRegister("s0").getAddress();
                byte[] bytes = emu.readMemory(stackBase, WasmLoader.REG_SIZE * 2);
                StringBuilder hex = new StringBuilder();
                for (byte b : bytes) {
                    hex.append(String.format("%02x", b));
                }
                println("RESULT    " + hex);
                if (sig != null) {
                    List<String> rets = new ArrayList<>();
                    int off = 0;
                    for (ValType rt : sig.getReturns()) {
                        byte[] chunk = new byte[rt.getSize()];
                        System.arraycopy(bytes, off, chunk, 0, Math.min(chunk.length,
                            bytes.length - off));
                        long v = 0;
                        for (int i = chunk.length - 1; i >= 0; i--) {
                            v = (v << 8) | (chunk[i] & 0xff);
                        }
                        rets.add(rt.toString() + "=0x" + Long.toUnsignedString(v, 16));
                        off += rt.getSize();
                    }
                    println("RETURN    " + String.join(" ", rets));
                }
            }
        }
        finally {
            emu.dispose();
        }
        println("STATUS    " + status);
    }
}
