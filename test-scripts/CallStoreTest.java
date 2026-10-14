//@category Test.Wasm
import java.math.BigInteger;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.emulation.WasmEmulationHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class CallStoreTest extends GhidraScript {
  public void run() throws Exception {
    String fixture = getScriptArgs()[0];
    boolean is64 = fixture.endsWith("call64.wasm");
    
    currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).setInt("Wasm Pre-Analyzer.C Stack Pointer", -1);
    AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
    manager.initializeOptions(currentProgram.getOptions(Program.ANALYSIS_PROPERTIES));
    manager.reAnalyzeAll(null); manager.waitForAnalysis(null, monitor);
    
    Function f = null;
    for (Function candidate: currentProgram.getFunctionManager().getFunctions(true)) {
      if (candidate.getName().equals("store_after_call")) { f = candidate; break; }
    }
    if (f == null) {
      println("FAIL: store_after_call function not found");
      return;
    }
    println("TEST fixture=" + currentProgram.getName() + " function=" + f.getName());
    
    EmulatorHelper emu = new EmulatorHelper(currentProgram);
    try {
      Address ret = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x80000000L);
      new WasmEmulationHelper(emu.getLanguage()).simulateCall(emu.getEmulator(), ret.getOffset(), f.getEntryPoint().getOffset(), new BigInteger[0]);
      boolean returned = false; String error = null; int steps = 0;
      for (; steps < 3000; steps++) {
        if (emu.getExecutionAddress().equals(ret)) { returned = true; break; }
        if (!emu.step(monitor)) { error = emu.getLastError(); break; }
      }
      
      if (!returned) {
        println("FAIL: emulation did not return (steps=" + steps + ", error=" + error + ", address=" + emu.getExecutionAddress() + ")");
        return;
      }
      
      // Read back the stored value from memory address 0
      // For call32: i32.load from address 0 (4 bytes)
      // For call64: i64.load32_s from address 0 (4 bytes, sign-extended to 8)
      AddressSpace memSpace = is64 ? currentProgram.getAddressFactory().getAddressSpace("memory64") : currentProgram.getAddressFactory().getAddressSpace("memory");
      byte[] val = emu.readMemory(memSpace.getAddress(0), 4);
      long result = 0;
      for (int i = 3; i >= 0; i--) result = (result << 8) | (val[i] & 255);
      
      if (result != 7) {
        println("FAIL: expected stored value 7, got " + result);
        return;
      }
      
      println("PASS: returned=true result=" + result + " steps=" + steps);
    } finally {
      emu.dispose();
    }
  }
}