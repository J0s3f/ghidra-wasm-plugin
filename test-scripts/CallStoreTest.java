//@category Test.Wasm
/*
 * Semantic regression driver for the call-store (R1) fix and the stale operand-slot
 * cache (N1) fix.
 *
 * It imports one fixture, re-runs the Wasm analysis with the C-stack-pointer
 * pre-analysis disabled (as the other emulation drivers do), then invokes *every*
 * exported function through the real EmulatorHelper / WasmEmulationHelper path and
 * asserts the outcome per case: a valid access must return its value, a
 * required-trap access must trap with "out of bounds memory access". It prints one
 * "PASS: <name> ..." / "FAIL: <name> ..." record per case and throws at the end if
 * any case failed.
 *
 * The check-call-store-semantics.ps1 wrapper requires the explicit PASS records (and
 * the launcher exit code), so a thrown script exception alone is not treated as
 * success - the marker is the contract.
 *
 * Usage:
 *   analyzeHeadless <projDir> <projName> -import <fixture.wasm> \
 *       -postScript CallStoreTest.java <fixture.wasm>
 */
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.emulation.WasmEmulationHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class CallStoreTest extends GhidraScript {

  private static final long RET_ADDR = 0x80000000L;
  private static final long EXPECTED_LOAD = 0x12345678L;
  private static final String TRAP_OOB = "out of bounds memory access";

  /** One expected outcome for one exported function. */
  private static final class Case {
    final boolean expectTrap;      // must the access trap?
    final long expectValue;        // expected s0 (return) value when it does not trap
    final boolean expectStored;    // when true, assert memory[0..4) == 7 instead of s0

    Case(boolean expectTrap, long expectValue, boolean expectStored) {
      this.expectTrap = expectTrap;
      this.expectValue = expectValue;
      this.expectStored = expectStored;
    }

    static Case ret(long value) { return new Case(false, value, false); }
    static Case trap() { return new Case(true, 0, false); }
    static Case stored() { return new Case(false, 0, true); }
  }

  private static Map<String, Case> casesFor(String fixture) {
    Map<String, Case> cases = new LinkedHashMap<>();
    if (fixture.equals("call32.wasm") || fixture.equals("call64.wasm")) {
      cases.put("store_after_call", Case.stored());
    }
    else if (fixture.equals("cache32.wasm") || fixture.equals("cache64.wasm")) {
      cases.put("load_after_call", Case.ret(EXPECTED_LOAD));
      cases.put("simd_after_call", Case.ret(EXPECTED_LOAD));
      cases.put("rmw_after_call", Case.ret(EXPECTED_LOAD));
      cases.put("overflow_after_call", Case.trap());
    }
    else if (fixture.equals("cache32_controls.wasm") || fixture.equals("cache64_controls.wasm")) {
      cases.put("direct_load", Case.ret(EXPECTED_LOAD));
      cases.put("direct_simd", Case.ret(EXPECTED_LOAD));
      cases.put("direct_rmw", Case.ret(EXPECTED_LOAD));
      cases.put("direct_overflow", Case.trap());
    }
    return cases;
  }

  private int failures = 0;

  private void pass(String name, String detail) {
    println("PASS: " + name + " " + detail);
  }

  private void fail(String name, String detail) {
    failures++;
    println("FAIL: " + name + " " + detail);
  }

  private long readS0(EmulatorHelper emu) {
    Address s0 = currentProgram.getRegister("s0").getAddress();
    byte[] val = emu.readMemory(s0, 4);
    long result = 0;
    for (int i = 3; i >= 0; i--) {
      result = (result << 8) | (val[i] & 255);
    }
    return result;
  }

  private long readMemoryZero(EmulatorHelper emu, boolean is64) {
    AddressSpace memSpace = is64
        ? currentProgram.getAddressFactory().getAddressSpace("memory64")
        : currentProgram.getAddressFactory().getAddressSpace("memory");
    byte[] val = emu.readMemory(memSpace.getAddress(0), 4);
    long result = 0;
    for (int i = 3; i >= 0; i--) {
      result = (result << 8) | (val[i] & 255);
    }
    return result;
  }

  private void runCase(Function f, Case expected, boolean is64) throws Exception {
    String name = f.getName();
    EmulatorHelper emu = new EmulatorHelper(currentProgram);
    try {
      Address ret = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(RET_ADDR);
      new WasmEmulationHelper(emu.getLanguage()).simulateCall(emu.getEmulator(), ret.getOffset(),
          f.getEntryPoint().getOffset(), new BigInteger[0]);
      boolean returned = false;
      String error = null;
      int steps = 0;
      for (; steps < 3000; steps++) {
        if (emu.getExecutionAddress().equals(ret)) { returned = true; break; }
        if (!emu.step(monitor)) { error = emu.getLastError(); break; }
      }

      if (expected.expectTrap) {
        if (returned) {
          fail(name, "expected trap '" + TRAP_OOB + "' but returned (steps=" + steps + ")");
        }
        else if (error == null || !error.contains(TRAP_OOB)) {
          fail(name, "expected trap '" + TRAP_OOB + "' but got error=" + error + " (steps=" + steps + ")");
        }
        else {
          pass(name, "trapped='" + error + "' steps=" + steps);
        }
        return;
      }

      if (!returned) {
        fail(name, "emulation did not return (steps=" + steps + ", error=" + error
            + ", address=" + emu.getExecutionAddress() + ")");
        return;
      }
      if (expected.expectStored) {
        long stored = readMemoryZero(emu, is64);
        if (stored != 7) {
          fail(name, "expected stored value 7, got " + stored + " (steps=" + steps + ")");
        }
        else {
          pass(name, "stored=" + stored + " steps=" + steps);
        }
        return;
      }
      long result = readS0(emu);
      if (result != expected.expectValue) {
        fail(name, "expected 0x" + Long.toUnsignedString(expected.expectValue, 16)
            + ", got 0x" + Long.toUnsignedString(result, 16) + " (steps=" + steps + ")");
      }
      else {
        pass(name, "returned=0x" + Long.toUnsignedString(result, 16) + " steps=" + steps);
      }
    }
    finally {
      emu.dispose();
    }
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1) {
      println("FAIL: no fixture argument supplied");
      throw new RuntimeException("CallStoreTest requires a fixture path argument");
    }
    String fixture = new java.io.File(args[0]).getName();
    boolean is64 = fixture.contains("64");

    Map<String, Case> cases = casesFor(fixture);
    if (cases.isEmpty()) {
      println("FAIL: no expectations defined for fixture " + fixture);
      throw new RuntimeException("unknown fixture " + fixture);
    }

    currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).setInt("Wasm Pre-Analyzer.C Stack Pointer", -1);
    AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
    manager.initializeOptions(currentProgram.getOptions(Program.ANALYSIS_PROPERTIES));
    manager.reAnalyzeAll(null);
    manager.waitForAnalysis(null, monitor);

    println("TEST fixture=" + fixture + " exports=" + cases.size());

    Set<String> seen = new LinkedHashSet<>();
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      if (f.getName().startsWith("unnamed")) {
        continue;
      }
      Case expected = cases.get(f.getName());
      if (expected == null) {
        fail(f.getName(), "unexpected exported function");
        continue;
      }
      seen.add(f.getName());
      runCase(f, expected, is64);
    }

    for (String name : cases.keySet()) {
      if (!seen.contains(name)) {
        fail(name, "exported function not found");
      }
    }

    if (failures != 0) {
      throw new RuntimeException("CallStoreTest: " + failures + " case(s) failed for " + fixture);
    }
    println("DONE fixture=" + fixture + " all " + cases.size() + " case(s) passed");
  }
}
