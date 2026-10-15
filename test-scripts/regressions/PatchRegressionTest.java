import java.math.BigInteger;
import java.util.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.database.ProgramDB;
import ghidra.program.emulation.WasmEmulationHelper;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;

/** Behavioral regressions for independent memories and complete large branch tables. */
public class PatchRegressionTest extends RegressionTest {
  static void run(ProgramDB p) throws Exception {
    boolean table=p.getName().startsWith("brtable_large");
    boolean memory=p.getName().startsWith("isolation");
    if(!table && !memory) return;
    if(table) {
      for(var ins:p.getListing().getInstructions(true)) if(ins.getMnemonicString().equals("br_table")) {
        var space=p.getAddressFactory().getAddressSpace("brtable");
        long base=wasm.analysis.WasmFunctionAnalysis.getBrTableOffset(ins.getAddress());
        for(int i=0;i<=16384;i++) check(p.getMemory().getInt(space.getAddress(base+4L*i))==(i==16384?1:i%2),"Every selector is materialized, including late cases");
        var context=new ghidra.program.model.lang.InjectContext();
        context.baseAddr=ins.getAddress();context.inputlist=new ArrayList<>(List.of(constant(16383,4)));
        context.output=new ArrayList<>(List.of(new ghidra.program.model.pcode.Varnode(lang.getRegister("BRTableInput").getAddress(),4)));
        var ops=new wasm.pcode.InjectPayloadWasmBrTable("test").getPcode(p,context);
        var load=ops[ops.length-1];
        check(load.getOpcode()==ghidra.program.model.pcode.PcodeOp.LOAD && (int)load.getInput(0).getOffset()==space.getSpaceID(),"Native selector injection reads the auxiliary space");
      }
    }
    if(memory) {
      var state=WasmAnalysis.getState(p);
      var spaces=new HashSet<ghidra.program.model.address.AddressSpace>();
      for(int i=0;i<state.getModule().getNonImportedMemories().size();i++) {
        var limits=state.getModule().getNonImportedMemories().get(i);
        var low=WasmLoader.getMemoryAddress(p.getAddressFactory(),i,0,limits.is64Bit());
        check(spaces.add(low.getAddressSpace()),"Every declared memory has a distinct space");
        var high=WasmLoader.getMemoryAddress(p.getAddressFactory(),i,limits.is64Bit()?0x100000010L:0x08000000L,limits.is64Bit());
        check(high.getAddressSpace().equals(low.getAddressSpace()),"Unmapped high offsets stay in the selected memory");
      }
    }
    var signature=WasmAnalysis.getState(p).getFunction(0);
    long[] inputs=table?new long[]{0,1,1022,1023,1024,1025,16382,16383,16384,0xffffffffL}:new long[]{0};
    for(long input:inputs) {
      var emu=new EmulatorHelper(p);
      try {
        long ret=0x80000000L;
        new WasmEmulationHelper(lang).simulateCall(emu.getEmulator(),ret,signature.getStartAddr().getOffset(),table?new BigInteger[]{BigInteger.valueOf(input)}:new BigInteger[0]);
        int steps=0;
        while(steps++<18000 && emu.getExecutionAddress().getOffset()!=ret && emu.step(monitor)) {}
        boolean trapped=p.getName().equals("isolation_oob.wasm");
        if(trapped) {
          check(emu.getExecutionAddress().getOffset()!=ret && emu.getLastError().contains("out of bounds"),"Secondary memory OOB store traps");
          check(Arrays.equals(emu.readMemory(WasmLoader.getMemoryAddress(p.getAddressFactory(),0,65532),4),new byte[]{0x78,0x56,0x34,0x12}),"Secondary memory trap preserves primary bytes");
          check(Arrays.equals(emu.readMemory(WasmLoader.getMemoryAddress(p.getAddressFactory(),1,65532),4),new byte[4]),"Secondary memory trap writes no bytes");
        } else {
          check(emu.getExecutionAddress().getOffset()==ret,"Patch emulation returns: "+p.getName()+" input="+input+" error="+emu.getLastError());
          long wanted=table?(input<16384 && input%2==0?43:42):switch(p.getName()) {
            case "isolation32.wasm" -> 0x4411;
            case "isolation_index32.wasm" -> 0x2277;
            case "isolation64.wasm" -> 0x5566;
            case "isolation_simd.wasm", "isolation_atomic.wasm" -> 0x3412;
            case "isolation_copy.wasm" -> 0x12345678;
            case "isolation_copy_overlap.wasm" -> 0xaabb;
            case "isolation_zero.wasm" -> 0;
            default -> throw new AssertionError(p.getName());
          };
          check(emu.readRegister(table?"s0q":"s0").equals(BigInteger.valueOf(wanted)),"Correct patch result: "+p.getName()+" input="+input+" actual="+emu.readRegister(table?"s0q":"s0")+" wanted="+wanted);
          if(table) check(steps<20,"Repeated labels do not expand executed control flow: "+steps);
        }
      } finally {emu.dispose();}
    }
    var d=new DecompInterface();d.openProgram(p);
    try {
      var f=p.getFunctionManager().getFunctionAt(signature.getStartAddr());
      var result=d.decompileFunction(f,30,monitor);
      check(result.decompileCompleted() && result.getDecompiledFunction()!=null,"Patch decompiles: "+result.getErrorMessage());
      check(result.getHighFunction().getBasicBlocks().size()<40,"Patch CFG remains compact");
      System.out.println("PATCH DECOMP "+p.getName()+" "+result.getDecompiledFunction().getC());
    } finally {d.dispose();}
  }
}
