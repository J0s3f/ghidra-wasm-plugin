import java.math.BigInteger;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.emulation.WasmEmulationHelper;
import ghidra.program.model.address.AddressSet;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;

/** End-to-end receipts for released-core functionality, shared with the probe inventory. */
public class ReleasedCoreRegressionTest extends RegressionTest {
  static long expected(String name) {
    return switch(name) {
      case "RC01_sparse32.wasm" -> 42;
      case "RC02_sparse64.wasm" -> 77;
      case "RC03_sparse_overlap.wasm" -> 0x5a5a7877;
      case "RC04_sparse32_upper.wasm" -> 91;
      case "RC10_reanalysis.wasm" -> 0;
      case "RC11_inline.wasm", "RC12_inline_nested.wasm" -> 123;
      case "RC20_struct_mixed.wasm" -> 65678;
      case "RC21_struct_empty.wasm" -> 0;
      case "RC22_array_wide.wasm" -> 10;
      case "RC23_array_vector.wasm" -> 49;
      case "RC24_array_fixed.wasm" -> 66;
      case "RC25_array_fill_copy.wasm" -> 254;
      case "RC27_cast_null.wasm" -> 3;
      case "RC28_cast_subtypes.wasm" -> 9;
      case "RC29_i31.wasm", "RC30_extern_roundtrip.wasm" -> 2;
      case "RC31_gc_global.wasm" -> 42;
      case "RC32_array_data.wasm" -> 128;
      case "RC33_array_elem.wasm" -> 14;
      case "RC34_nominal_call.wasm" -> 7;
      case "RC35_recursive_cast.wasm" -> 1;
      case "RC36_cast_branches.wasm" -> 0;
      case "RC40_named_types.wasm" -> 42;
      default -> {if(name.startsWith("RC5")) yield 0; throw new AssertionError(name);}
    };
  }
  static void run(ProgramDB p) throws Exception {
    if(!p.getName().startsWith("RC")) return;
    if(p.getName().equals("RC40_named_types.wasm")) {
      for(var ins:p.getListing().getInstructions(true)) if(ins.getMnemonicString().equals("block")) check(ins.toString().contains("blocktype=i32"),"Released value types print by name");
      for(var ins:p.getListing().getInstructions(true)) if(ins.getMnemonicString().equals("ref.test")) check(ins.toString().contains("struct"),"Padded heap type prints by name");
    }
    if(p.getName().equals("RC10_reanalysis.wasm")) reanalysis(p);
    if(p.getName().startsWith("RC5")) structures(p);
    var module=WasmAnalysis.getState(p).getModule();
    check(new wasm.format.WasmTypeGraph(module).diagnostics().isEmpty(),"Valid declared type graph");
    for(var function:WasmAnalysis.getState(p).getFunctions()) if(!function.isImport()) check(WasmAnalysis.getState(p).getFunctionAnalysis(function.getStartAddr()).getTypeDiagnostics().isEmpty(),"Valid nominal operand flow: "+p.getName());
    var sig=WasmAnalysis.getState(p).getFunction(0);
    var emu=new EmulatorHelper(p);
    try {
      long ret=0x80000000L;
      new WasmEmulationHelper(lang).simulateCall(emu.getEmulator(),ret,sig.getStartAddr().getOffset(),new BigInteger[0]);
      int steps=0;
      while(steps++<200 && emu.getExecutionAddress().getOffset()!=ret && emu.step(monitor)) {}
      if(p.getName().startsWith("RC6")) {
        String error=switch(p.getName().substring(2,4)) {case "60"->"null reference";case "61","62"->"cast failure";case "64"->"out of bounds memory access";default->"out of bounds array access";};
        check(emu.getExecutionAddress().getOffset()!=ret && emu.getLastError()!=null && emu.getLastError().contains(error),"Expected GC trap: "+p.getName()+" "+emu.getLastError());
        if(p.getName().contains("copy_atomic")) {
          emu.getEmulator().setHalt(false);
          new WasmEmulationHelper(lang).simulateCall(emu.getEmulator(),ret,WasmAnalysis.getState(p).getFunction(1).getStartAddr().getOffset(),new BigInteger[0]);
          int afterSteps=0;while(afterSteps++<100 && emu.getExecutionAddress().getOffset()!=ret && emu.step(monitor)) {}
          check(emu.getExecutionAddress().getOffset()==ret && emu.readRegister("s0").intValue()==8,"Trapping copy preserves destination");
        }
        return;
      }
      check(emu.getExecutionAddress().getOffset()==ret,"Released-core emulation returns: "+p.getName()+" "+emu.getLastError());
      check(emu.readRegister("s0").equals(BigInteger.valueOf(expected(p.getName()))),"Released-core result: "+p.getName());
      if(p.getName().equals("RC02_sparse64.wasm")) {
        var provider=Class.forName("ghidra.program.emulation.WasmEmulateInstructionStateModifier$WasmFunctionAnalysisProvider");
        var constructor=provider.getDeclaredConstructors()[0];constructor.setAccessible(true);
        var shape=constructor.newInstance(lang.getAddressFactory(),emu.getEmulator().getMemState());
        var pages=provider.getDeclaredField("memoryPages");pages.setAccessible(true);((long[])pages.get(shape))[1]=1L<<48;
        var bytes=provider.getDeclaredMethod("getMemoryByteSize",int.class);bytes.setAccessible(true);
        check(bytes.invoke(shape,1).equals(BigInteger.ONE.shiftLeft(64)),"Full memory64 extent is 2^64 bytes, without signed saturation");
        var size=provider.getDeclaredMethod("getMemoryPages",int.class);size.setAccessible(true);
        check(size.invoke(shape,1).equals(1L<<48),"memory.size retains the complete unsigned address extent");
      }
    } finally {emu.dispose();}
    if(p.getName().equals("RC11_inline.wasm") || p.getName().equals("RC12_inline_nested.wasm")) {
      int tx=p.startTransaction("mark inline");
      try {for(int i=1;i<WasmAnalysis.getState(p).getFunctions().size();i++) p.getFunctionManager().getFunctionAt(WasmAnalysis.getState(p).getFunction(i).getStartAddr()).setInline(true);}
      finally {p.endTransaction(tx,true);}
    }
    var decompiler=new DecompInterface();decompiler.openProgram(p);
    try {
      var result=decompiler.decompileFunction(p.getFunctionManager().getFunctionAt(sig.getStartAddr()),30,monitor);
      check(result.decompileCompleted() && result.getDecompiledFunction()!=null,"Released-core decompilation: "+result.getErrorMessage());
      String source=result.getDecompiledFunction().getC();
      if(p.getName().equals("RC11_inline.wasm") || p.getName().equals("RC12_inline_nested.wasm")) check(source.contains("return 0x7b;") || source.contains("return 123;"),"Inline preserves caller locals and live stack: "+source);
      System.out.println("RELEASED CORE "+p.getName()+" "+source);
    } finally {decompiler.dispose();}
  }
  static void invalid(java.nio.file.Path root) throws Exception {
    var constraints=Class.forName("wasm.analysis.WasmStructSynthAnalyzer$UnionFind");
    var constructor=constraints.getDeclaredConstructors()[0];constructor.setAccessible(true);var aliases=constructor.newInstance();
    var union=constraints.getDeclaredMethod("union",int.class,int.class,int.class,int.class,long.class);union.setAccessible(true);
    var find=constraints.getDeclaredMethod("rootKey",int.class,int.class);find.setAccessible(true);
    var offset=constraints.getDeclaredMethod("displacement",int.class,int.class);offset.setAccessible(true);
    var consistent=constraints.getDeclaredMethod("valid",long.class);consistent.setAccessible(true);
    for(int i=1;i<=20000;i++) union.invoke(aliases,i,0,i-1,0,1L);
    long representative=(long)find.invoke(aliases,0,0);
    check(offset.invoke(aliases,0,0).equals(20000L),"Deep call constraints retain offsets without recursive stack overflow");
    union.invoke(aliases,0,0,20000,0,-20000L);
    check((boolean)consistent.invoke(aliases,representative),"Consistent alias cycle remains usable");
    union.invoke(aliases,0,0,20000,0,0L);
    check(!(boolean)consistent.invoke(aliases,representative),"Conflicting alias cycle excluded from synthesis");
    var valid=new wasm.format.WasmModule(new ghidra.app.util.bin.BinaryReader(new ghidra.app.util.bin.ByteArrayProvider(java.nio.file.Files.readAllBytes(root.resolve("released-validtypes/variance.wasm"))),true));
    var graph=new wasm.format.WasmTypeGraph(valid);
    check(graph.diagnostics().isEmpty(),"Legal function variance, immutable covariance, mutable invariance");
    for(int[] pair:new int[][]{{1,0},{3,2},{5,4},{7,6}}) {
      check(graph.isHeapSubtype(pair[0],pair[1]),"Declared subtype relation "+Arrays.toString(pair));
      check(!graph.isHeapSubtype(pair[1],pair[0]),"Nominal subtype is directional "+Arrays.toString(pair));
    }
    var ref=wasm.format.WasmEnums.ValType.TypeInfo.reference(0,true);
    var nonnull=wasm.format.WasmEnums.ValType.TypeInfo.reference(0,false);
    check(graph.isSubtype(nonnull,ref) && !graph.isSubtype(ref,nonnull),"Reference nullability is directional");
    for(var file:java.nio.file.Files.list(root.resolve("released-invalid")).sorted().toList()) {
      ProgramDB p=load(file);
      try {
        var state=WasmAnalysis.getState(p);
        if(file.getFileName().toString().contains("call")) {
          inspect(p);
          check(!state.getFunctionAnalysis(state.getFunction(0).getStartAddr()).getTypeDiagnostics().isEmpty(),"Invalid nominal flow diagnosed: "+file);
          for(var function:state.getFunctions()) if(!function.isImport()) check(p.getListing().getInstructionAt(function.getStartAddr())!=null,"Invalid nominal flow still disassembled");
        } else check(!new wasm.format.WasmTypeGraph(state.getModule()).diagnostics().isEmpty(),"Invalid declared subtype diagnosed: "+file);
      } finally {p.release(owner);}
    }
  }
  static void structures(ProgramDB p) throws Exception {
    int tx=p.startTransaction("structure recovery");
    try {
      new wasm.analysis.WasmSignatureAnalyzer().added(p,p.getMemory(),monitor,new ghidra.app.util.importer.MessageLog());
      new wasm.analysis.WasmStructSynthAnalyzer().added(p,p.getMemory(),monitor,new ghidra.app.util.importer.MessageLog());
      var state=WasmAnalysis.getState(p);String name=p.getName();
      if(name.contains("global_struct")) {
        var data=p.getListing().getDataAt(WasmLoader.getGlobalAddress(p.getAddressFactory(),0));
        check(data.getDataType() instanceof ghidra.program.model.data.Pointer,"Global pointer recovered");
      } else if(name.contains("local_struct")) {
        var function=p.getFunctionManager().getFunctionAt(state.getFunction(0).getStartAddr());
        check(Arrays.stream(function.getLocalVariables()).anyMatch(v->v.getDataType() instanceof ghidra.program.model.data.Pointer),"Local pointer recovered");
      } else {
        var function=p.getFunctionManager().getFunctionAt(state.getFunction(1).getStartAddr());
        var type=function.getParameter(0).getDataType();
        if(name.contains("memory_separation")) {check(!(type instanceof ghidra.program.model.data.Pointer),"Different memories never merged into a pointer layout");return;}
        check(type instanceof ghidra.program.model.data.Pointer,"Caller pointer propagated through calls: "+name);
        var structure=(ghidra.program.model.data.Structure)((ghidra.program.model.data.Pointer)type).getDataType();
        if(name.contains("interior_struct")) {
          check(structure.getComponentAt(16)!=null && structure.getComponentAt(24)!=null && structure.getLength()==28,"Interior argument offsets propagated to caller");
          var callee=p.getFunctionManager().getFunctionAt(state.getFunction(2).getStartAddr());
          var view=(ghidra.program.model.data.Structure)((ghidra.program.model.data.Pointer)callee.getParameter(0).getDataType()).getDataType();
          check(view.getLength()==12 && view.getComponentAt(8)!=null,"Callee receives its own interior view");
        }
        if(name.contains("simd_struct")) {
          check(structure.getComponentAt(0).getLength()==1,"SIMD lane load observes only one byte");
          check(structure.getComponentAt(4).getDataType() instanceof ghidra.program.model.data.Float4DataType,"Float field retains numeric type");
        }
        if(name.contains("wide_struct")) check(type.getLength()==8 && function.getParameter(0).getLength()==8,"memory64 pointer retains eight-byte ABI storage");
      }
    } finally {p.endTransaction(tx,true);}
  }
  static void reanalysis(ProgramDB p) throws Exception {
    var state=WasmAnalysis.getState(p);var sig=state.getFunction(0);
    var analysis=state.getFunctionAnalysis(sig.getStartAddr());
    int tx=p.startTransaction("reanalysis");
    try {
      var body=new AddressSet(sig.getStartAddr(),sig.getEndAddr());
      var function=p.getFunctionManager().getFunctionAt(sig.getStartAddr());
      var frame=function.getStackFrame();
      frame.createVariable("user_stack",-32,ghidra.program.model.data.Undefined4DataType.dataType,ghidra.program.model.symbol.SourceType.USER_DEFINED);
      frame.createVariable("old_stack",-16,ghidra.program.model.data.Undefined4DataType.dataType,ghidra.program.model.symbol.SourceType.ANALYSIS);
      for(int selected:new int[]{0,1,-1,0,-1}) {
        check(analysis.applyContext(p,selected),"Changing C-stack selection updates context");
        check(frame.getVariableContaining(-16)==null,"Old inferred stack variables removed on context change");
        check(frame.getVariableContaining(-32)!=null,"User-defined stack variables survive reanalysis");
        Disassembler.getDisassembler(p,monitor,null).disassemble(body,body,false);
        for(var ins:p.getListing().getInstructions(body,true)) if(ins.getMnemonicString().equals("global.get")) {
          int index=p.getMemory().getByte(ins.getAddress().add(1)) & 0x7f;
          boolean stack=p.getProgramContext().getValue(lang.getRegister("ctx_is_global_sp"),ins.getAddress(),false).intValue()!=0;
          check(stack==(index==selected),"C-stack context clears the previous global");
        }
        frame.createVariable("old_stack",-16,ghidra.program.model.data.Undefined4DataType.dataType,ghidra.program.model.symbol.SourceType.ANALYSIS);
        check(!analysis.applyContext(p,selected),"Unchanged context does not rewrite or invalidate instructions");
        check(frame.getVariableContaining(-16)!=null,"Idempotent reanalysis preserves inferred variables");
        check(p.getListing().getInstructionAt(sig.getStartAddr())!=null,"Idempotent analysis preserves disassembly");
      }
    } finally {p.endTransaction(tx,true);}
  }
}
