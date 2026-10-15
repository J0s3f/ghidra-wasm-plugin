import java.io.*;
import java.nio.file.*;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.emulation.WasmEmulationHelper;
import ghidra.util.task.TaskMonitor;
import wasm.*;
import wasm.analysis.*;
import wasm.format.*;
import wasm.format.sections.*;

public class RegressionTest {
  static Object owner = new Object();
  static TaskMonitor monitor = TaskMonitor.DUMMY;
  static Language lang;
  static int assertions;
  static Map<Integer,BigInteger> numericExpected=new HashMap<>();
  static void check(boolean condition, String message) {
    assertions++;
    if (!condition) throw new AssertionError(message);
  }
  static class SourceLayout extends GhidraApplicationLayout {
    SourceLayout(File root) throws IOException {
      super(root);
      modules = new LinkedHashMap<>(modules);
      modules.entrySet().removeIf(e -> new generic.jar.ResourceFile(e.getValue().getModuleRoot(), "data/languages/WebAssembly.ldefs").exists());
      var local = new GModule(applicationRootDirs, new generic.jar.ResourceFile(System.getProperty("wasm.test.module")));
      modules.put(local.getName(), local);
    }
  }
  static class LocalNameProbe extends WasmFunctionVariableNameAnalyzer {
    @Override protected Map<Long,Long> getLocalFirstUses(Program p,Function f,Set<Long> s){return new HashMap<>();}
    void apply(Program p,Function f,WasmFuncSignature sig){applyLocalNames(p,f,sig,Map.of(1L,"wide_local"));}
    String registerName(long index,int size){return getRegisterName(index,size);}
    Map<Long,String> filter(Function f,WasmFuncSignature sig,Map<Long,String> names){return filterNewVariables(f,sig,names);}
  }
  static void init() throws Exception {
    var config = new HeadlessGhidraApplicationConfiguration();
    config.setInitializeLogging(false);
    Application.initializeApplication(new SourceLayout(new File(System.getProperty("review.ghidra","C:/Tools/ghidra_12.1.4_PUBLIC"))), config);
    lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("Wasm:LE:32:default"));
    System.out.println("REVIEW classes="+WasmLoader.class.getProtectionDomain().getCodeSource().getLocation());
    var cs=lang.getCompilerSpecByID(new CompilerSpecID("default"));
    System.out.println("REVIEW CSPEC stack="+cs.getStackBaseSpace()+" memoryGlobal="+cs.isGlobal(lang.getAddressFactory().getAddressSpace("memory").getAddress(1024))+" ramGlobal="+cs.isGlobal(lang.getAddressFactory().getDefaultAddressSpace().getAddress(1024)));
    for (var id : new String[]{"default", "pos-stack"}) {
      var spec = lang.getCompilerSpecByID(new CompilerSpecID(id));
      check(spec.getStackBaseSpace().getName().equals("memory"), id+" C stack space");
      for (var space : new String[]{"memory", "memory64"}) check(spec.isGlobal(lang.getAddressFactory().getAddressSpace(space).getAddress(1024)), id+" global "+space);
    }
  }
  static ProgramDB load(Path path) throws Exception {
    var p = new ProgramDB(path.getFileName().toString(),lang,lang.getCompilerSpecByID(new CompilerSpecID("default")),owner);
    int tx = p.startTransaction("review");
    try {
      var m = WasmLoader.class.getDeclaredMethod("doLoad",ByteProvider.class,Program.class,TaskMonitor.class);
      m.setAccessible(true);
      m.invoke(new WasmLoader(),new ByteArrayProvider(Files.readAllBytes(path)),p,monitor);
      return p;
    } finally { p.endTransaction(tx,true); }
  }
  static ghidra.program.model.pcode.Varnode constant(long value,int size) {
    return new ghidra.program.model.pcode.Varnode(lang.getAddressFactory().getConstantSpace().getAddress(value),size);
  }
  static void copyInjectionTests(ProgramDB p,Address site) {
    for(boolean wide:new boolean[]{false,true}) {
      String name=WasmLoader.getMemorySpaceName(1,wide);
      if(p.getAddressFactory().getAddressSpace(name)==null) try {
        p.createOverlaySpace(name,p.getAddressFactory().getAddressSpace(wide?"memory64":"memory"));
      } catch(Exception e) {throw new AssertionError(e);}
    }
    // Execute injected straight-line pcode on a tiny independent memory image. This
    // checks the observable memmove result, not just a particular operation order.
    for(int srcWidth:new int[]{4,8}) for(int dstWidth:new int[]{4,8}) for(boolean separate:new boolean[]{false,true}) {
      int srcIndex=separate?1:0;
      var context=new InjectContext();context.baseAddr=site;context.inputlist=new ArrayList<>();
      context.inputlist.add(constant(0,4));context.inputlist.add(constant(srcIndex,4));
      context.inputlist.add(constant(3,4));context.inputlist.add(constant(4096,srcWidth));context.inputlist.add(constant(4097,dstWidth));
      WasmMemoryCopyInfo.putLength(p,site,3);
      var fixup=new wasm.pcode.InjectPayloadWasmMemoryCopy("regression");
      var ops=fixup.getPcode(p,context);
      Map<ghidra.program.model.pcode.Varnode,Long> values=new HashMap<>();
      Map<String,Byte> memory=new HashMap<>();
      String srcSpace=WasmLoader.getMemorySpaceName(srcIndex,srcWidth==8),dstSpace=WasmLoader.getMemorySpaceName(0,dstWidth==8);
      for(int i=0;i<4;i++) memory.put(srcSpace+":"+(4096+i),(byte)(65+i));
      java.util.function.ToLongFunction<ghidra.program.model.pcode.Varnode> value=v->v.isConstant()?v.getOffset():Objects.requireNonNull(values.get(v));
      for(var op:ops) switch(op.getOpcode()) {
        case ghidra.program.model.pcode.PcodeOp.INT_ADD: {
          long result=value.applyAsLong(op.getInput(0))+value.applyAsLong(op.getInput(1));
          values.put(op.getOutput(),op.getOutput().getSize()==4?result & 0xffffffffL:result);break;
        }
        case ghidra.program.model.pcode.PcodeOp.LOAD: {
          String space=p.getAddressFactory().getAddressSpace((int)op.getInput(0).getOffset()).getName();
          Byte b=memory.get(space+":"+value.applyAsLong(op.getInput(1)));
          check(b!=null,"Copy reads correct source memory and width");
          values.put(op.getOutput(),b.longValue() & 255);break;
        }
        case ghidra.program.model.pcode.PcodeOp.STORE: {
          String space=p.getAddressFactory().getAddressSpace((int)op.getInput(0).getOffset()).getName();
          memory.put(space+":"+value.applyAsLong(op.getInput(1)),(byte)value.applyAsLong(op.getInput(2)));break;
        }
        default: throw new AssertionError("Unexpected copy pcode "+op);
      }
      for(int i=0;i<3;i++) check(memory.get(dstSpace+":"+(4097+i))==(byte)(65+i),"Overlapping/multi-memory copy result");
      WasmMemoryCopyInfo.clear(p,site);
      ops=fixup.getPcode(p,context);
      check(ops.length==1 && ops[0].getOpcode()==ghidra.program.model.pcode.PcodeOp.CALLOTHER,"Opaque dynamic copy");
      var op=ops[0];
      check(lang.getUserDefinedOpName((int)op.getInput(0).getOffset()).equals("wasm_memory_copy"),"Dynamic copy retains Wasm overlap semantics");
      check(op.getInput(1).getOffset()==0 && op.getInput(2).getOffset()==srcIndex && op.getInput(3).getSize()==dstWidth && op.getInput(4).getSize()==srcWidth,"Dynamic copy retains memories and widths");
    }
  }
  static void inspect(ProgramDB p) throws Exception {
    int tx=p.startTransaction("analyze");
    var state=WasmAnalysis.getState(p);
    try {
      for(int t=0;t<state.getModule().getNonImportedTables().size();t++) {
        var table=state.getModule().getTableType(t);
        System.out.println("REVIEW TABLE "+t+" type="+table.getElementType()+" size="+table.getLimits().getInitial());
      }
      for (var f:state.getFunctions()) {
        if (f.isImport()) continue;
        try {
          var fa=state.getFunctionAnalysis(f.getStartAddr());
          // Retain context in a separate walk: applyContext clears its pending context map.
          var bytes=state.getModule().getFunctionCode(f.getFuncIdx()).getInstructions();
          var copy=new WasmFunctionAnalysis(f);
          copy.analyzeFunction(state,new BinaryReader(new ByteArrayProvider(bytes),true));
          fa.applyContext(p,-1);
          var set=new AddressSet(f.getStartAddr(),f.getEndAddr());
          Disassembler.getDisassembler(p,monitor,null).disassemble(set,set,false);
          System.out.println("REVIEW ANALYSIS OK "+f.getName());
          for (var i:p.getListing().getInstructions(set,true)) {
            if (i.getMnemonicString().startsWith("br_on") || i.getMnemonicString().contains("load") || i.getMnemonicString().equals("select") || i.getMnemonicString().equals(".local")) {
              var eff=fa.getStackEffect(i.getAddress());
              System.out.println("REVIEW INSTR "+i+" len="+i.getLength()+" objects="+Arrays.toString(i.getOpObjects(0))+" effect="+(eff==null?"null":eff.getPopHeight()+"->"+eff.getPushHeight()));
            }
          }
          Address pc=f.getStartAddr();
          while(pc.compareTo(f.getEndAddr())<=0) {
            var ins=p.getListing().getInstructionAt(pc);
            check(ins!=null,"Undefined instruction at "+pc+" in "+p.getName());
            pc=pc.add(ins.getLength());
          }
          for(var ins:p.getListing().getInstructions(set,true)) {
            if(ins.getMnemonicString().startsWith("br_on")) {
              var effect=fa.getStackEffect(ins.getAddress());
              check(effect!=null,"Missing reference branch relocation");
              if(p.getName().startsWith("br_on_cast")) check(effect.getPopHeight()==1 && effect.getPushHeight()==0 && effect.getToPop().length==2 && effect.getToPop()[0].getSize()==8,"GC branch relocates mixed-width label arguments");
            }
            if(p.getName().equals("typed_local.wasm") && ins.getMnemonicString().equals(".local")) check(ins.getLength()==3,"Multibyte local length");
            if(p.getName().equals("typed_select.wasm") && ins.getMnemonicString().equals("select")) check(ins.getLength()==4,"Multibyte select length");
            if(p.getName().equals("table64_ops.wasm") && (ins.getMnemonicString().startsWith("table.") || ins.getMnemonicString().contains("call_indirect"))) {
              boolean checked=false;
              for(var op:ins.getPcode()) {
                if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.INT_MULT) {
                  check(op.getInput(0).getSize()==8,"Preserve table64 index in address arithmetic");checked=true;
                }
                if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.CALLOTHER) {
                  String name=lang.getUserDefinedOpName((int)op.getInput(0).getOffset());
                  int[] widths=null;
                  switch(name) {
                  case "table_init": widths=new int[]{4,4,4,4,8};break;
                  case "table_grow": widths=new int[]{4,4,8};check(op.getOutput().getSize()==8,"table64.grow result");break;
                  case "table_size": widths=new int[]{4};check(op.getOutput().getSize()==8,"table64.size result");break;
                  case "table_fill": widths=new int[]{4,8,4,8};break;
                  case "table_copy": widths=f.getFuncIdx()==6?new int[]{4,4,8,8,8}:f.getFuncIdx()==7?new int[]{4,4,4,4,8}:new int[]{4,4,4,8,4};break;
                  }
                  if(widths!=null) {
                    check(op.getNumInputs()==widths.length+1,"Table userop operand count");
                    for(int j=0;j<widths.length;j++) check(op.getInput(j+1).getSize()==widths[j],name+" operand "+j+" width");
                    checked=true;
                  }
                }
              }
              check(checked,"Check table64 pcode for "+ins);
            }
          }
        } catch (Throwable e) { throw new AssertionError("Analysis failed in "+p.getName()+" "+f.getName(),e); }
      }
      new WasmSignatureAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
      if(p.getName().equals("local_names.wasm")) {
        var sig=state.getFunction(0);var f=p.getFunctionManager().getFunctionAt(sig.getStartAddr());
        new LocalNameProbe().apply(p,f,sig);
        var vars=f.getLocalVariables();
        check(vars.length==1 && vars[0].getLength()==8 && vars[0].getVariableStorage().getRegister().getName().equals("l1q"),"Named i64 local uses its own type and storage");
        var probe=new LocalNameProbe();
        check(probe.registerName(1,16).equals("l1o"),"Named v128 register width");
        check(probe.filter(f,sig,Map.of(4095L,"invalid",2L,"past_end")).isEmpty(),"Ignore nonexistent named locals");
      }
      if(p.getName().equals("global_index64.wasm")) {
        var m=WasmPreAnalyzer.class.getDeclaredMethod("guessCStackGlobalForFunction",Program.class,Address.class);m.setAccessible(true);
        check(m.invoke(new WasmPreAnalyzer(),p,state.getFunction(0).getStartAddr()).equals(64),"Unsigned global index 64");
        var analyzer=new WasmPreAnalyzer();
        analyzer.added(p,new AddressSet(),monitor,new MessageLog());
        var field=WasmPreAnalyzer.class.getDeclaredField("cStackGlobal");field.setAccessible(true);
        check(field.getInt(analyzer)==-2,"Automatic C-stack option must survive program analysis");
      }
      if(p.getName().startsWith("copy_")) {
        new WasmMemoryCopyAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
        for(var i:p.getListing().getInstructions(true)) if(i.getMnemonicString().equals("memory.copy")) {
          Integer length=WasmMemoryCopyInfo.getLength(p,i.getAddress());
          check(p.getName().equals("copy_dynamic_len.wasm") ? length==null : Integer.valueOf(3).equals(length), "Copy length comes from the length operand: "+length);
          if(p.getName().equals("copy_dynamic_len.wasm")) {
            WasmMemoryCopyInfo.putLength(p,i.getAddress(),16);
            new WasmMemoryCopyAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
            check(WasmMemoryCopyInfo.getLength(p,i.getAddress())==null,"Remove stale inferred copy length");
            copyInjectionTests(p,i.getAddress());
          }
        }
      }
      if(p.getName().equals("multi_memarg.wasm")) {
        var method=WasmStructSynthAnalyzer.class.getDeclaredMethod("getMemoryOffset",Instruction.class);
        method.setAccessible(true);
        for(var i:p.getListing().getInstructions(true)) if(i.getMnemonicString().equals("i32.load")) {
          check(((ghidra.program.model.scalar.Scalar)method.invoke(null,i)).getUnsignedValue()==16,"Struct memarg offset");
          var stackMethod=WasmStackVariableAnalyzer.class.getDeclaredMethod("getMemoryOffset",Instruction.class); stackMethod.setAccessible(true);
          check(((ghidra.program.model.scalar.Scalar)stackMethod.invoke(null,i)).getUnsignedValue()==16,"Stack memarg offset");
        }
      }
      if(p.getName().equals("overlap_struct.wasm")) {
        var method=WasmStructSynthAnalyzer.class.getDeclaredMethod("createStructure",Program.class,String.class,TreeMap.class);
        method.setAccessible(true);
        var offsets=new TreeMap<Integer,Integer>();offsets.put(0,8);offsets.put(4,4);
        var st=(Structure)method.invoke(new WasmStructSynthAnalyzer(),p,"overlap_review",offsets);
        check(st.getLength()==8 && st.getDefinedComponents().length==1 && st.getDefinedComponents()[0].getOffset()==0,"Overlapping fields must not move to invented offsets");
        offsets.clear(); offsets.put(0,1);offsets.put(8,8);offsets.put(24,4);
        st=(Structure)method.invoke(new WasmStructSynthAnalyzer(),p,"gap_review",offsets);
        for(var c:st.getDefinedComponents()) check(c.getOffset()==Integer.parseInt(c.getFieldName().substring(6)),"Preserve field offset across padding");
        offsets.clear();offsets.put(0,8);offsets.put(4,8);offsets.put(16,4);
        st=(Structure)method.invoke(new WasmStructSynthAnalyzer(),p,"crossing_overlap_review",offsets);
        check(st.getLength()==20 && st.getDefinedComponents()[0].getLength()==12 && st.getDefinedComponents()[1].getOffset()==16,"Crossing overlaps retain their full extent and following offsets");
      }
      if(p.getName().equals("varargs.wasm")) {
        new WasmVarargAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
        boolean found=false;
        for(var ins:p.getListing().getInstructions(true)) if(ins.getMnemonicString().equals("call")) {
          var info=WasmVarargInfo.get(p,ins.getAddress());
          check(info!=null && info.sizes.length==1 && info.sizes[0]==4,"Recover %d format from linear memory");
          var context=new InjectContext();context.baseAddr=ins.getAddress();context.inputlist=new ArrayList<>();
          context.inputlist.add(new ghidra.program.model.pcode.Varnode(lang.getAddressFactory().getConstantSpace().getAddress(lang.getRegister("i0").getOffset()),4));
          var ops=new wasm.pcode.InjectPayloadWasmCallPrologue("regression").getPcode(p,context);
          for(var op:ops) if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.LOAD) {
            check(op.getInput(0).getOffset()==lang.getAddressFactory().getAddressSpace("memory").getSpaceID(),"Vararg loads use linear memory");found=true;
          }
        }
        check(found,"Vararg injection emitted a load");
      }
    } finally { p.endTransaction(tx,true); }
    if(p.getName().equals("table_initializer.wasm")) {
      var table=state.getModule().getTableType(0);
      check(table.getElementType()==wasm.format.WasmEnums.ValType.funcref && table.getLimits().getInitial()==1,"Parse table initializer header");
      check(p.getMemory().getInt(WasmLoader.getTableAddress(p.getAddressFactory(),0,0))==(int)state.getFunction(0).getStartAddr().getOffset(),"Apply table ref.func initializer");
    }
    if(p.getName().equals("mutable_memory.wasm") || p.getName().startsWith("copy_")) {
      var d=new DecompInterface();d.openProgram(p);
      try{for(var f:p.getFunctionManager().getFunctions(true)) {
        var result=d.decompileFunction(f,20,monitor);
        check(result.decompileCompleted() && result.getDecompiledFunction()!=null,"Decompilation must succeed: "+result.getErrorMessage());
        String source=result.getDecompiledFunction().getC();
        if(p.getName().equals("mutable_memory.wasm") && f.getName().equals("read_mutable")) check(source.contains("memory_00000400") && !source.contains("in_memory_"),"Linear memory must decompile as global data");
        if(p.getName().equals("copy_dynamic_len.wasm")) check(source.contains("wasm_memory_copy"),"Dynamic copy decompiles with Wasm semantics");
        System.out.println("REVIEW DECOMP "+f.getName()+" "+(result.getDecompiledFunction()==null?result.getErrorMessage():result.getDecompiledFunction().getC()));
      }} finally{d.dispose();}
    }
  }
  static void emulate(ProgramDB p) throws Exception {
    var expected=Map.ofEntries(
      Map.entry("br_on_null.wasm","42"),Map.entry("br_on_non_null.wasm","7"),
      Map.entry("typed_local.wasm","1"),Map.entry("typed_select.wasm","1"),
      Map.entry("table64_get.wasm","1"),Map.entry("table64_size.wasm","1"),
      Map.entry("trunc_lower.wasm","2147483648"),Map.entry("trunc_unsigned.wasm","4294967295"),
      Map.entry("sat_nan.wasm","0"),Map.entry("sat_unsigned_negative.wasm","0"),
      Map.entry("sat_unsigned_max.wasm","4294967295"),Map.entry("sat_signed_max.wasm","2147483647"),
      Map.entry("sat_unsigned_2p32.wasm","4294967295"),Map.entry("trunc_unsigned_i64.wasm","9223372036854775808"),
      Map.entry("grow_overflow.wasm","18446744073709551615"),Map.entry("min_zero.wasm","2147483648"),
      Map.entry("max_zero.wasm","0"),Map.entry("nearest_half.wasm","1073741824"),Map.entry("typed_table_call.wasm","42"));
    boolean legacy=p.getName().startsWith("cache") || p.getName().startsWith("call") || p.getName().equals("brtable_default.wasm");
    if(!expected.containsKey(p.getName()) && !p.getName().startsWith("oob_store") && !p.getName().equals("numeric_matrix.wasm") && !legacy) return;
    for (var f:WasmAnalysis.getState(p).getFunctions()) {
      if (f.isImport() || (!f.getName().startsWith("test_") && !legacy)) continue;
      if(legacy && (f.getName().equals("callee") || f.getName().startsWith("unnamed_"))) continue;
      var emu=new EmulatorHelper(p);
      try {
        long ret=0x80000000L;
        new WasmEmulationHelper(lang).simulateCall(emu.getEmulator(),ret,f.getStartAddr().getOffset(),new BigInteger[0]);
        int steps=0;
        while(steps++<(legacy?5000:300) && emu.getExecutionAddress().getOffset()!=ret && emu.step(monitor)) {}
        var mem=p.getAddressFactory().getAddressSpace("memory");
        System.out.println("REVIEW EMU "+f.getName()+" steps="+steps+" returned="+(emu.getExecutionAddress().getOffset()==ret)+" s0="+emu.readRegister("s0")+" s0q="+emu.readRegister("s0q")+" error="+emu.getLastError()+" tail="+Arrays.toString(emu.readMemory(mem.getAddress(65532),4)));
        if(p.getName().startsWith("oob_store") || (legacy && f.getName().contains("overflow"))) {
          check(emu.getExecutionAddress().getOffset()!=ret && emu.getLastError().contains("out of bounds"),"OOB store must trap");
          if(p.getName().startsWith("oob_store")) {
            var space=p.getAddressFactory().getAddressSpace(p.getName().equals("oob_store64.wasm")?"memory64":"memory");
            check(Arrays.equals(emu.readMemory(space.getAddress(65532),4),new byte[]{65,66,67,68}),"Trapping store must preserve ABCD");
          }
        } else {
          check(emu.getExecutionAddress().getOffset()==ret,"Emulation must return: "+emu.getLastError());
          if(legacy && f.getName().equals("store_after_call")) {
            var space=p.getAddressFactory().getAddressSpace(p.getName().equals("call64.wasm")?"memory64":"memory");
            check(Arrays.equals(emu.readMemory(space.getAddress(0),4),new byte[]{7,0,0,0}),"Valid store after call");continue;
          }
          BigInteger wanted=legacy?BigInteger.valueOf(p.getName().equals("brtable_default.wasm")?2:0x12345678L):p.getName().equals("numeric_matrix.wasm")?numericExpected.get(f.getFuncIdx()):new BigInteger(expected.get(p.getName()));
          check(emu.readRegister(f.getReturns()[0].getSize()==8?"s0q":"s0").equals(wanted),"Wrong emulation result in "+p.getName()+" "+f.getName()+" wanted "+wanted);
        }
      } finally {emu.dispose();}
    }
  }
  public static void main(String[] args) throws Exception {
    init();
    for(String row:Files.readAllLines(Path.of(args[0]).getParent().resolve("numeric-expected.tsv"))) {
      var fields=row.split("\t");numericExpected.put(Integer.parseInt(fields[0]),new BigInteger(fields[1]));
    }
    int failures=0;
    for (String arg:args) {
      System.out.println("REVIEW FILE "+arg);
      ProgramDB p=null;
      try {p=load(Path.of(arg));inspect(p);emulate(p);PatchRegressionTest.run(p);} catch(Throwable e) {failures++;e.printStackTrace(System.out);} finally {if(p!=null)p.release(owner);}
    }
    System.out.println("Assertions: "+assertions+"; failed fixtures: "+failures);
    System.exit(failures==0?0:1);
  }
}
