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

public class ReviewHarness {
  static Object owner = new Object();
  static TaskMonitor monitor = TaskMonitor.DUMMY;
  static Language lang;
  static class LocalNameProbe extends WasmFunctionVariableNameAnalyzer {
    @Override protected Map<Long,Long> getLocalFirstUses(Program p,Function f,Set<Long> s){return new HashMap<>();}
    void apply(Program p,Function f,WasmFuncSignature sig){applyLocalNames(p,f,sig,Map.of(1L,"wide_local"));}
  }
  static void init() throws Exception {
    var config = new HeadlessGhidraApplicationConfiguration();
    config.setInitializeLogging(false);
    Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("review.ghidra","C:/Tools/ghidra_12.1.4_PUBLIC"))), config);
    lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("Wasm:LE:32:default"));
    System.out.println("REVIEW classes="+WasmLoader.class.getProtectionDomain().getCodeSource().getLocation());
    var cs=lang.getCompilerSpecByID(new CompilerSpecID("default"));
    System.out.println("REVIEW CSPEC stack="+cs.getStackBaseSpace()+" memoryGlobal="+cs.isGlobal(lang.getAddressFactory().getAddressSpace("memory").getAddress(1024))+" ramGlobal="+cs.isGlobal(lang.getAddressFactory().getDefaultAddressSpace().getAddress(1024)));
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
        } catch (Throwable e) { System.out.println("REVIEW ANALYSIS ERROR "+f.getName()+" "+e); }
      }
      new WasmSignatureAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
      if(p.getName().equals("local_names.wasm")) {
        var sig=state.getFunction(0);var f=p.getFunctionManager().getFunctionAt(sig.getStartAddr());
        new LocalNameProbe().apply(p,f,sig);
        for(var v:f.getLocalVariables()) System.out.println("REVIEW LOCAL "+v.getName()+" size="+v.getLength()+" expected=8 storage="+v.getVariableStorage());
      }
      if(p.getName().equals("global_index64.wasm")) {
        var m=WasmPreAnalyzer.class.getDeclaredMethod("guessCStackGlobalForFunction",Program.class,Address.class);m.setAccessible(true);
        System.out.println("REVIEW SP GUESS "+m.invoke(new WasmPreAnalyzer(),p,state.getFunction(0).getStartAddr())+" expected=64");
      }
      if(p.getName().startsWith("copy_")) {
        new WasmMemoryCopyAnalyzer().added(p,p.getMemory(),monitor,new MessageLog());
        for(var i:p.getListing().getInstructions(true)) if(i.getMnemonicString().equals("memory.copy")) System.out.println("REVIEW COPY LENGTH "+WasmMemoryCopyInfo.getLength(p,i.getAddress()));
      }
      if(p.getName().equals("multi_memarg.wasm")) {
        var method=WasmStructSynthAnalyzer.class.getDeclaredMethod("getMemoryOffset",Instruction.class);
        method.setAccessible(true);
        for(var i:p.getListing().getInstructions(true)) if(i.getMnemonicString().equals("i32.load")) System.out.println("REVIEW OFFSET "+method.invoke(null,i));
      }
      if(p.getName().equals("overlap_struct.wasm")) {
        var method=WasmStructSynthAnalyzer.class.getDeclaredMethod("createStructure",Program.class,String.class,TreeMap.class);
        method.setAccessible(true);
        var offsets=new TreeMap<Integer,Integer>();offsets.put(0,8);offsets.put(4,4);
        var st=(Structure)method.invoke(new WasmStructSynthAnalyzer(),p,"overlap_review",offsets);
        for(var c:st.getDefinedComponents()) System.out.println("REVIEW STRUCT "+c.getFieldName()+" offset="+c.getOffset()+" size="+c.getLength());
      }
    } finally { p.endTransaction(tx,true); }
    if(p.getName().equals("mutable_memory.wasm") || p.getName().startsWith("copy_")) {
      var d=new DecompInterface();d.openProgram(p);
      try{for(var f:p.getFunctionManager().getFunctions(true)) {
        var result=d.decompileFunction(f,20,monitor);
        System.out.println("REVIEW DECOMP "+f.getName()+" "+(result.getDecompiledFunction()==null?result.getErrorMessage():result.getDecompiledFunction().getC()));
      }} finally{d.dispose();}
    }
  }
  static void emulate(ProgramDB p) throws Exception {
    for (var f:WasmAnalysis.getState(p).getFunctions()) {
      if (f.isImport() || !f.getName().startsWith("test_")) continue;
      var emu=new EmulatorHelper(p);
      try {
        long ret=0x80000000L;
        new WasmEmulationHelper(lang).simulateCall(emu.getEmulator(),ret,f.getStartAddr().getOffset(),new BigInteger[0]);
        int steps=0;
        while(steps++<300 && emu.getExecutionAddress().getOffset()!=ret && emu.step(monitor)) {}
        var mem=p.getAddressFactory().getAddressSpace("memory");
        System.out.println("REVIEW EMU "+f.getName()+" steps="+steps+" returned="+(emu.getExecutionAddress().getOffset()==ret)+" s0="+emu.readRegister("s0")+" s0q="+emu.readRegister("s0q")+" error="+emu.getLastError()+" tail="+Arrays.toString(emu.readMemory(mem.getAddress(65532),4)));
      } catch(Throwable e) {System.out.println("REVIEW EMU ERROR "+f.getName()+" "+e);} finally {emu.dispose();}
    }
  }
  public static void main(String[] args) throws Exception {
    init();
    for (String arg:args) {
      System.out.println("REVIEW FILE "+arg);
      ProgramDB p=null;
      try {p=load(Path.of(arg));inspect(p);emulate(p);} catch(Throwable e) {System.out.println("REVIEW LOAD ERROR "+e);e.printStackTrace(System.out);} finally {if(p!=null)p.release(owner);}
    }
    System.exit(0);
  }
}
