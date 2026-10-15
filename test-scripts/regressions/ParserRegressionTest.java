import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import ghidra.app.util.bin.*;
import wasm.format.*;
import wasm.format.sections.*;
import wasm.format.sections.structures.*;

/** Small-heap tests: malicious counts must fail before attempting allocations. */
public class ParserRegressionTest {
  static int assertions;
  static void check(boolean ok, String message) { assertions++; if(!ok) throw new AssertionError(message); }
  static BinaryReader reader(byte... bytes) { return new BinaryReader(new ByteArrayProvider(bytes),true); }
  interface Parse { void run() throws Exception; }
  static void rejects(Parse parse, String message) throws Exception {
    try { parse.run(); } catch(IOException expected) { assertions++; return; }
    throw new AssertionError(message);
  }
  public static void main(String[] args) throws Exception {
    ghidra.util.UniversalIdGenerator.initialize();
    Path fixtures=Path.of(args[0]);
    for(String name:List.of("huge_params", "truncated_datacount", "cross_section_type")) {
      rejects(()->new WasmModule(reader(Files.readAllBytes(fixtures.resolve(name+".wasm")))),name+" must reject");
    }
    byte[] huge={ (byte)0x80,(byte)0x80,(byte)0x80,(byte)0x80,1 };
    var results=new java.io.ByteArrayOutputStream(); results.writeBytes(new byte[]{0x60,0});results.writeBytes(huge);
    rejects(()->new WasmFuncType(reader(results.toByteArray())),"Huge result vector");
    var supers=new java.io.ByteArrayOutputStream();supers.write(0x50);supers.writeBytes(huge);supers.write(0x60);
    rejects(()->WasmGCType.parseTypeEntry(reader(supers.toByteArray())),"Huge supertype vector");
    rejects(()->new WasmCodeEntry(reader((byte)1,(byte)1,(byte)1,(byte)0x7f,(byte)0x0b)),"Locals cannot read past a body boundary");
    // A malformed name map may fall back to raw markup, but cannot steal the next map's bytes.
    var names=reader((byte)1,(byte)1,(byte)1,(byte)1,(byte)4,(byte)1,(byte)0,(byte)1,(byte)'x');
    var first=WasmNameSubsection.createSubsection(names);
    check(names.getPointerIndex()==3,"Bound first name subsection");
    check(!(first instanceof WasmNameMapSubsection),"Truncated name map must not read following subsection");
    rejects(()->WasmNameSubsection.createSubsection(reader((byte)1,(byte)5,(byte)0)),"Truncated name payload");
    check(new WasmGlobalType(reader((byte)0x63,(byte)0x70,(byte)0)).toDataType().getLength()==3,"Global markup length");
    check(new WasmLocalEntry(reader((byte)1,(byte)0x63,(byte)0x70)).toDataType().getLength()==3,"Local markup length");
    check(new WasmGlobalType(reader((byte)0x63,(byte)0xc0,(byte)0,(byte)0)).toDataType().getLength()==4,"Global multibyte heap index markup");
    check(new WasmLocalEntry(reader((byte)1,(byte)0x63,(byte)0xc0,(byte)0)).toDataType().getLength()==4,"Local multibyte heap index markup");
    check(new WasmFuncType(reader((byte)0x60,(byte)1,(byte)0x63,(byte)0xc0,(byte)0,(byte)0)).toDataType().getLength()==6,"Signature multibyte heap index markup");
    check(new WasmTableType(reader((byte)0x63,(byte)0xc0,(byte)0,(byte)0,(byte)1)).toDataType().getLength()==5,"Table multibyte heap index markup");
    for(String name:List.of("typed_signature", "rec_functype", "table_initializer")) {
      var module=new WasmModule(reader(Files.readAllBytes(fixtures.resolve(name+".wasm"))));
      for(var section:module.getSections()) if(!(section instanceof WasmCodeSection)) check(section.toDataType().getLength()==section.getSectionSize(),name+" markup "+section.getName());
    }
    var module=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("gc_return.wasm"))));
    check(module.getType(1).getReturnTypes()[0]==WasmEnums.ValType.structref,"Concrete struct return family");
    System.out.println("Parser regression assertions: "+assertions);
  }
}
