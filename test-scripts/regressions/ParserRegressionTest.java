import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import wasm.WasmLoader;
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
    // array.new_fixed in a constant expression keeps its typeidx/count immediates (count 11 is 0x0b).
    var fixed=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("gc_new_fixed_const.wasm"))));
    check(fixed.getNonImportedGlobals().size()==2,"array.new_fixed constant expression with count 11 must not end early");
    // select t* is vec(valtype): a multibyte reftype whose heap index is 0x0b must not end the expression.
    var selectBytes=new byte[]{0x1c,1,0x63,0x0b,0x0b,0x7f};
    var selectReader=reader(selectBytes);
    new ConstantExpression(selectReader);
    check(selectReader.getPointerIndex()==5,"select t* constant expression consumes vec(valtype)");
    // The function and code sections may disagree: only functions with both are enumerated.
    var mismatch=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("func_code_mismatch.wasm"))));
    check(mismatch.getDeclaredFunctionCount()==2 && mismatch.getFunctionCount()==1,"Function count counts only functions with bodies");
    check(mismatch.getFunctionCode(1)==null && mismatch.getFunctionCode(5)==null,"Missing function body is null, not an exception");
    check(WasmLoader.getFunctionAddressOffset(mismatch,1)==0 && WasmLoader.getFunctionSize(mismatch,1)==0,"Address helpers tolerate a missing body");
    // An explicit multibyte element reftype is kept, resolved and fully covered by the markup.
    var elem=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("elem_reftype_multibyte.wasm"))));
    var segment=elem.getElementSegments().get(0);
    check(segment.getElementType()==WasmEnums.ValType.funcref,"Element reftype (ref null $0) resolves to funcref");
    check(segment.toDataType().getLength()==7,"Element segment markup covers the multibyte reftype");
    // table64 limits compare unsigned: a maximum of 2^64-1 is not smaller than the initial size.
    var table=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("table64_max_unsigned.wasm"))));
    var validate=WasmLoader.class.getDeclaredMethod("validateTableLimits",int.class,WasmTableType.class);
    validate.setAccessible(true);
    validate.invoke(null,0,table.getTableType(0));
    check(table.getTableType(0).is64Bit(),"table64 maximum above 2^63 is accepted");
    // Export lookup is indexed by (kind, index) and keeps the first export of an index.
    var exports=new WasmModule(reader(Files.readAllBytes(fixtures.resolve("export_lookup.wasm"))));
    check("first".equals(exports.findExport(WasmEnums.WasmExternalKind.EXT_FUNCTION,0).getName()),"First export of a function wins");
    check("other".equals(exports.findExport(WasmEnums.WasmExternalKind.EXT_FUNCTION,1).getName()),"Export of second function");
    check(exports.findExport(WasmEnums.WasmExternalKind.EXT_FUNCTION,2)==null && exports.findExport(WasmEnums.WasmExternalKind.EXT_GLOBAL,0)==null,"Missing export is null");
    // Unknown 0xFD/0xFE sub-opcodes relax validation like 0xFC and consume no guessed memarg:
    // the following drop must not fail the function, and the final end must still be analysed.
    for(byte[] unknown:List.of(new byte[]{(byte)0xfd,(byte)0x80,0x04},new byte[]{(byte)0xfe,0x60})) {
      var bodyBytes=new java.io.ByteArrayOutputStream();bodyBytes.write(0);bodyBytes.writeBytes(unknown);bodyBytes.write(0x1a);bodyBytes.write(0x0b);
      byte[] body=bodyBytes.toByteArray();
      var bytes=new java.io.ByteArrayOutputStream();
      bytes.writeBytes(new byte[]{0,0x61,0x73,0x6d,1,0,0,0, 1,4,1,0x60,0,0, 3,2,1,0, 10,(byte)(body.length+2),1,(byte)body.length});
      bytes.writeBytes(body);
      var analysis=new wasm.analysis.WasmAnalysis(new ghidra.program.model.address.DefaultAddressFactory(new ghidra.program.model.address.AddressSpace[]{
        new ghidra.program.model.address.GenericAddressSpace("ram",32,ghidra.program.model.address.AddressSpace.TYPE_RAM,0)}),new WasmModule(reader(bytes.toByteArray())));
      var start=analysis.getFunction(0).getStartAddr();
      var walk=analysis.getFunctionAnalysis(start);
      check(walk.getStackEffect(start.add(body.length-1))!=null,String.format("Unknown 0x%02x sub-opcode keeps the rest of the body analysable",unknown[0]&0xff));
    }
    System.out.println("Parser regression assertions: "+assertions);
  }
}
