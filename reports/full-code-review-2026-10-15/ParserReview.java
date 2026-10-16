import java.nio.file.*;
import ghidra.app.util.bin.*;
import wasm.format.*;
import wasm.format.sections.*;
public class ParserReview {
  public static void main(String[] args) throws Exception {
    ghidra.util.UniversalIdGenerator.initialize();
    for(String arg:args) {
      try {
        byte[] bytes=Files.readAllBytes(Path.of(arg));
        var module=new WasmModule(new BinaryReader(new ByteArrayProvider(bytes),true));
        System.out.println("PARSER ACCEPT "+arg+" bytes="+bytes.length+" sections="+module.getSections().size());
        var ts=(WasmTypeSection)module.getSection(WasmSection.WasmSectionId.SEC_TYPE);
        if(ts!=null) System.out.println("TYPE MARKUP declared="+ts.getSectionSize()+" actual="+ts.toDataType().getLength());
      } catch(Throwable e) {System.out.println("PARSER ERROR "+arg+" "+e);}
    }
  }
}
