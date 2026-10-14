// Normalize only compiler-assigned unique offsets and address-space IDs.
//@category Test.Wasm
import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
public class MemoryPcodeFingerprint extends GhidraScript {
    private String normalized(Varnode v, Map<Long, Integer> uniques) {
        if (v == null) return "-";
        if (v.isUnique()) {
            int id = uniques.computeIfAbsent(v.getOffset(), key -> uniques.size());
            return "u" + id + ":" + v.getSize();
        }
        return v.getAddress().getAddressSpace().getName() + ":"
            + Long.toHexString(v.getOffset()) + ":" + v.getSize();
    }

    // Space IDs and compiler-assigned unique offsets are normalized, while opcode,
    // register offsets, widths, constants and memory spaces must match exactly.
    public void run() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        int count = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().startsWith("m64_")) continue;
            for (Instruction insn : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                Map<Long, Integer> uniques = new HashMap<>();
                for (PcodeOp op : insn.getPcode()) {
                    String text = op.getMnemonic() + " " + normalized(op.getOutput(), uniques);
                    for (int i = 0; i < op.getNumInputs(); i++) {
                        if (i == 0 && (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE)) {
                            text += " " + currentProgram.getAddressFactory()
                                .getAddressSpace((int) op.getInput(0).getOffset()).getName();
                        } else text += " " + normalized(op.getInput(i), uniques);
                    }
                    digest.update((text + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    count++;
                }
            }
        }
        println("I32-PCODE " + currentProgram.getName() + " ops=" + count + " sha256="
            + java.util.HexFormat.of().formatHex(digest.digest()));
    }

}
