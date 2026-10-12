// Print each linear-memory block of a loaded wasm program and the location of every non-zero byte
// run, so a data segment's placement can be checked byte-for-byte at any offset (used by
// probes_sections_i64.py to verify 64-bit data-segment offsets).
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class DumpMemory extends GhidraScript {

	@Override
	public void run() throws Exception {
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.getName().startsWith(".memory")) {
				continue;
			}
			long size = block.getSize();
			int n = (int) Math.min(size, Integer.MAX_VALUE);
			byte[] bytes = new byte[n];
			block.getBytes(block.getStart(), bytes);
			println("MEMBLOCK " + currentProgram.getName() + " " + block.getName()
					+ " start=" + block.getStart() + " size=" + size);

			int i = 0;
			while (i < bytes.length) {
				if (bytes[i] == 0) {
					i++;
					continue;
				}
				int start = i;
				while (i < bytes.length && bytes[i] != 0) {
					i++;
				}
				int end = i; // exclusive
				StringBuilder hex = new StringBuilder();
				StringBuilder ascii = new StringBuilder();
				for (int j = start; j < end; j++) {
					hex.append(String.format("%02x ", bytes[j]));
					ascii.append(bytes[j] >= 0x20 && bytes[j] < 0x7f ? (char) bytes[j] : '.');
				}
				println(String.format("MEMDATA %s +0x%x (%s) len=%d %s  %s", block.getName(), start,
					block.getStart().add(start), end - start, hex.toString(), ascii.toString()));
			}
		}
	}
}
