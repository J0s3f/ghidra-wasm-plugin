package wasm.format;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProviderWrapper;

/** Shared physical bounds for all module parse paths, including emulator re-parsing. */
public final class WasmParsing {
	private WasmParsing() {}
	public static final int MAX_TYPE_VALUES = 1_000_000;

	/** Keep file-relative offsets, but prevent a child reader from crossing its container. */
	public static BinaryReader boundedReader(BinaryReader reader, long start, long length) throws IOException {
		if (start < 0 || length < 0 || start > reader.length() || length > reader.length() - start) {
			throw new IOException("Truncated or overflowing Wasm payload at " + start + " (size " + length + ")");
		}
		BinaryReader child = new BinaryReader(new ByteProviderWrapper(reader.getByteProvider(), 0, start + length), reader.isLittleEndian());
		child.setPointerIndex(start);
		return child;
	}

	public static int checkedCount(BinaryReader reader, long count, int minimumBytes, String name) throws IOException {
		long remaining = reader.length() - reader.getPointerIndex();
		if (count < 0 || count > MAX_TYPE_VALUES || count > remaining / minimumBytes) {
			throw new IOException("Invalid " + name + " count " + Long.toUnsignedString(count) + " (" + remaining + " bytes remain)");
		}
		return (int) count;
	}
}
