/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmCodeEntry implements StructConverter {

	/**
	 * B1/J02/J03/NS06/NS07: upper bound on the number of locals a single function may declare
	 * (parameters excluded).
	 *
	 * <p>The binary format puts no bound on a function's declared locals - they are
	 * zero-initialised, so a few bytes can declare billions of them - and this loader materialises
	 * them ({@link #getLocals()}) into a {@code ValType[]} during analysis. Summing the declared
	 * counts without a bound is what made a 30-byte module raise an escaping
	 * {@code OutOfMemoryError} (J02/{@code B04_locals_1G_alloc}) or a silent
	 * {@code NegativeArraySizeException} (J03/{@code B03_locals_ffffffff}).
	 *
	 * <p>The limit is far above anything a real toolchain emits: no function in the 747-module
	 * regression corpus (Rust/Clang/npm modules + the testsuite's valid modules) declares more than
	 * 84 locals, and V8 caps a function at 50&#160;000 locals, so 1&#160;000&#160;000 can never
	 * reject a module that runs in a real engine, while bounding the allocation to at most 4&#160;MB
	 * per function.
	 */
	public static final int MAX_FUNCTION_LOCALS = 1_000_000;

	/**
	 * B1: upper bound on the total number of locals a single module may declare across all of its
	 * functions. A module can otherwise "spread" the per-function budget over many tiny functions
	 * (each function body is only a few bytes), so the per-function limit alone does not bound the
	 * total allocation made by {@code WasmAnalysis.getFunctions()}.
	 *
	 * <p>The largest total observed in the 747-module regression corpus is 1398, so this limit has
	 * more than 7000x headroom (worst case ~40&#160;MB of {@code ValType} references).
	 */
	public static final long MAX_MODULE_LOCALS = 10_000_000L;

	private LEB128Info codeSize;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private LEB128Info localCount;
	private long codeOffset;
	private long declaredLocalCount;
	private byte[] instructions;

	public WasmCodeEntry(BinaryReader reader) throws IOException {
		codeSize = reader.readNext(LEB128Info::unsigned);
		codeOffset = reader.getPointerIndex();
		localCount = reader.readNext(LEB128Info::unsigned);

		/*
		 * B1: bound the locals *before* anything is allocated. `numGroups` counts locals vectors
		 * (count,type pairs), each of which occupies at least 2 bytes, so it can never exceed the
		 * number of bytes still left in the module.
		 */
		long numGroups = localCount.asLong();
		long remaining = reader.length() - reader.getPointerIndex();
		if (numGroups < 0 || numGroups > remaining) {
			throw new IOException("Invalid local-group count " + Long.toUnsignedString(numGroups)
					+ " for a function body with only " + remaining + " byte(s) left");
		}

		long total = 0;
		for (long i = 0; i < numGroups; ++i) {
			WasmLocalEntry local = new WasmLocalEntry(reader);
			long declared = local.getCountLong();
			if (declared < 0 || declared > MAX_FUNCTION_LOCALS || total > MAX_FUNCTION_LOCALS - declared) {
				throw new IOException("Function declares more than " + MAX_FUNCTION_LOCALS
						+ " locals (the loader's per-function limit; see REPORT-HARD.md)");
			}
			total += declared;
			locals.add(local);
		}
		declaredLocalCount = total;

		instructions = reader.readByteArray(codeOffset, codeSize.asInt32());
		reader.setPointerIndex(codeOffset + codeSize.asLong());
	}


	public LEB128Info getCodeSizeLeb128() {
		return codeSize;
	}

	public long getCodeSize() {
		return codeSize.asLong();
	}

	public long getOffset() {
		return codeOffset;
	}

	/**
	 * The total number of locals (parameters excluded) this function declares, computed while
	 * parsing and without allocating anything. Used by the loader to enforce
	 * {@link #MAX_MODULE_LOCALS} across the whole module.
	 */
	public long getDeclaredLocalCount() {
		return declaredLocalCount;
	}

	public byte[] getInstructions() {
		return instructions;
	}

	public ValType[] getLocals() {
		long localCount = 0;
		for (WasmLocalEntry local : locals) {
			long declared = local.getCountLong();
			localCount += declared;
			if (localCount < 0 || localCount > MAX_FUNCTION_LOCALS) {
				/*
				 * Unreachable in practice: the constructor already rejects any function whose
				 * declared locals exceed the limit. Kept as a defensive last line of defence so an
				 * allocation can never be sized from an unchecked count.
				 */
				throw new IllegalStateException("Function declares more than " + MAX_FUNCTION_LOCALS
						+ " locals (the loader's per-function limit; see REPORT-HARD.md)");
			}
		}
		ValType[] result = new ValType[(int) localCount];
		int pos = 0;
		for (WasmLocalEntry local : locals) {
			int count = (int) local.getCountLong();
			Arrays.fill(result, pos, pos + count, local.getType());
			pos += count;
		}
		return result;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("code_" + codeOffset);
		builder.addUnsignedLeb128(codeSize, "code_size");
		builder.addArray(BYTE, instructions.length, "instructions");
		return builder.toStructure();
	}
}
