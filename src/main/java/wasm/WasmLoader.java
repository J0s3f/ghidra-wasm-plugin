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
package wasm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.format.StructureBuilder;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmUnknownCustomSection;
import wasm.format.sections.structures.WasmCodeEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmLoader extends AbstractLibrarySupportLoader {

	public final static String WEBASSEMBLY = "WebAssembly";

	public final static long IMPORT_BASE = 0x7f000000L;
	public final static long CODE_BASE = 0x80000000L;
	/*
	 * @@MM: multi-memory. Linear memory N is mapped into the dedicated `memory` address
	 * space at N * MEMORY_STRIDE (memory 0 therefore stays at offset 0, exactly as
	 * before, so the C stack/heap analysis and every single-memory module are
	 * unaffected). The `memory` space is 32-bit (size=4, see WebAssembly.slaspec), so
	 * the stride is 128 MiB: memory index >= 8 no longer collides with the module image
	 * in `ram` at CODE_BASE (0x80000000), and indices 0..31 fit in 32 bits (memory 31 =
	 * 0xF8000000). All 32-bit memory address arithmetic stays in 32 bits (addr:4), so
	 * the decompiled C has no ZEXT noise. memory64 addresses above 4 GiB wrap (same as
	 * the pre-memory-space behaviour; see REPORT-N.md). The stride keeps the memories
	 * apart: each memory should be at most MEMORY_STRIDE bytes. Must stay in sync with
	 * @define MEMORY_STRIDE in data/languages/WebAssembly.sinc.
	 */
	public final static long MEMORY_STRIDE = 0x08000000L;
	/*
	 * @@M64: the `memory` address space is 32-bit (size=4, see WebAssembly.slaspec), so
	 * getMemoryAddress() can represent any offset up to 4 GiB. The SLEIGH truncates
	 * memory64 effective addresses to 32 bits (addr:4 = full:4), so decoded accesses
	 * above 4 GiB wrap - a modelling choice, not a space limitation (see REPORT-N.md).
	 */
	public final static long MEMORY_MAX_ADDRESS = 0xffffffffL;
	/* The size of one WebAssembly linear-memory page. */
	public final static long MEMORY_PAGE_SIZE = 65536L;
	/*
	 * B2/J01/M03/NS12/NS10: the largest initialized region the loader will materialise for a
	 * single memory (128 MiB, i.e. MEMORY_STRIDE). A malformed or absurd `initial` used to be
	 * clamped to CODE_BASE (2 GiB) and a tiny module could force that allocation, wedging
	 * auto-analysis. Valid modules are unaffected: the largest memory in the 747-module
	 * regression corpus is 17 pages (1 MiB), and the memory64 / multi-memory probes use 1-7
	 * pages. Anything larger is clamped (with a warning) rather than rejected, so a spec-valid
	 * module with a very large declared memory still imports - just with a bounded block.
	 */
	public final static long MAX_MEMORY_BLOCK_BYTES = MEMORY_STRIDE;
	/* Core-spec page limit for a 32-bit-index memory: 65536 pages = 4 GiB. */
	public final static long MAX_MEMORY32_PAGES = 65536L;
	/* Implementation page limit for a 64-bit-index memory (memory64); well above any real module. */
	public final static long MAX_MEMORY64_PAGES = 1L << 48;
	/*
	 * B5/J04/NS10: the largest table region the loader will materialise (64 MiB). A table whose
	 * declared minimum would exceed this is *not* materialised and a clear error is logged, so a
	 * table with min = 0xffffffff can no longer be lost silently (previously Ghidra's 16 GiB guard
	 * refused the block and the accepted program simply had no table). The largest table in the
	 * regression corpus has 1024 entries.
	 */
	public final static long MAX_TABLE_BLOCK_BYTES = 64L * 1024 * 1024;
	/* Size of each register */
	public final static int REG_SIZE = 16;

	@Override
	public String getName() {
		return WEBASSEMBLY;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if (Arrays.equals(WasmConstants.WASM_MAGIC, header.getMagic()) && WasmConstants.WASM_VERSION == header.getVersion()) {
			loadSpecs.add(new LoadSpec(this, CODE_BASE, new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	// #region Address computations
	public static long getFunctionAddressOffset(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return IMPORT_BASE + funcidx * 4;
		} else {
			WasmCodeEntry codeEntry = module.getNonImportedFunctions().get(funcidx - imports.size());
			return CODE_BASE + codeEntry.getOffset();
		}
	}

	public static long getFunctionSize(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return 4;
		} else {
			WasmCodeEntry codeEntry = module.getNonImportedFunctions().get(funcidx - imports.size());
			return codeEntry.getCodeSize();
		}
	}

	public static Address getFunctionAddress(AddressFactory addressFactory, WasmModule module, int funcidx) {
		return addressFactory.getAddressSpace("ram").getAddress(getFunctionAddressOffset(module, funcidx));
	}

	public static Address getTableAddress(AddressFactory addressFactory, int tableidx, long itemIndex) {
		return addressFactory.getAddressSpace("table").getAddress((((long) tableidx) << 32) + (itemIndex * 4));
	}

	/**
	 * @@MM: the address of a byte in linear memory {@code memidx}.
	 *
	 * <p>Memory 0 lives at offset 0 in the dedicated {@code memory} address space
	 * (unchanged); memory N &gt;= 1 lives at {@code N * MEMORY_STRIDE} (see
	 * {@link #MEMORY_STRIDE}), matching the address the SLEIGH memarg decoders compute
	 * for a memarg that carries a memory index. The {@code memory} space is 32-bit, so
	 * with MEMORY_STRIDE = 128 MiB, memory indices 0..31 are representable without
	 * colliding with the module image in {@code ram}.
	 *
	 * <p>@@M64: a 64-bit (memory64) memory may address up to 2^64, which the 32-bit
	 * {@code memory} space cannot represent. The SLEIGH truncates effective addresses to
	 * 32 bits (see REPORT-N.md), so decoded accesses above 4 GiB wrap - a modelling
	 * choice, not a space limitation.
	 */
	public static Address getMemoryAddress(AddressFactory addressFactory, int memidx, long offset) {
		long base = ((long) memidx) * MEMORY_STRIDE;
		long address = base + offset;
		if (memidx < 0 || offset < 0 || base < 0 || address < 0 || address > MEMORY_MAX_ADDRESS) {
			Msg.warn(WasmLoader.class, "Address memidx=" + memidx + " offset=0x" + Long.toHexString(offset)
					+ " does not fit the 32-bit `memory` address space; clamping to 0x"
					+ Long.toHexString(MEMORY_MAX_ADDRESS)
					+ " (see REPORT-N.md)");
			address = MEMORY_MAX_ADDRESS;
		}
		return addressFactory.getAddressSpace("memory").getAddress(address);
	}

	public static Address getGlobalAddress(AddressFactory addressFactory, int globalidx) {
		return addressFactory.getAddressSpace("global").getAddress(((long) globalidx) * REG_SIZE);
	}

	public static Address getModuleAddress(AddressFactory addressFactory) {
		return getCodeAddress(addressFactory, 0);
	}

	private static Address getCodeAddress(AddressFactory addressFactory, long fileOffset) {
		return addressFactory.getAddressSpace("ram").getAddress(CODE_BASE + fileOffset);
	}
	// #endregion

	// #region Naming
	private static Symbol createLabel(Program program, Address address, String name, Namespace namespace, SourceType sourceType) throws InvalidInputException {
		if (name == null || name.isEmpty()) {
			name = "unnamed";
		}

		// Make spaces into non-breaking spaces to avoid invalid chars
		name = name.replace(" ", "\u00A0");
		// Replace any other invalid chars with _
		name = SymbolUtilities.replaceInvalidChars(name, true);
		// Leave room for a suffix if necessary
		int maxLen = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - 16;
		if (name.length() > maxLen) {
			name = name.substring(0, maxLen);
		}
		String newname = name;
		int suffix = 0;
		while (!program.getSymbolTable().getSymbols(newname, namespace).isEmpty()) {
			suffix++;
			newname = name + "_" + suffix;
		}

		return program.getSymbolTable().createLabel(address, newname, namespace, sourceType);
	}

	private static Namespace getNamespace(Program program, Namespace parent, String name) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(parent, name, SourceType.IMPORTED);
		} catch (Exception e) {
			return parent;
		}
	}

	private static Namespace getObjectNamespace(Program program, WasmModule module, WasmExternalKind objectKind, int objidx) {
		Namespace globalNamespace = program.getGlobalNamespace();

		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			Namespace importNamespace = getNamespace(program, globalNamespace, "import");
			return getNamespace(program, importNamespace, imports.get(objidx).getModule());
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return getNamespace(program, globalNamespace, "export");
		}
		return globalNamespace;
	}

	private static String getObjectName(WasmModule module, WasmExternalKind objectKind, int objidx) {
		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			return imports.get(objidx).getName();
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return entry.getName();
		}
		return null;
	}

	public static Namespace getFunctionNamespace(Program program, WasmModule module, int funcidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_FUNCTION, funcidx);
	}

	public static String getFunctionName(WasmModule module, int funcidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getFunctionName(funcidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(module, WasmExternalKind.EXT_FUNCTION, funcidx);
		if (name != null) {
			return name;
		}
		return "unnamed_function_" + funcidx;
	}

	public static Namespace getGlobalNamespace(Program program, WasmModule module, int globalidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_GLOBAL, globalidx);
	}

	public static String getGlobalName(Program program, WasmModule module, int globalidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getGlobalName(globalidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(module, WasmExternalKind.EXT_GLOBAL, globalidx);
		if (name != null) {
			return name;
		}
		return "global_" + globalidx;
	}
	// #endregion

	// #region Memory blocks
	private static Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(WasmLoader.class, "Data markup conflict at " + address, e);
		}
		return null;
	}

	private static MemoryBlock createModuleBlock(Program program, FileBytes fileBytes) throws Exception {
		Address start = getCodeAddress(program.getAddressFactory(), 0);
		MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
		block.setSourceName("Wasm Module");
		block.setComment("The full file contents of the Wasm module");
		return block;
	}

	private static void createImportStubBlock(Program program, Address startAddress, long length) {
		try {
			MemoryBlock block = program.getMemory().createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, startAddress, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setComment("NOTE: This block is artificial and is used to represent imported functions");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create imported function block at " + startAddress, e);
		}
	}

	private static void createTableBlock(Program program, DataType elementDataType, long numElements, int tableidx, boolean is64Bit, TaskMonitor monitor) {
		if (numElements == 0) {
			return;
		}
		/*
		 * B5/J04: bound the table before sizing an allocation. `numElements` is a u32, so it can
		 * be up to 0xffffffff; the previous code multiplied that by the element size and handed the
		 * result to Ghidra, which refused the block and left the accepted program silently without a
		 * table. Anything beyond the modelled limit is now skipped with an explicit diagnostic.
		 *
		 * @@T64: a 64-bit table (table64, limits flag 0x04) can declare up to 2^64-1 elements, so its
		 * `initial` does not even fit the u32 the 32-bit form is limited to. Such a table is not
		 * materialised - the loader only models the small fixed tables real modules use - and the
		 * diagnostic names the 64-bit index type so the reason is unambiguous.
		 */
		long elementSize = elementDataType.getLength();
		if (numElements < 0 || numElements > Integer.MAX_VALUE
				|| (elementSize > 0 && numElements > MAX_TABLE_BLOCK_BYTES / elementSize)) {
			Msg.error(WasmLoader.class, "Table " + tableidx + (is64Bit ? " (i64 index)" : "")
					+ " declares " + Long.toUnsignedString(numElements)
					+ " element(s); this exceeds the loader's table limit of " + MAX_TABLE_BLOCK_BYTES
					+ " byte(s), so the table is not materialised (see REPORT-HARD.md)");
			return;
		}
		long byteSize = elementSize * numElements;
		Address dataStart = getTableAddress(program.getAddressFactory(), tableidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".table" + tableidx, dataStart, byteSize, (byte) 0x00, monitor, false);
			block.setRead(true);
			/*
			 * Mark the table read-only: for compiled C/C++ modules the function
			 * table is fixed at instantiation (element segments), and read-only
			 * lets the decompiler treat entries as constants — a call_indirect
			 * with a statically-known index then resolves to a direct call to
			 * the actual function. (table.set/table.grow at runtime would be
			 * misrepresented, but such modules are rare and were previously
			 * unreadable anyway.)
			 */
			block.setWrite(false);
			block.setExecute(false);
			if (is64Bit) {
				/*
				 * @@T64: unlike memory64 there is no truncation here - the `table` address space is 8
				 * bytes wide - so a 64-bit table is fully modelled; make its index type visible.
				 */
				block.setComment("64-bit (table64) table: the index type is i64; entries are mapped "
						+ "into the 64-bit `table` address space");
			}
			DataType tableDataType = new ArrayDataType(elementDataType, (int) numElements, elementDataType.getLength());
			createData(program, program.getListing(), dataStart, tableDataType);
			createLabel(program, dataStart, "table" + tableidx, program.getGlobalNamespace(), SourceType.IMPORTED);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create table block " + tableidx + " at " + dataStart, e);
		}
	}

	private static void createMemoryBlock(Program program, int memidx, long length, boolean is64Bit, TaskMonitor monitor) {
		if (length == 0) {
			return;
		}
		Address dataStart = getMemoryAddress(program.getAddressFactory(), memidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".memory" + memidx, dataStart, length, (byte) 0x00, monitor, false);
			block.setRead(true);
			/*
			 * Mark linear memory read-only so the decompiler (which respects
			 * read-only flags by default) constant-folds reads of compile-time
			 * constant addresses: string/array/const-data references then render
			 * as inline literals (printf("Hello") instead of
			 * printf(s_Hello_ram_...)) and array initializers are recovered.
			 * This is safe for genuinely mutable globals: the decompiler only
			 * folds addresses that have NO store references, so a global written
			 * anywhere Ghidra can see stays a memory read. Stack/heap accesses go
			 * through registers/runtime pointers (not constant addresses) and are
			 * never folded. Data segments are written into this block during
			 * loading via the low-level Memory API, which bypasses this flag.
			 */
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Memory");
			if (is64Bit) {
				/*
				 * @@M64: make the (lossy) representation visible in the listing. The block
				 * is in the 32-bit `memory` address space, but the SLEIGH truncates effective
				 * addresses to 32 bits, so only addresses below 4 GiB are decoded exactly.
				 */
				block.setComment("64-bit (memory64) linear memory: the index type is i64, but the SLEIGH "
						+ "truncates effective addresses to 32 bits, so only addresses below 4 GiB are "
						+ "decoded exactly (accesses above that wrap; see REPORT-N.md)");
			}
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create memory block " + memidx + " at " + dataStart, e);
		}
	}

	/**
	 * @@M64: the byte size of a memory's declared initial size (pages), with saturation.
	 * A 64-bit memory can declare a u64 page count; anything that does not fit - or whose
	 * byte size would overflow - becomes {@link Long#MAX_VALUE} so the caller's clamp can
	 * never be defeated by an integer overflow.
	 */
	private static long memoryByteSize(long pages) {
		if (pages < 0 || pages > (Long.MAX_VALUE / MEMORY_PAGE_SIZE)) {
			return Long.MAX_VALUE;
		}
		return pages * MEMORY_PAGE_SIZE;
	}

	/**
	 * B2/NS10: validate a memory's resizable limits before anything is materialised.
	 *
	 * <p>The core spec requires {@code initial <= maximum} for every memory (32- and 64-bit), and
	 * caps a 32-bit memory at 65536 pages (4 GiB) / a 64-bit memory at 2^48 pages. A malformed
	 * module can otherwise declare {@code initial = 0xFFFFFFFF} pages (J01/M03/NS12) or a
	 * {@code min > max} pair (M01), neither of which a real engine would accept.
	 *
	 * @throws IOException when the declared limits are out of range; the caller lets this fail the
	 *         import (a load failure must be visible, see {@link #load})
	 */
	private static void validateMemoryLimits(int memidx, WasmResizableLimits memory) throws IOException {
		long initial = memory.getInitial();
		long limit = memory.is64Bit() ? MAX_MEMORY64_PAGES : MAX_MEMORY32_PAGES;
		if (memory.hasMaximum() && initial > memory.getMaximum()) {
			throw new IOException("Memory " + memidx + " is invalid: initial size " + initial
					+ " page(s) exceeds the declared maximum " + memory.getMaximum() + " page(s)");
		}
		if (initial > limit) {
			throw new IOException("Memory " + memidx + " is invalid: initial size " + initial
					+ " page(s) exceeds the " + (memory.is64Bit() ? "64-bit" : "32-bit") + " limit of "
					+ limit + " page(s)");
		}
		if (memory.hasMaximum() && memory.getMaximum() > limit) {
			throw new IOException("Memory " + memidx + " is invalid: maximum size " + memory.getMaximum()
					+ " page(s) exceeds the " + (memory.is64Bit() ? "64-bit" : "32-bit") + " limit of "
					+ limit + " page(s)");
		}
	}

	/**
	 * B5/NS10: validate a table's resizable limits before a block is created. The core spec
	 * requires {@code initial <= maximum}; the byte-size bound is enforced in
	 * {@link #createTableBlock}.
	 *
	 * @throws IOException when the declared limits are out of range
	 */
	private static void validateTableLimits(int tableidx, WasmTableType table) throws IOException {
		WasmResizableLimits limits = table.getLimits();
		if (limits.hasMaximum() && limits.getInitial() > limits.getMaximum()) {
			throw new IOException("Table " + tableidx + " is invalid: initial size " + limits.getInitial()
					+ " element(s) exceeds the declared maximum " + limits.getMaximum() + " element(s)");
		}
	}

	private static void createGlobalBlock(Program program, DataType dataType, byte[] initBytes, int globalidx, int mutability, TaskMonitor monitor) {
		Address dataStart = getGlobalAddress(program.getAddressFactory(), globalidx);
		try {
			MemoryBlock block;
			if (initBytes == null) {
				block = program.getMemory().createUninitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), false);
			} else {
				block = program.getMemory().createInitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), (byte) 0x00, monitor, false);
				program.getMemory().setBytes(dataStart, initBytes);
			}
			block.setRead(true);
			block.setWrite((mutability != 0) ? true : false);
			block.setExecute(false);
			createData(program, program.getListing(), dataStart, dataType);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create global block " + globalidx + " at " + dataStart, e);
		}
	}

	private static void createCodeLengthData(Program program, MemoryBlock moduleBlock, WasmModule module) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		List<WasmCodeEntry> codeEntries = module.getNonImportedFunctions();
		for (int i = 0; i < codeEntries.size(); i++) {
			WasmCodeEntry entry = codeEntries.get(i);
			StructureBuilder builder = new StructureBuilder("code_" + (i + imports.size()));
			builder.addUnsignedLeb128(entry.getCodeSizeLeb128(), "code_size");
			long offset = entry.getOffset() - entry.getCodeSizeLeb128().getLength();
			createData(program, program.getListing(), moduleBlock.getStart().add(offset), builder.toStructure());
		}
	}
	// #endregion

	public void createImportExportSymbols(Program program, WasmModule module, int funcidx, Function function) throws Exception {

		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		// imported function
		if (funcidx < imports.size()) {
			WasmImportEntry importEntry = imports.get(funcidx);
			// create Import symbol
			ExternalLocation extLoc = program.getExternalManager().addExtFunction(
					importEntry.getModule(), importEntry.getName(), function.getEntryPoint(),
					SourceType.IMPORTED);
			function.setThunkedFunction(extLoc.getFunction());
			return;
		}

		WasmExportEntry entry = module.findExport(WasmExternalKind.EXT_FUNCTION, funcidx);
		// exported function
		if (entry != null) {
			program.getSymbolTable().addExternalEntryPoint(function.getEntryPoint());
		}
	}

	private void loadFunctions(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading functions");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		List<WasmCodeEntry> codeEntries = module.getNonImportedFunctions();
		int numFunctions = imports.size() + codeEntries.size();

		if (imports.size() > 0) {
			createImportStubBlock(program, getFunctionAddress(program.getAddressFactory(), module, 0), imports.size() * 4);
		}

		monitor.initialize(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			Address startAddress = getFunctionAddress(program.getAddressFactory(), module, funcidx);
			long functionLength = getFunctionSize(module, funcidx);
			String functionName = getFunctionName(module, funcidx);
			Namespace functionNamespace = getFunctionNamespace(program, module, funcidx);

			try {
				Symbol symbol = createLabel(program, startAddress, functionName, functionNamespace, SourceType.IMPORTED);
				Function function = program.getFunctionManager().createFunction(symbol.getName(false), symbol.getParentNamespace(),
						startAddress, new AddressSet(startAddress, startAddress.add(functionLength - 1)), SourceType.IMPORTED);
				try {
					createImportExportSymbols(program, module, funcidx, function);
				} catch (Exception e) {
					Msg.error(this, "Failed to create import/export symbol for function index " + funcidx + " (" + functionName + ") at " + startAddress, e);
				}
			} catch (Exception e) {
				Msg.error(this, "Failed to create function index " + funcidx + " (" + functionName + ") at " + startAddress, e);
			}
		}
	}

	private void loadTables(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) throws IOException {
		monitor.setMessage("Loading tables");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_TABLE);
		List<WasmTableType> tables = module.getNonImportedTables();
		int numTables = imports.size() + tables.size();

		monitor.initialize(numTables);
		for (int tableidx = 0; tableidx < numTables; tableidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmTableType table;
			if (tableidx < imports.size()) {
				table = imports.get(tableidx).getTableType();
			} else {
				table = tables.get(tableidx - imports.size());
			}

			validateTableLimits(tableidx, table);
			createTableBlock(program, table.getElementDataType(), table.getLimits().getInitial(), tableidx, table.is64Bit(), monitor);
		}
	}

	/**
	 * Copy element segment to table.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * element segment once the dynamic table index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadElementsToTable(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), elemidx, tableidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadElementsToTable(Program program, WasmModule module, int elemidx, int tableidx, long offset, TaskMonitor monitor) throws Exception {
		WasmElementSegment elemSegment = module.getElementSegments().get(elemidx);

		byte[] initBytes = elemSegment.getInitData(module);
		if (initBytes == null)
			return;

		program.getMemory().setBytes(getTableAddress(program.getAddressFactory(), tableidx, offset), initBytes);

		Address[] refs = elemSegment.getAddresses(program.getAddressFactory(), module);
		for (int i = 0; i < refs.length; i++) {
			if (refs[i] != null) {
				Address elementAddr = getTableAddress(program.getAddressFactory(), tableidx, offset + i);
				program.getReferenceManager().removeAllReferencesFrom(elementAddr);
				program.getReferenceManager().addMemoryReference(elementAddr, refs[i], RefType.DATA, SourceType.IMPORTED, 0);
			}
		}
	}

	private void loadElementSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active element segments into tables */
		monitor.setMessage("Loading table elements");
		List<WasmElementSegment> entries = module.getElementSegments();

		monitor.initialize(entries.size());
		for (int elemidx = 0; elemidx < entries.size(); elemidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmElementSegment elemSegment = entries.get(elemidx);
			int tableidx = (int) elemSegment.getTableIndex();

			Long offset = elemSegment.getOffset();
			if (offset == null)
				continue;

			try {
				loadElementsToTable(program, module, elemidx, tableidx, offset, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to initialize table " + tableidx + " with element segment " + elemidx + " at offset " + offset, e);
			}
		}
	}

	private void loadMemories(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) throws IOException {
		monitor.setMessage("Loading memories");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_MEMORY);
		List<WasmResizableLimits> memories = module.getNonImportedMemories();
		int numMemories = imports.size() + memories.size();

		monitor.initialize(numMemories);
		for (int memidx = 0; memidx < numMemories; memidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmResizableLimits mem;
			if (memidx < imports.size()) {
				mem = imports.get(memidx).getMemoryType();
			} else {
				mem = memories.get(memidx - imports.size());
			}
			/*
			 * B2: reject an invalid limits pair (initial > maximum, or a size beyond the index
			 * type's limit) before any block is created - see validateMemoryLimits.
			 */
			validateMemoryLimits(memidx, mem);
			/*
			 * @@MM: memory N is mapped into the dedicated `memory` address space at
			 * N * MEMORY_STRIDE (see getMemoryAddress). The `memory` space is 32-bit
			 * (size=4), so with MEMORY_STRIDE = 128 MiB, memory indices 0..31 are
			 * representable without colliding with the module image in `ram`.
			 *
			 * B2: a memory's materialised size is bounded by MAX_MEMORY_BLOCK_BYTES (128 MiB) so a
			 * tiny module can never force a multi-GiB block (which wedges auto-analysis). Memory 0
			 * used to keep a 2 GiB clamp of its own; the bound is now uniform across memories.
			 *
			 * @@M64: the size of a 64-bit memory is a u64, so it is computed with saturation and
			 * then clamped (and logged) like any other memory. The `memory` space is 32-bit, and
			 * the SLEIGH truncates effective addresses to 32 bits, so a memory larger than 4 GiB
			 * is only partly decoded.
			 *
			 * @@M64 >4 GiB: a memory64 declaration with an initial size above 4 GiB (e.g. 70000
			 * pages = 4,587,520,000 bytes) is *valid* per the memory64 proposal and is accepted
			 * here: the declared byte count is computed as a long (never overflowing), the block is
			 * capped at MAX_MEMORY_BLOCK_BYTES (128 MiB) and the mismatch is logged - so the import
			 * is honest and bounded instead of silently truncated or an OOM. The module's code
			 * section still decodes because nothing in the decode path depends on the memory's
			 * materialised size. The SLEIGH truncates effective addresses to 32 bits, so decoded
			 * accesses at or above 4 GiB wrap (see REPORT-N.md).
			 */
			long declared = memoryByteSize(mem.getInitial());
			long length = Math.min(declared, MAX_MEMORY_BLOCK_BYTES);
			if (length != declared) {
				Msg.warn(WasmLoader.class, "Memory " + memidx + (mem.is64Bit() ? " (i64 index)" : "")
						+ " declares " + (declared == Long.MAX_VALUE ? "an unrepresentably large" : "" + declared)
						+ " byte(s) but is mapped to " + length + " byte(s) (the loader's "
						+ MAX_MEMORY_BLOCK_BYTES + "-byte materialisation bound); accesses beyond the "
						+ "mapped size are not modelled (see REPORT-HARD.md)");
			} else if (mem.is64Bit()) {
				Msg.info(WasmLoader.class, "Memory " + memidx + " has a 64-bit (i64) index type; its "
						+ length + " byte(s) are mapped into the 64-bit `memory` space at 0x"
						+ Long.toHexString(((long) memidx) * MEMORY_STRIDE)
						+ " (the SLEIGH truncates effective addresses to 32 bits; see REPORT-N.md)");
			}
			createMemoryBlock(program, memidx, length, mem.is64Bit(), monitor);
		}
	}

	/**
	 * Copy data segment to memory.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * data segment once the dynamic memory index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadDataToMemory(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), dataidx, memidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadDataToMemory(Program program, WasmModule module, int dataidx, int memidx, long offset, TaskMonitor monitor) throws Exception {
		WasmDataSegment dataSegment = module.getDataSegments().get(dataidx);
		Address memStart = getMemoryAddress(program.getAddressFactory(), memidx, offset);
		program.getMemory().setBytes(memStart, dataSegment.getData());
	}

	private void loadDataSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active data segments into memory */
		monitor.setMessage("Loading data segments");
		List<WasmDataSegment> dataSegments = module.getDataSegments();

		monitor.initialize(dataSegments.size());
		for (int dataidx = 0; dataidx < dataSegments.size(); dataidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmDataSegment dataSegment = dataSegments.get(dataidx);
			int memidx = (int) dataSegment.getIndex();
			/* @@MM: active data segments for every memory (memory >= 1 included). */

			/*
			 * B2 (REPORT-N.md §7 item 8): getMemoryOffset() now reads an i64.const offset too, and
			 * resolveDataSegmentOffset() additionally resolves a global.get of a defined i64 global
			 * (memory64 data segments). An unresolved offset (an imported global, or an unparsed
			 * expression) still degrades to "segment skipped with a warning", never a crash.
			 */
			Long offset = resolveDataSegmentOffset(module, dataSegment);
			if (offset == null) {
				if (dataSegment.isActive()) {
					Msg.warn(this, "Skipping active data segment " + dataidx + " (memory " + memidx
							+ "): its offset expression could not be resolved statically"
							+ (dataSegment.hasUnknownOffset() ? " (it was not parsed)" : "")
							+ " (see REPORT-H1.md)");
				}
				continue;
			}

			try {
				loadDataToMemory(program, module, dataidx, memidx, offset, monitor);
			} catch (Exception e) {
				Address memStart = getMemoryAddress(program.getAddressFactory(), memidx, offset);
				Msg.error(this, "Failed to initialize memory " + memidx + " with data segment " + dataidx + " at " + memStart, e);
			}
		}
	}

	/**
	 * Resolve the static offset of an active data segment.
	 *
	 * <p>An {@code i32.const}/{@code i64.const} offset is returned directly. A {@code global.get}
	 * offset is resolved only when it refers to a defined (non-imported) i64 global whose
	 * initializer is itself a constant: that is the memory64 case (an active segment of a 64-bit
	 * memory must be offset by an i64 global). An imported global's value is not known until
	 * instantiation, so it - and a 32-bit {@code global.get} offset, whose placement was
	 * already dropped before this change - returns null (the caller skips the segment with a
	 * warning).
	 */
	private static Long resolveDataSegmentOffset(WasmModule module, WasmDataSegment dataSegment) {
		Long direct = dataSegment.getMemoryOffset();
		if (direct != null) {
			return direct;
		}
		Long globalidx = dataSegment.getOffsetGlobalIndex();
		if (globalidx == null) {
			return null;
		}
		int idx = (int) (long) globalidx;
		if (idx < 0) {
			return null;
		}
		List<WasmImportEntry> globalImports = module.getImports(WasmExternalKind.EXT_GLOBAL);
		WasmGlobalType globalType;
		byte[] initBytes;
		if (idx < globalImports.size()) {
			/* Imported global: its value is only known once the module is instantiated. */
			globalType = globalImports.get(idx).getGlobalType();
			initBytes = null;
		}
		else {
			List<WasmGlobalEntry> globals = module.getNonImportedGlobals();
			int local = idx - globalImports.size();
			if (local >= globals.size()) {
				return null;
			}
			globalType = globals.get(local).getGlobalType();
			initBytes = globals.get(local).asBytes(module);
		}
		if (globalType == null || globalType.getType() != ValType.i64) {
			/*
			 * Only an i64 global offsets a memory64 segment. Leaving a 32-bit global.get offset
			 * unresolved keeps 32-bit-memory placement byte-for-byte unchanged (it was dropped
			 * before this change too; see REPORT-H1.md).
			 */
			return null;
		}
		if (initBytes == null || initBytes.length < 8) {
			return null;
		}
		return littleEndianLong(initBytes);
	}

	private static long littleEndianLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < 8; i++) {
			value |= (bytes[i] & 0xFFL) << (8 * i);
		}
		return value;
	}

	private void loadGlobals(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading globals");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_GLOBAL);
		List<WasmGlobalEntry> globals = module.getNonImportedGlobals();
		int numGlobals = imports.size() + globals.size();

		monitor.initialize(numGlobals);
		for (int globalidx = 0; globalidx < numGlobals; globalidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmGlobalType globalType;
			byte[] initBytes;
			Address initRef;
			Long initGlobal;
			if (globalidx < imports.size()) {
				globalType = imports.get(globalidx).getGlobalType();
				initBytes = null;
				initRef = null;
				initGlobal = null;
			} else {
				WasmGlobalEntry entry = globals.get(globalidx - imports.size());
				globalType = entry.getGlobalType();
				initBytes = entry.asBytes(module);
				initRef = entry.asAddress(program.getAddressFactory(), module);
				initGlobal = entry.asGlobalGet();
			}

			createGlobalBlock(program, globalType.getType().asDataType(), initBytes, globalidx, globalType.getMutability(), monitor);

			Address dataStart = getGlobalAddress(program.getAddressFactory(), globalidx);
			Namespace namespace = getGlobalNamespace(program, module, globalidx);
			String name = getGlobalName(program, module, globalidx);
			try {
				createLabel(program, dataStart, name, namespace, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to label global " + globalidx + " (" + name + ") at " + dataStart, e);
			}

			if (initRef != null) {
				program.getReferenceManager().removeAllReferencesFrom(dataStart);
				program.getReferenceManager().addMemoryReference(dataStart, initRef, RefType.DATA, SourceType.IMPORTED, 0);
			}
			if (initGlobal != null) {
				CommentType commentType = CommentType.PLATE;
				String currentComment = program.getListing().getComment(commentType, dataStart);
				if (currentComment == null) {
					currentComment = "";
				} else if (!currentComment.isEmpty()) {
					currentComment += "\n";
				}
				Address otherAddress = getGlobalAddress(program.getAddressFactory(), (int) (long) initGlobal);
				program.getListing().setComment(dataStart, commentType, currentComment + "Initializer: {@symbol " + otherAddress + "}");
			}
		}
	}

	private MemoryBlock createCustomSectionBlock(Program program, FileBytes fileBytes, WasmUnknownCustomSection customSection, Address address)
			throws Exception {
		/*
		 * DWARF sections (.debug_info, .debug_abbrev, ...) must keep their exact
		 * names: Ghidra's DWARFSectionProviderFactory locates them by memory-block
		 * name, and the ".custom." prefix used for other sections (to avoid
		 * DataType name conflicts) makes them invisible, silently disabling all
		 * DWARF type/signature import.
		 */
		String blockName = customSection.getCustomName().startsWith(".debug_")
				? customSection.getCustomName()
				: customSection.getName();
		MemoryBlock block = program.getMemory().createInitializedBlock(blockName, address, fileBytes, customSection.getContentOffset(), customSection.getCustomSize(), false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
		block.setSourceName("Wasm Module");
		return block;
	}

	private void createCustomSections(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Creating custom sections");
		// start right after the module block
		Address address = AddressSpace.OTHER_SPACE.getAddress(fileBytes.getSize());
		for (WasmSection section : module.getCustomSections()) {
			if (!(section instanceof WasmUnknownCustomSection)) {
				continue;
			}
			WasmUnknownCustomSection customSection = (WasmUnknownCustomSection) section;
			try {
				if (customSection.getCustomSize() == 0) {
					continue;
				}
				monitor.setMessage("Creating custom section " + section.getName());
				MemoryBlock block = createCustomSectionBlock(program, fileBytes, customSection, address);
				address = address.add(block.getSize());
			} catch (Exception e) {
				Msg.error(this, "Failed to load Wasm Custom section " + customSection.getCustomName(), e);
			}
		}
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws IOException {
		settings.monitor().setMessage("Start loading");

		try {
			doLoad(settings.provider(), program, settings.monitor());
		} catch (OutOfMemoryError e) {
			/*
			 * B1/B2 defence in depth: the loader now bounds every allocation it drives (locals,
			 * memories, tables), so this should be unreachable - but if it is reached, an
			 * OutOfMemoryError must not escape to the headless process (it would abort the whole
			 * run, see J02). Convert it into an ordinary, reported import failure.
			 */
			settings.monitor().setMessage("Error");
			Msg.error(this, "Failed to load Wasm module (out of memory): " + e.getMessage(), e);
			throw new IOException("Failed to load Wasm module (out of memory): " + e.getMessage(), e);
		} catch (Exception e) {
			/*
			 * B3/NS09/NS11: do NOT swallow the failure. Previously the module block was already
			 * created by this point, so Ghidra reported the import as successful while everything
			 * after the failing section had been silently dropped (a malformed custom-section name
			 * produced `funcs=0` "success"). Rethrowing makes the load failure visible and honest.
			 */
			settings.monitor().setMessage("Error");
			Msg.error(this, "Failed to load Wasm module: " + e.getMessage(), e);
			throw new IOException("Failed to load Wasm module: " + e.getMessage(), e);
		}
	}

	/**
	 * B1: reject a module that declares more total locals than the loader will materialise.
	 *
	 * <p>The per-function limit is enforced while the code section is parsed
	 * ({@link WasmCodeEntry#MAX_FUNCTION_LOCALS}); this bounds the sum across functions, which a
	 * hostile module could otherwise pad with many small function bodies.
	 *
	 * @throws IOException when the module's total declared locals exceed
	 *         {@link WasmCodeEntry#MAX_MODULE_LOCALS}
	 */
	private static void validateLocalsBudget(WasmModule module) throws IOException {
		long total = 0;
		for (WasmCodeEntry entry : module.getNonImportedFunctions()) {
			total += entry.getDeclaredLocalCount();
			if (total < 0 || total > WasmCodeEntry.MAX_MODULE_LOCALS) {
				throw new IOException("Module declares more than " + WasmCodeEntry.MAX_MODULE_LOCALS
						+ " locals in total (the loader's module limit; see REPORT-HARD.md)");
			}
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		WasmModule module = new WasmModule(reader);

		validateLocalsBudget(module);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		MemoryBlock moduleBlock = createModuleBlock(program, fileBytes);
		createData(program, program.getListing(), moduleBlock.getStart(), module.getHeader().toDataType());

		for (WasmSection section : module.getSections()) {
			monitor.setMessage("Creating section " + section.getName());
			try {
				createData(program, program.getListing(), moduleBlock.getStart().add(section.getSectionOffset()), section.toDataType());
			} catch (Exception e) {
				/*
				 * B3: give the failure enough context to be actionable. The exception is rethrown
				 * so load() reports the import as failed instead of returning a truncated program.
				 */
				throw new IOException("Failed to create markup for section " + section.getName()
						+ " (id " + section.getId() + ") at file offset 0x"
						+ Long.toHexString(section.getSectionOffset()) + ": " + e.getMessage(), e);
			}
		}

		createCodeLengthData(program, moduleBlock, module);

		createCustomSections(program, fileBytes, module, monitor);

		loadFunctions(program, fileBytes, module, monitor);
		loadTables(program, fileBytes, module, monitor);
		loadElementSegments(program, fileBytes, module, monitor);
		loadMemories(program, fileBytes, module, monitor);
		loadDataSegments(program, fileBytes, module, monitor);
		loadGlobals(program, fileBytes, module, monitor);

		warnIfNothingLoaded(program, module);
	}

	/**
	 * B9: the loader deliberately accepts modules it does not validate, so a malformed module can
	 * import "successfully" while producing a program with nothing in it. Say so explicitly instead
	 * of returning a silently empty program - the negative-test harness' "accepted as bare bytes"
	 * class (see MODERN_WASM_GAPS.md 2.3 and 6.4). The module is still accepted.
	 */
	private void warnIfNothingLoaded(Program program, WasmModule module) {
		if (program.getFunctionManager().getFunctionCount() > 0) {
			return;
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			String name = block.getName();
			if (name.startsWith(".memory") || name.startsWith(".table") || name.startsWith(".global")) {
				return;
			}
		}
		boolean declaredContent = module.getFunctionCount() > 0
				|| !module.getNonImportedMemories().isEmpty()
				|| !module.getNonImportedTables().isEmpty()
				|| !module.getNonImportedGlobals().isEmpty();
		if (!declaredContent) {
			return; // header-only, custom-section-only or import-only modules are legitimate
		}
		int codeEntries = module.getNonImportedFunctions().size();
		StringBuilder detail = new StringBuilder("Declared: ")
				.append(module.getFunctionCount()).append(" function(s), ")
				.append(codeEntries).append(" code entries, ")
				.append(module.getNonImportedMemories().size()).append(" memory(ies), ")
				.append(module.getNonImportedTables().size()).append(" table(s), ")
				.append(module.getNonImportedGlobals().size()).append(" global(s).");
		if (module.getFunctionCount() > 0 && codeEntries == 0) {
			detail.append(" The module declares functions but has no usable code entries")
					.append(" (a function section without a matching code section?).");
		}
		Msg.warn(this, "Module accepted but nothing was decoded: the program contains only the raw"
				+ " module bytes. " + detail
				+ " The loader deliberately accepts spec-invalid modules (it is not a validator; B9 in"
				+ " MODERN_WASM_GAPS.md), so a malformed section can leave nothing to analyse - the"
				+ " section markup and any warnings above may show which part could not be used.");
	}
}
