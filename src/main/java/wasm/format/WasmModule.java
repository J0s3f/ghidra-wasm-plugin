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
package wasm.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.structures.WasmGCType;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmCustomSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmElementSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmGlobalSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmLinearMemorySection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmTagSection;
import wasm.format.sections.WasmStartSection;
import wasm.format.sections.WasmTableSection;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmCodeEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmModule {

	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<>();
	private List<WasmCustomSection> customSections = new ArrayList<>();
	private Map<WasmSectionId, WasmSection> sectionMap = new EnumMap<>(WasmSectionId.class);

	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		int lastRank = -1;
		WasmSectionId lastOrdered = null;
		/*
		 * B4: every non-custom section may appear at most once. The check uses the raw section id
		 * rather than the parsed WasmSection, because a known-but-unmodelled id (SEC_DATACOUNT)
		 * does not produce a section object and would otherwise escape the check.
		 */
		Set<Integer> seenNonCustom = new HashSet<>();
		while (reader.getPointerIndex() < reader.length()) {
			long sectionStart = reader.getPointerIndex();
			int rawId = reader.readNextUnsignedByte();
			reader.setPointerIndex(sectionStart);

			WasmSection section = WasmSection.createSection(reader);
			if (rawId != 0 && !seenNonCustom.add(rawId)) {
				String name = rawId < WasmSectionId.values().length
						? WasmSectionId.values()[rawId].toString()
						: "id " + rawId;
				throw new IOException("Duplicate section " + name + " (id " + rawId
						+ ") at file offset 0x" + Long.toHexString(sectionStart)
						+ ": a non-custom section may appear at most once");
			}
			if (section == null) {
				/*
				 * Only a known-but-unmodelled section id returns null (today: SEC_DATACOUNT, id 12 -
				 * the loader does not need its content, so skipping it is deliberate). An id outside
				 * the enum throws in WasmSection.createSection() instead of being skipped silently.
				 */
				continue;
			}
			sections.add(section);

			/* Except for custom sections, all other sections may appear at most once. */
			if (section.getId() == WasmSectionId.SEC_CUSTOM) {
				customSections.add((WasmCustomSection) section);
				continue;
			}
			sectionMap.put(section.getId(), section);

			/*
			 * The core spec requires the non-custom sections in a canonical order, but this loader
			 * is deliberately lenient for real-world modules: an odd order (and an omitted section)
			 * is tolerated with a warning at most, never a rejection (see REPORT-H1.md).
			 */
			int rank = canonicalRank(section.getId());
			if (rank < lastRank) {
				Msg.warn(WasmModule.class, "Section " + section.getId() + " (id "
						+ section.getId().ordinal() + ") at file offset 0x"
						+ Long.toHexString(section.getSectionOffset())
						+ " is out of the canonical section order (it follows " + lastOrdered
						+ "); tolerated by this loader (see REPORT-H1.md)");
			}
			lastRank = Math.max(lastRank, rank);
			lastOrdered = section.getId();
		}
		resolveReferenceTypes();
	}

	/** Resolve concrete references to their abstract family, keeping external and internal
	 * references distinct without pretending to implement full nominal type validation. */
	public ValType resolveHeapType(long heapType) {
		if (heapType < 0) { return ValType.forHeapType(heapType); }
		if (heapType > Integer.MAX_VALUE) { throw new IllegalArgumentException("Invalid heap type index " + heapType); }
		WasmFuncType type = getType((int) heapType);
		if (!(type instanceof WasmGCType)) { return ValType.funcref; }
		switch (((WasmGCType) type).getKind()) {
		case STRUCT: return ValType.structref;
		case ARRAY: return ValType.arrayref;
		case CONT: return ValType.contref;
		default: return ValType.funcref;
		}
	}

	private void resolveReferenceTypes() throws IOException {
		try {
			WasmTypeSection types = getTypeSection();
			if (types != null) {
				for (int i = 0; i < types.getNumTypes(); i++) { types.getType(i).resolveReferenceTypes(this::resolveHeapType); }
			}
			for (WasmImportEntry entry : getImports(WasmExternalKind.EXT_GLOBAL)) { entry.getGlobalType().resolveReferenceTypes(this::resolveHeapType); }
			for (WasmImportEntry entry : getImports(WasmExternalKind.EXT_TABLE)) { entry.getTableType().resolveReferenceTypes(this::resolveHeapType); }
			for (WasmGlobalEntry entry : getNonImportedGlobals()) { entry.getGlobalType().resolveReferenceTypes(this::resolveHeapType); }
			for (WasmTableType table : getNonImportedTables()) { table.resolveReferenceTypes(this::resolveHeapType); }
			for (WasmCodeEntry function : getNonImportedFunctions()) { function.resolveReferenceTypes(this::resolveHeapType); }
		} catch (IndexOutOfBoundsException | IllegalArgumentException e) {
			throw new IOException("Invalid concrete reference type", e);
		}
	}

	/**
	 * Canonical file position of a non-custom section (core spec order; the exception-handling tag
	 * section sits between the memory and global sections). Used only to warn about a tolerated
	 * ordering oddity, never to reject a module.
	 */
	private static int canonicalRank(WasmSectionId id) {
		switch (id) {
			case SEC_TYPE: return 0;
			case SEC_IMPORT: return 1;
			case SEC_FUNCTION: return 2;
			case SEC_TABLE: return 3;
			case SEC_LINEARMEMORY: return 4;
			case SEC_TAG: return 5;
			case SEC_GLOBAL: return 6;
			case SEC_EXPORT: return 7;
			case SEC_START: return 8;
			case SEC_ELEMENT: return 9;
			case SEC_DATACOUNT: return 10;
			case SEC_CODE: return 11;
			case SEC_DATA: return 12;
			default: return -1;
		}
	}

	public WasmHeader getHeader() {
		return header;
	}

	public List<WasmSection> getSections() {
		return sections;
	}

	public WasmSection getSection(WasmSectionId sectionId) {
		return sectionMap.get(sectionId);
	}

	// #region Sections which do not represent vectors of entries
	public List<WasmCustomSection> getCustomSections() {
		return Collections.unmodifiableList(customSections);
	}

	public WasmNameSection getNameSection() {
		for (WasmCustomSection section : customSections) {
			if (section instanceof WasmNameSection) {
				return (WasmNameSection) section;
			}
		}
		return null;
	}

	public WasmStartSection getStartSection() {
		return (WasmStartSection) sectionMap.get(WasmSectionId.SEC_START);
	}
	// #endregion

	// #region Sections which represent vectors of entries
	private WasmTypeSection getTypeSection() {
		return (WasmTypeSection) sectionMap.get(WasmSectionId.SEC_TYPE);
	}

	private WasmImportSection getImportSection() {
		return (WasmImportSection) sectionMap.get(WasmSectionId.SEC_IMPORT);
	}

	private WasmFunctionSection getFunctionSection() {
		return (WasmFunctionSection) sectionMap.get(WasmSectionId.SEC_FUNCTION);
	}

	private WasmTableSection getTableSection() {
		return (WasmTableSection) sectionMap.get(WasmSectionId.SEC_TABLE);
	}

	private WasmLinearMemorySection getLinearMemorySection() {
		return (WasmLinearMemorySection) sectionMap.get(WasmSectionId.SEC_LINEARMEMORY);
	}

	private WasmGlobalSection getGlobalSection() {
		return (WasmGlobalSection) sectionMap.get(WasmSectionId.SEC_GLOBAL);
	}

	private WasmExportSection getExportSection() {
		return (WasmExportSection) sectionMap.get(WasmSectionId.SEC_EXPORT);
	}

	private WasmElementSection getElementSection() {
		return (WasmElementSection) sectionMap.get(WasmSectionId.SEC_ELEMENT);
	}

	private WasmCodeSection getCodeSection() {
		return (WasmCodeSection) sectionMap.get(WasmSectionId.SEC_CODE);
	}

	private WasmDataSection getDataSection() {
		return (WasmDataSection) sectionMap.get(WasmSectionId.SEC_DATA);
	}

	public WasmFuncType getType(int typeidx) {
		WasmTypeSection typeSection = getTypeSection();
		if (typeSection == null) {
			throw new IndexOutOfBoundsException(typeidx);
		}
		return typeSection.getType(typeidx);
	}

	public List<WasmImportEntry> getImports(WasmExternalKind kind) {
		WasmImportSection importSection = getImportSection();
		if (importSection == null) {
			return Collections.emptyList();
		}
		return importSection.getImports(kind);
	}

	public List<WasmTableType> getNonImportedTables() {
		WasmTableSection tableSection = getTableSection();
		if (tableSection == null) {
			return Collections.emptyList();
		}
		return tableSection.getTables();
	}

	public List<WasmResizableLimits> getNonImportedMemories() {
		WasmLinearMemorySection memorySection = getLinearMemorySection();
		if (memorySection == null) {
			return Collections.emptyList();
		}
		return memorySection.getMemories();
	}

	public List<WasmGlobalEntry> getNonImportedGlobals() {
		WasmGlobalSection globalSection = getGlobalSection();
		if (globalSection == null) {
			return Collections.emptyList();
		}
		return globalSection.getEntries();
	}

	public List<WasmExportEntry> getExports(WasmExternalKind kind) {
		WasmExportSection exportSection = getExportSection();
		if (exportSection == null) {
			return Collections.emptyList();
		}
		return exportSection.getExports(kind);
	}

	public List<WasmElementSegment> getElementSegments() {
		WasmElementSection elementSection = getElementSection();
		if (elementSection == null) {
			return Collections.emptyList();
		}
		return elementSection.getSegments();
	}

	public List<WasmCodeEntry> getNonImportedFunctions() {
		WasmCodeSection codeSection = getCodeSection();
		if (codeSection == null) {
			return Collections.emptyList();
		}
		return codeSection.getFunctions();
	}

	public List<WasmDataSegment> getDataSegments() {
		WasmDataSection dataSection = getDataSection();
		if (dataSection == null) {
			return Collections.emptyList();
		}
		return dataSection.getSegments();
	}
	// #endregion

	// #region Convenience functions
	public int getFunctionCount() {
		int numFunctions = getImports(WasmExternalKind.EXT_FUNCTION).size();
		WasmFunctionSection functionSection = getFunctionSection();
		if (functionSection != null) {
			numFunctions += functionSection.getTypeCount();
		}
		return numFunctions;
	}

	public WasmFuncType getFunctionType(int funcidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return getType(imports.get(funcidx).getFunctionType());
		}
		return getType(getFunctionSection().getTypeIdx(funcidx - imports.size()));
	}

	public WasmCodeEntry getFunctionCode(int funcidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return null;
		} else {
			return getNonImportedFunctions().get(funcidx - imports.size());
		}
	}

	/** The function type of exception tag `tagidx` (imported tags first, then the tag section), or null. */
	public WasmFuncType getTagType(int tagidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_TAG);
		if (tagidx < imports.size()) {
			return getType(imports.get(tagidx).getTagType());
		}
		WasmTagSection tagSection = (WasmTagSection) sectionMap.get(WasmSectionId.SEC_TAG);
		int local = tagidx - imports.size();
		if (tagSection == null || local >= tagSection.getTagCount()) {
			return null;
		}
		return getType(tagSection.getTypeIdx(local));
	}

	public WasmGlobalType getGlobalType(int globalidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_GLOBAL);
		if (globalidx < imports.size()) {
			return imports.get(globalidx).getGlobalType();
		}
		return getNonImportedGlobals().get(globalidx - imports.size()).getGlobalType();
	}

	public WasmTableType getTableType(int tableidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_TABLE);
		if (tableidx < imports.size()) {
			return imports.get(tableidx).getTableType();
		}
		return getNonImportedTables().get(tableidx - imports.size());
	}

	public WasmExportEntry findExport(WasmExternalKind kind, int idx) {
		WasmExportSection exportSection = getExportSection();
		if (exportSection == null) {
			return null;
		}
		return exportSection.findEntry(kind, idx);
	}
	// #endregion
}
