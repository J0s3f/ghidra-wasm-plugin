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
package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmNameFieldSubsection;
import wasm.format.sections.structures.WasmNameLabelSubsection;
import wasm.format.sections.structures.WasmNameLocalSubsection;
import wasm.format.sections.structures.WasmNameMapSubsection;
import wasm.format.sections.structures.WasmNameModuleSubsection;
import wasm.format.sections.structures.WasmNameSubsection;
import wasm.format.sections.structures.WasmNameSubsection.WasmNameSubsectionId;
import wasm.format.sections.structures.WasmNameUnknownSubsection;

public class WasmNameSection extends WasmCustomSection {
	private List<WasmNameSubsection> subsections = new ArrayList<>();
	private Map<WasmNameSubsectionId, WasmNameSubsection> subsectionMap = new EnumMap<>(WasmNameSubsectionId.class);

	public WasmNameSection(BinaryReader reader) throws IOException {
		super(reader);
		long sectionEnd = getSectionOffset() + getSectionSize();
		while (reader.getPointerIndex() < sectionEnd) {
			long before = reader.getPointerIndex();
			WasmNameSubsection subsection;
			try {
				subsection = WasmNameSubsection.createSubsection(reader);
			}
			catch (IOException | RuntimeException e) {
				/*
				 * @@NAME: a malformed subsection (bad id/size encoding) must not fail the
				 * import. Keep everything parsed so far and stop reading the section.
				 */
				break;
			}
			if (reader.getPointerIndex() <= before) {
				/* No forward progress: malformed size, avoid an infinite loop. */
				break;
			}
			if (subsection == null)
				continue;
			subsections.add(subsection);
			/*
			 * @@NAME: an unparseable known subsection is represented as
			 * WasmNameUnknownSubsection, but must not shadow the typed lookup for its id
			 * (the getters cast to the concrete subclass). Keep it in the listing only.
			 */
			if (subsection.getId() != null && !(subsection instanceof WasmNameUnknownSubsection))
				subsectionMap.put(subsection.getId(), subsection);
		}
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		super.addToStructure(builder);
		for (int i = 0; i < subsections.size(); i++) {
			builder.add(subsections.get(i), subsections.get(i).getName());
		}
	}

	public String getModuleName() {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_MODULE);
		if (subsection == null)
			return null;
		return ((WasmNameModuleSubsection) subsection).getModuleName();
	}

	public String getFunctionName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FUNCTION);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getLocalName(int funcidx, int localidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LOCAL);
		if (subsection == null)
			return null;
		return ((WasmNameLocalSubsection) subsection).getLocalName(funcidx, localidx);
	}

	public String getGlobalName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_GLOBAL);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getDataName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_DATA);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	/** @@NAME: extended-name-section subsection accessors (labels/fields/tags/types/...). */
	public String getLabelName(int funcidx, int labelidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LABELS);
		if (subsection == null)
			return null;
		return ((WasmNameLabelSubsection) subsection).getLabelName(funcidx, labelidx);
	}

	public Map<Long, String> getLabelNames(int funcidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LABELS);
		if (subsection == null)
			return null;
		return ((WasmNameLabelSubsection) subsection).getLabelNames(funcidx);
	}

	public String getFieldName(int typeidx, int fieldidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FIELD);
		if (subsection == null)
			return null;
		return ((WasmNameFieldSubsection) subsection).getFieldName(typeidx, fieldidx);
	}

	public Map<Long, String> getFieldNames(int typeidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FIELD);
		if (subsection == null)
			return null;
		return ((WasmNameFieldSubsection) subsection).getFieldNames(typeidx);
	}

	public String getTypeName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_TYPE);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getTableName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_TABLE);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getMemoryName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_MEMORY);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getElemName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_ELEM);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getTagName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_TAG);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	/** The raw name map behind one subsection id, or null. Used by the applier analyzer. */
	public Map<Long, String> getNameMap(WasmNameSubsectionId nameSubsectionId) {
		WasmNameSubsection subsection = subsectionMap.get(nameSubsectionId);
		if (subsection instanceof WasmNameMapSubsection) {
			return ((WasmNameMapSubsection) subsection).getMap();
		}
		return null;
	}

	/** The label name map (funcidx -> {labelidx -> name}) behind subsection 3, or null. */
	public WasmNameLabelSubsection getLabelSubsection() {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LABELS);
		return (subsection instanceof WasmNameLabelSubsection) ? (WasmNameLabelSubsection) subsection : null;
	}

	/** The field name map (typeidx -> {fieldidx -> name}) behind subsection 10, or null. */
	public WasmNameFieldSubsection getFieldSubsection() {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FIELD);
		return (subsection instanceof WasmNameFieldSubsection) ? (WasmNameFieldSubsection) subsection : null;
	}

	public Map<Long, String> getLocalNames(int funcidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LOCAL);
		if (subsection == null)
			return null;
		return ((WasmNameLocalSubsection) subsection).getLocalNames(funcidx);
	}

	public boolean hasNameSubSection(WasmNameSubsectionId nameSubsectionId) {
		return subsectionMap.containsKey(nameSubsectionId);
	}

	@Override
	public String getName() {
		return ".name";
	}
}
