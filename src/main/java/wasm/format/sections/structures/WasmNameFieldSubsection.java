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
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

/**
 * Field names subsection (id 10) of the WebAssembly .name section.
 * <p>
 * Field names use an indirect map structure identical to local names:
 * typeidx → (fieldidx → name). They apply to struct type definitions
 * (GC / component-model proposals), naming individual fields within a struct.
 */
public class WasmNameFieldSubsection extends WasmNameSubsection {

	private WasmNameIndirectMap fieldNameMap;

	public WasmNameFieldSubsection(BinaryReader reader) throws IOException {
		super(reader);
		fieldNameMap = new WasmNameIndirectMap("namemap_type_fields_", reader);
	}

	public String getFieldName(int typeidx, int fieldidx) {
		return fieldNameMap.getEntry(typeidx, fieldidx);
	}

	public Map<Long, String> getFieldNames(int typeidx) {
		return fieldNameMap.getNameMapping(typeidx);
	}

	/** All field name maps: typeidx -> (fieldidx -> name). */
	public Map<Long, Map<Long, String>> getFieldNameMap() {
		return fieldNameMap.getMap();
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(fieldNameMap, "field_names");
	}

	@Override
	public String getName() {
		return ".name.fields";
	}
}
