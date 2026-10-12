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
 * Label names subsection (id 3) of the WebAssembly .name section.
 * <p>
 * Label names use an indirect map structure identical to local names:
 * funcidx → (labelidx → name). Per the extended-name-section spec, "Labels
 * are indexed in the order they appear in the function body" — i.e. the
 * first block/loop/if/try encountered in a function is label 0, the second
 * is label 1, and so on.
 */
public class WasmNameLabelSubsection extends WasmNameSubsection {

	private WasmNameIndirectMap labelNameMap;

	public WasmNameLabelSubsection(BinaryReader reader) throws IOException {
		super(reader);
		labelNameMap = new WasmNameIndirectMap("namemap_func_labels_", reader);
	}

	public String getLabelName(int funcidx, int labelidx) {
		return labelNameMap.getEntry(funcidx, labelidx);
	}

	public Map<Long, String> getLabelNames(int funcidx) {
		return labelNameMap.getNameMapping(funcidx);
	}

	/** All label name maps: funcidx -> (labelidx -> name). */
	public Map<Long, Map<Long, String>> getLabelNameMap() {
		return labelNameMap.getMap();
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(labelNameMap, "label_names");
	}

	@Override
	public String getName() {
		return ".name.labels";
	}
}
