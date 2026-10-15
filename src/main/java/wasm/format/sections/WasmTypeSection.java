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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmGCType;

public class WasmTypeSection extends WasmSection {

	private LEB128Info count;
	private List<WasmFuncType> types = new ArrayList<WasmFuncType>();
	private final List<Integer> groupStarts = new ArrayList<>();
	private final List<Integer> groupSizes = new ArrayList<>();

	public WasmTypeSection(BinaryReader reader) throws IOException {
		super(reader);
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); ++i) {
			// @@GC: a type entry is a rec group (0x4E), a subtype (0x50/0x4F), a plain
			// function type (0x60), a GC composite type (0x5F struct / 0x5E array) or a
			// continuation type (0x5D cont, stack-switching). A 0x60 entry still goes through
			// WasmFuncType exactly as before; anything else is parsed structurally by WasmGCType
			// (one list entry per type index).
			long pos = reader.getPointerIndex();
			int form = reader.readNextUnsignedByte();
			reader.setPointerIndex(pos);
			int groupStart = types.size();
			if (form == 0x60) {
				types.add(new WasmFuncType(reader));
			} else {
				types.addAll(WasmGCType.parseTypeEntry(reader));
			}
			int groupSize = types.size() - groupStart;
			for (int member = 0; member < groupSize; member++) { groupStarts.add(groupStart); groupSizes.add(groupSize); }
		}
		resolveContinuationTypes();
	}

	/**
	 * @@GC/@@SS: bind each `cont` composite type (0x5D) to the function type it references. The
	 * reference may be a forward reference, so this can only run once the whole type section is
	 * parsed. A missing or out-of-range index is left unresolved: the continuation type then
	 * reports an empty parameter/return tuple rather than crashing the loader.
	 */
	private void resolveContinuationTypes() {
		for (WasmFuncType type : types) {
			if (type instanceof WasmGCType) {
				WasmGCType gcType = (WasmGCType) type;
				if (gcType.getKind() == WasmGCType.Kind.CONT) {
					long idx = gcType.getContTypeIndex();
					if (idx >= 0 && idx < types.size()) {
						WasmFuncType referenced = types.get((int) idx);
						if (!(referenced instanceof WasmGCType) || ((WasmGCType) referenced).getKind() == WasmGCType.Kind.FUNC) {
							gcType.resolveContType(referenced);
						}
					}
				}
			}
		}
	}

	public WasmFuncType getType(int typeidx) {
		return types.get(typeidx);
	}

	public int getNumTypes() {
		return types.size();
	}
	public int getGroupStart(int index) { return groupStarts.get(index); }
	public int getGroupSize(int index) { return groupSizes.get(index); }

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < types.size(); i++) {
			builder.add(types.get(i), "type_" + i);
		}
	}

	@Override
	public String getName() {
		return ".type";
	}
}
