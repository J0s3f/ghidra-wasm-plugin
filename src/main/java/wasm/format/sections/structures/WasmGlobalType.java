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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.LEB128;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmGlobalType implements StructConverter {

	private ValType type;
	private int mutability;

	public WasmGlobalType(BinaryReader reader) throws IOException {
		type = readValType(reader);
		mutability = reader.readNextUnsignedByte();
	}

	// @@GC: a value type is not always a single byte. The GC encodings (ref null ht) = 0x63 and
	// (ref ht) = 0x64 are followed by a heap type (s33); consuming it keeps the global's
	// initializer aligned. (A plain heap-type shorthand, e.g. anyref = 0x6e, is still one byte.)
	private static ValType readValType(BinaryReader reader) throws IOException {
		int typeByte = reader.readNextUnsignedByte();
		if (typeByte == 0x63 || typeByte == 0x64) {
			reader.readNext(LEB128::signed); /* heaptype (s33) */
		}
		return ValType.fromByte(typeByte);
	}

	public ValType getType() {
		return type;
	}

	public int getMutability() {
		return mutability;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("global_type");
		builder.add(BYTE, "type");
		builder.add(BYTE, "mutability");
		return builder.toStructure();
	}
}
