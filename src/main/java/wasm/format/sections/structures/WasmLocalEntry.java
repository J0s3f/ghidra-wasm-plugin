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
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmLocalEntry implements StructConverter {

	private LEB128Info count;
	private ValType type;
	private ValType.TypeInfo typeInfo;

	public WasmLocalEntry(BinaryReader reader) throws IOException {
		count = reader.readNext(LEB128Info::unsigned);
		typeInfo = ValType.readTypeInfo(reader);
		type = typeInfo.type;
	}

	public int getCount() {
		return (int) count.asLong();
	}

	/**
	 * The declared count as an unsigned value, without the lossy narrowing to {@code int}.
	 *
	 * <p>Malformed input can declare a count that does not fit (or wraps) a Java {@code int}
	 * (e.g. {@code 0xFFFFFFFF}); every caller that is about to size an allocation must use this
	 * method and validate the value first (see {@code WasmCodeEntry}).
	 *
	 * @return the declared local count, exactly as read from the LEB128
	 */
	public long getCountLong() {
		return count.asLong();
	}

	public ValType getType() {
		return type;
	}
	public void resolveReferenceTypes(java.util.function.LongFunction<ValType> resolver) {
		type = typeInfo.resolve(resolver);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("locals_" + count.asLong() + "_" + type.typeByte);
		builder.addUnsignedLeb128(count, "count");
		builder.addArray(BYTE, typeInfo.encodedLength, "type");
		return builder.toStructure();
	}
}
