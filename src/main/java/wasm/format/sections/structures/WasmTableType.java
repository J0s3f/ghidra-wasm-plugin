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
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmTableType implements StructConverter {

	private ValType elemType;
	private ValType.TypeInfo elemTypeInfo;
	private WasmResizableLimits limits;
	private ConstantExpression initializer;

	public WasmTableType(BinaryReader reader) throws IOException {
		this(reader, false);
	}

	public WasmTableType(BinaryReader reader, boolean definition) throws IOException {
		boolean hasInitializer = definition && reader.peekNextByte() == 0x40;
		if (hasInitializer) {
			reader.readNextByte();
			if (reader.readNextUnsignedByte() != 0) { throw new IOException("Invalid table initializer prefix"); }
		}
		elemTypeInfo = ValType.readTypeInfo(reader);
		elemType = elemTypeInfo.type;
		limits = new WasmResizableLimits(reader);
		if (hasInitializer) { initializer = new ConstantExpression(reader); }
	}

	public ConstantExpression getInitializer() { return initializer; }
	public void resolveReferenceTypes(java.util.function.LongFunction<ValType> resolver) {
		elemType = elemTypeInfo.resolve(resolver);
	}

	public ValType getElementType() {
		return elemType;
	}

	public DataType getElementDataType() {
		return elemType.asDataType();
	}

	public WasmResizableLimits getLimits() {
		return limits;
	}

	/**
	 * @@T64: table64. The memory64 proposal reuses the memory limits encoding for tables, so bit 2
	 * (0x04) of the limits flags marks a 64-bit *table* index type ({@code (table i64 N funcref)}).
	 * The flag is decoded by {@link WasmResizableLimits} (it never desyncs the table section - the
	 * initial size is still a plain LEB128 that follows the flags byte); this accessor records it so
	 * the loader can report the table honestly.
	 */
	public boolean is64Bit() {
		return limits.is64Bit();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("table_type");
		if (initializer != null) { builder.addArray(BYTE, 2, "initializer_prefix"); }
		builder.addArray(BYTE, elemTypeInfo.encodedLength, "element_type");
		builder.add(limits, "limits");
		if (initializer != null) { builder.add(initializer, "initializer"); }
		return builder.toStructure();
	}
}
