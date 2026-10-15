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
import wasm.format.WasmParsing;
import wasm.format.WasmEnums.ValType;

public class WasmFuncType implements StructConverter {

	@SuppressWarnings("unused")
	private int form; /* always 0x60 in this version */
	private LEB128Info paramCount;
	private ValType[] paramTypes;
	private LEB128Info returnCount;
	private ValType[] returnTypes;
	private int paramEncodingLength;
	private int returnEncodingLength;
	private ValType.TypeInfo[] paramTypeInfo;
	private ValType.TypeInfo[] returnTypeInfo;

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextUnsignedByte();
		if (form != 0x60) { throw new IOException("Invalid function type form " + form); }
		paramCount = reader.readNext(LEB128Info::unsigned);
		int pcount = WasmParsing.checkedCount(reader, paramCount.asLong(), 1, "parameter");
		paramTypes = new ValType[pcount];
		paramTypeInfo = new ValType.TypeInfo[pcount];
		long paramStart = reader.getPointerIndex();
		for (int i = 0; i < pcount; i++) {
			paramTypeInfo[i] = ValType.readTypeInfo(reader);
			paramTypes[i] = paramTypeInfo[i].type;
		}
		paramEncodingLength = (int) (reader.getPointerIndex() - paramStart);
		returnCount = reader.readNext(LEB128Info::unsigned);
		int rcount = WasmParsing.checkedCount(reader, returnCount.asLong(), 1, "result");
		returnTypes = new ValType[rcount];
		returnTypeInfo = new ValType.TypeInfo[rcount];
		long returnStart = reader.getPointerIndex();
		for (int i = 0; i < rcount; i++) {
			returnTypeInfo[i] = ValType.readTypeInfo(reader);
			returnTypes[i] = returnTypeInfo[i].type;
		}
		returnEncodingLength = (int) (reader.getPointerIndex() - returnStart);
	}

	// @@GC: used by WasmGCType (a structural GC type entry) so that GC composite
	// types can live in WasmTypeSection's WasmFuncType list without changing its
	// public contract. WasmGCType overrides getParamTypes/getReturnTypes/toString/
	// toDataType, so the fields below are never touched for a GC entry.
	protected WasmFuncType() {
	}

	public ValType[] getParamTypes() {
		return paramTypes;
	}

	public void resolveReferenceTypes(java.util.function.LongFunction<ValType> resolver) {
		for (int i = 0; i < paramTypes.length; i++) { paramTypes[i] = paramTypeInfo[i].resolve(resolver); }
		for (int i = 0; i < returnTypes.length; i++) { returnTypes[i] = returnTypeInfo[i].resolve(resolver); }
	}

	public ValType[] getReturnTypes() {
		return returnTypes;
	}

	private static String typeTupleToString(ValType[] types) {
		StringBuilder result = new StringBuilder();
		result.append("(");
		for (int i = 0; i < types.length; i++) {
			if (i != 0) {
				result.append(",");
			}
			result.append(types[i]);
		}
		result.append(")");
		return result.toString();
	}

	@Override
	public String toString() {
		return typeTupleToString(paramTypes) + "->" + typeTupleToString(returnTypes);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("func_type_" + paramCount.asLong() + "_" + returnCount.asLong());
		builder.add(BYTE, "form");
		builder.addUnsignedLeb128(paramCount, "param_count");
		builder.addArray(BYTE, paramEncodingLength, "param_types");
		builder.addUnsignedLeb128(returnCount, "return_count");
		builder.addArray(BYTE, returnEncodingLength, "return_types");
		return builder.toStructure();
	}
}
