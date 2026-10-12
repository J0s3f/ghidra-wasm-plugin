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

import java.util.HashMap;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;

public class WasmEnums {
	public enum WasmExternalKind {
		EXT_FUNCTION,
		EXT_TABLE,
		EXT_MEMORY,
		EXT_GLOBAL,
		EXT_TAG		// exception handling: import/export kind 4
	}

	public enum ValType {
		i32(0x7f),
		i64(0x7e),
		f32(0x7d),
		f64(0x7c),
		v128(0x7b),

		funcref(0x70),
		externref(0x6f),

		// @@GC ---------------------------------------------------------------------
		// WebAssembly GC / function-references value types (proposal: garbage
		// collection). The single-byte abstract heap types can appear directly as a
		// value type; refnull/ref are markers for the multi-byte (ref null ht)/(ref ht)
		// encodings, which are parsed structurally by WasmGCType/ConstantExpression.
		// All of these are modelled as 32-bit opaque reference values.
		exnref(0x69),
		arrayref(0x6a),
		structref(0x6b),
		i31ref(0x6c),
		eqref(0x6d),
		anyref(0x6e),
		nullref(0x71),
		nullexternref(0x72),
		nullfuncref(0x73),
		nullexnref(0x74),
		refnull(0x63),
		ref(0x64);
		// @@GC ---------------------------------------------------------------------

		private static final HashMap<Integer, ValType> BY_BYTE = new HashMap<>();
		public static final DataType Undefined16 = Undefined.getUndefinedDataType(16);
		public final int typeByte;

		static {
			for (ValType t : ValType.values()) {
				BY_BYTE.put(t.typeByte, t);
			}
		}

		private ValType(int v) {
			this.typeByte = v;
		}

		public DataType asDataType() {
			switch (this) {
			case i32:
				return Undefined4DataType.dataType;
			case i64:
				return Undefined8DataType.dataType;
			case f32:
				return FloatDataType.dataType;
			case f64:
				return DoubleDataType.dataType;
			case v128:
				return Undefined16;
			case funcref:
				return PointerDataType.dataType;
			case externref:
				return Undefined4DataType.dataType;
			// @@GC: GC / function-references value types are opaque 4-byte references.
			case exnref:
			case arrayref:
			case structref:
			case i31ref:
			case eqref:
			case anyref:
			case nullref:
			case nullexternref:
			case nullfuncref:
			case nullexnref:
			case refnull:
			case ref:
				return Undefined4DataType.dataType;
			}
			// @@GC ---------------------------------------------------------------------
			return null;
		}

		/**
		 * Data type to use for a *function signature* slot (parameter or return
		 * value). Unlike {@link #asDataType}, integer types resolve to concrete
		 * signed C integers rather than Undefined, so signatures read as
		 * "int foo(int)" instead of "undefined4 foo(undefined4)". The
		 * decompiler still refines signedness/pointerness from use. Width is
		 * identical to asDataType, so stack layout is unaffected.
		 */
		public DataType asSignatureDataType() {
			switch (this) {
			case i32:
				return IntegerDataType.dataType;
			case i64:
				return LongLongDataType.dataType;
			default:
				return asDataType();
			}
		}

		public int getSize() {
			switch (this) {
			case i32:
			case f32:
			case funcref:
			case externref:
				return 4;
			// @@GC: GC / function-references value types are 4-byte references.
			case exnref:
			case arrayref:
			case structref:
			case i31ref:
			case eqref:
			case anyref:
			case nullref:
			case nullexternref:
			case nullfuncref:
			case nullexnref:
			case refnull:
			case ref:
				return 4;
			// @@GC ---------------------------------------------------------------------
			case i64:
			case f64:
				return 8;
			case v128:
				return 16;
			}
			return 4;
		}

		public static ValType fromByte(int b) {
			return BY_BYTE.get(b);
		}

		public static ValType[] fromBytes(byte[] types) {
			ValType[] res = new ValType[types.length];
			for (int i = 0; i < types.length; i++) {
				res[i] = fromByte(types[i]);
			}
			return res;
		}
	}
}
