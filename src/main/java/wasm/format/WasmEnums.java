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
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
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

	/**
	 * WebAssembly value types, including GC/reference types.
	 * 
	 * Single-byte types (MVP + reference-types):
	 *   0x7F i32, 0x7E i64, 0x7D f32, 0x7C f64, 0x7B v128,
	 *   0x70 funcref, 0x6F externref
	 * 
	 * Multi-byte types (function references / GC):
	 *   0x63 (ref null <heaptype>) - nullable reference
	 *   0x64 (ref <heaptype>)      - non-nullable reference
	 *   Heaptype is encoded as s33 (signed LEB128).
	 *   Abstract heap types (negative s33):
	 *     0x69 exnref, 0x6A array, 0x6B struct, 0x6C i31, 0x6D eq,
	 *     0x6E any, 0x6F extern, 0x70 func, 0x71 none, 0x72 noextern,
	 *     0x73 nofunc, 0x74 noexn
	 */
	public enum ValType {
		// Basic value types (MVP)
		i32(0x7f),
		i64(0x7e),
		f32(0x7d),
		f64(0x7c),
		v128(0x7b),

		// Reference types (reference-types proposal)
		funcref(0x70),
		externref(0x6f),

		// GC reference types (abstract heap types, encoded as negative s33)
		// These are represented as distinct ValType entries for easier handling.
		// exnref (0x69) is the new exception-handling type and is used by EH2Ops.java.
		// (The multi-byte forms 0x63/0x64 "(ref null ht)/(ref ht)" are consumed structurally by
		// WasmFuncType/WasmGlobalType.readFromReader; they are not separate enum constants.)
		exnref(0x69),
		arrayref(0x6a),
		structref(0x6b),
		i31ref(0x6c),
		eqref(0x6d),
		anyref(0x6e),

		// Bottom types
		none(0x71),
		noexternref(0x72),
		nofuncref(0x73),
		noexnref(0x74);

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
			case nofuncref:
				return PointerDataType.dataType;
			case externref:
			case exnref:
			case arrayref:
			case structref:
			case i31ref:
			case eqref:
			case anyref:
			case noexternref:
			case noexnref:
			case none:
				// All reference types are 4 bytes on wasm32 (pointer-sized)
				return Undefined4DataType.dataType;
			}
			return Undefined4DataType.dataType; // Should not reach, but safe fallback
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
			case exnref:
			case arrayref:
			case structref:
			case i31ref:
			case eqref:
			case anyref:
			case noexternref:
			case nofuncref:
			case noexnref:
			case none:
				return 4;
			case i64:
			case f64:
				return 8;
			case v128:
				return 16;
			}
			return 4;
		}

		public static ValType fromByte(int b) {
			ValType t = BY_BYTE.get(b);
			if (t != null) {
				return t;
			}
			// Unknown byte - return a placeholder that won't crash
			return i32; // Default to i32 (4 bytes) for unknown
		}

		/**
		 * Read a value type from a BinaryReader, handling multi-byte encodings.
		 * Returns a ValType and consumes the appropriate number of bytes.
		 * For multi-byte types (0x63, 0x64), consumes the s33 heaptype operand.
		 * Never returns null.
		 */
		public static ValType readFromReader(BinaryReader reader) throws IOException {
			int b = reader.readNextUnsignedByte();
			
			// Check for multi-byte reference types
			if (b == 0x63 || b == 0x64) {
				// (ref null <heaptype>) or (ref <heaptype>)
				// Consume the s33 heaptype operand
				reader.readNext(LEB128Info::signed);
				// Return a placeholder ValType based on the heaptype if known
				// For now, return externref as a 4-byte placeholder
				return externref;
			}
			
			return fromByte(b);
		}

		public static ValType[] fromBytes(byte[] types) {
			ValType[] res = new ValType[types.length];
			for (int i = 0; i < types.length; i++) {
				res[i] = fromByte(types[i]);
			}
			return res;
		}
		
		/** Returns true if this is a reference type (4 bytes on wasm32). */
		public boolean isReferenceType() {
			return this == funcref || this == externref || this == exnref || 
			       this == arrayref || this == structref || this == i31ref ||
			       this == eqref || this == anyref || this == noexternref ||
			       this == nofuncref || this == noexnref || this == none;
		}
		
		/** Returns true if this is a multi-byte valtype (ref null/ref with heaptype). */
		public static boolean isMultiBytePrefix(int b) {
			return b == 0x63 || b == 0x64;
		}
	}
}
