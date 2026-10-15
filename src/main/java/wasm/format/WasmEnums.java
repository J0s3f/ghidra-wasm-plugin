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
		noexnref(0x74),

		// @@SS/@@STR: placeholder reference types for the stack-switching (JSPI) and
		// stringref proposals. The plugin models their *stack effect* (a 4-byte opaque
		// reference on wasm32, exactly like the other reference types) but does not
		// implement their semantics; the decompiler shows the operation via a callother.
		//
		// The byte values are internal placeholders, not a claim about the proposals'
		// binary encodings: the type-section reader never produces them (0x63/0x64 stay
		// the GC "(ref null ht)/(ref ht)" prefixes, and the stringref draft's 0x64
		// spelling collides with that prefix, so 0x67 is used here instead). 0x68 is the
		// abstract `cont` heap type; 0x67 is otherwise unused by this reader.
		contref(0x68),   // (ref null $ct): continuation reference (stack switching)
		stringref(0x67); // stringref / stringview_*: JS string builtins reference

		private static final HashMap<Integer, ValType> BY_BYTE = new HashMap<>();
		public static final DataType Undefined16 = Undefined.getUndefinedDataType(16);
		public final int typeByte;

		/**
		 * Provisional value for readers without a module type graph. Persisted TypeInfo
		 * records retain the heap index; WasmModule resolves it to func/struct/array/cont
		 * after parsing, before signatures or stack analysis use the value.
		 */
		public static final ValType GENERIC_REF = externref;

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
			case contref:
			case stringref:
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
			case contref:
			case stringref:
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
		 * Map an s33 heap type to the ValType this plugin uses for it.
		 *
		 * <p>Abstract heap types are encoded as the single bytes 0x69..0x74, i.e. the
		 * negative s33 values -0x17 (exn) .. -0x0c (noexn): func -0x10, extern -0x11,
		 * any -0x12, eq -0x13, i31 -0x14, struct -0x15, array -0x16, exn -0x17,
		 * none -0x0f, noextern -0x0e, nofunc -0x0d, noexn -0x0c. The byte table is reused so
		 * the mapping is byte-identical to the (ref ht) valtype encoding.
		 *
		 * <p>A non-negative heap type is a concrete type index whose referenced type is not
		 * modelled; every such reference maps to {@link #GENERIC_REF}.
		 */
		public static ValType forHeapType(long heaptype) {
			if (heaptype >= 0) {
				return GENERIC_REF;
			}
			ValType t = BY_BYTE.get((int) heaptype + 0x80);
			return (t != null && t.isReferenceType()) ? t : GENERIC_REF;
		}

		/**
		 * Read a value type from a BinaryReader, handling multi-byte encodings.
		 * Returns a ValType and consumes the appropriate number of bytes.
		 * For multi-byte types (0x63, 0x64), consumes the s33 heaptype operand and maps it
		 * to the matching abstract heap type (e.g. (ref null struct) -&gt; structref); a
		 * concrete type index maps to {@link #GENERIC_REF}.
		 * Never returns null.
		 */
		public static ValType readFromReader(BinaryReader reader) throws IOException {
			return readTypeInfo(reader).type;
		}

		/** Preserve a concrete heap index until the complete module type graph is available. */
		public static final class TypeInfo {
			public final ValType type;
			public final Long heapType;
			public final int encodedLength;
			public final boolean nullable;
			private TypeInfo(ValType type, Long heapType, int encodedLength, boolean nullable) {
				this.type = type; this.heapType = heapType; this.encodedLength = encodedLength; this.nullable = nullable;
			}
			public static TypeInfo reference(long heap, boolean nullable) { return new TypeInfo(forHeapType(heap), heap, 0, nullable); }
			public static TypeInfo value(ValType type) { return new TypeInfo(type, null, 0, type.ordinal() >= funcref.ordinal()); }
			public ValType resolve(java.util.function.LongFunction<ValType> resolver) {
				return heapType == null ? type : resolver.apply(heapType);
			}
		}

		public static TypeInfo readTypeInfo(BinaryReader reader) throws IOException {
			long start = reader.getPointerIndex();
			int b = reader.readNextUnsignedByte();
			Long heap = b == 0x63 || b == 0x64 ? reader.readNext(LEB128Info::signed).asLong() : null;
			if (heap == null && !BY_BYTE.containsKey(b)) {
				throw new IOException("Invalid value type byte " + b);
			}
			return new TypeInfo(heap == null ? fromByte(b) : forHeapType(heap), heap,
					(int) (reader.getPointerIndex() - start), b != 0x64 && (heap != null || b >= 0x68 && b <= 0x74));
		}

		public static ValType readFromReader(BinaryReader reader, java.util.function.LongFunction<ValType> resolver)
				throws IOException {
			return readTypeInfo(reader).resolve(resolver);
		}

		/**
		 * Read a bare s33 heap-type immediate (as used by {@code ref.null}), consuming its bytes.
		 * Unlike {@link #readFromReader} this does not expect the 0x63/0x64 reftype prefix: the
		 * heap type is already the immediate.
		 */
		public static ValType readHeapType(BinaryReader reader) throws IOException {
			return forHeapType(reader.readNext(LEB128Info::signed).asLong());
		}

		/**
		 * Read a block type immediate (the operand of block/loop/if/try/try_table). It is either
		 * the empty type 0x40, a single value type byte, a multi-byte {@code (ref null ht)} /
		 * {@code (ref ht)} value type, or a non-negative s33 type index. The whole immediate is
		 * consumed. A type index is resolved by the caller, so {@code typeIndex} is set to the
		 * index (&gt;= 0) and {@code type} is null in that case; the empty type has both null.
		 */
		public static final class BlockTypeInfo {
			public final ValType type;
			public final long typeIndex;
			public final Long heapType;
			public boolean nullable=true;

			private BlockTypeInfo(ValType type, long typeIndex) {
				this(type, typeIndex, null);
			}
			private BlockTypeInfo(ValType type, long typeIndex, Long heapType) {
				this.type = type;
				this.typeIndex = typeIndex;
				this.heapType = heapType;
			}
		}

		public static BlockTypeInfo readBlockType(BinaryReader reader) throws IOException {
			int b = reader.readNextUnsignedByte();
			if (b == 0x63 || b == 0x64) {
				long heapType = reader.readNext(LEB128Info::signed).asLong();
				BlockTypeInfo info=new BlockTypeInfo(forHeapType(heapType),-1,heapType);info.nullable=b==0x63;return info;
			}
			/* Re-encode the first byte and decode the whole immediate as a signed LEB, so a
			   multi-byte type index is consumed correctly. */
			long value = decodeSignedLeb128(b, reader);
			if (value == -0x40) {
				return new BlockTypeInfo(null, -1); /* empty block type */
			}
			if (value < 0) {
				return new BlockTypeInfo(fromByte((int) value + 0x80), -1);
			}
			return new BlockTypeInfo(null, value);
		}

		/** Decode the rest of a signed LEB128 whose first byte has already been read. */
		private static long decodeSignedLeb128(int firstByte, BinaryReader reader) throws IOException {
			long result = firstByte & 0x7f;
			int shift = 7;
			int b = firstByte;
			while ((b & 0x80) != 0) {
				b = reader.readNextUnsignedByte();
				result |= (long) (b & 0x7f) << shift;
				shift += 7;
			}
			if (shift < 64 && (b & 0x40) != 0) {
				result |= -1L << shift;
			}
			return result;
		}

		/**
		 * True if a value of this type may be used where {@code expected} is required (this is
		 * a subtype of {@code expected}, reflexively). Only the reference subtyping relevant to
		 * the plugin's coarse model is represented:
		 * anyref &gt;= eqref &gt;= {i31ref, structref, arrayref}, funcref &gt;= nofuncref,
		 * externref &gt;= noexternref, exnref &gt;= noexnref, with {@code none} as the bottom of
		 * the internal (any) hierarchy. Numeric and vector types only match themselves.
		 */
		public boolean isSubtypeOf(ValType expected) {
			if (this == expected) {
				return true;
			}
			switch (expected) {
			case anyref:
				return this == eqref || this == i31ref || this == structref || this == arrayref
						|| this == none;
			case eqref:
				return this == i31ref || this == structref || this == arrayref || this == none;
			case structref:
			case arrayref:
			case i31ref:
				return this == none;
			case funcref:
				return this == nofuncref;
			case externref:
				return this == noexternref;
			case exnref:
				return this == noexnref;
			default:
				return false;
			}
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
			       this == nofuncref || this == noexnref || this == none ||
			       this == contref || this == stringref;
		}
		
		/** Returns true if this is a multi-byte valtype (ref null/ref with heaptype). */
		public static boolean isMultiBytePrefix(int b) {
			return b == 0x63 || b == 0x64;
		}
	}
}
