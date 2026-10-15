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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmParsing;
import wasm.format.WasmEnums.ValType;

/**
 * A WebAssembly GC type entry (proposal: garbage collection / typed function
 * references). This covers the type-section encodings that are not plain
 * function types:
 *
 * <pre>
 *   rectype  ::= 0x4E vec(subtype) | subtype
 *   subtype  ::= 0x50 vec(typeidx) comptype      (sub)
 *              | 0x4F vec(typeidx) comptype      (sub final)
 *              | comptype
 *   comptype ::= functype | structtype | arraytype | conttype
 *   structtype ::= 0x5F vec(fieldtype)
 *   arraytype  ::= 0x5E fieldtype
 *   conttype   ::= 0x5D typeidx                 (stack-switching proposal)
 *   fieldtype  ::= storagetype mut
 *   storagetype::= valtype | 0x78 (i8) | 0x77 (i16)
 * </pre>
 *
 * A rec group contributes one type index per member subtype. Extends
 * {@link WasmFuncType} so that {@code WasmTypeSection}'s list (and every
 * consumer of {@code getType()}) keeps working unchanged: a struct/array entry
 * simply reports empty parameter/return tuples.
 *
 * <p>The listing representation is a <em>byte-faithful</em> structure (its
 * length equals the encoded byte length, so it fits the type-section layout):
 * the form/count/subtype bytes are shown verbatim and each field/element is a
 * byte blob whose component name carries the decoded storage type, e.g.
 * {@code field_0_i32_mut} or {@code field_1_refnull_type0}.
 */
public class WasmGCType extends WasmFuncType {

	public enum Kind {
		FUNC, STRUCT, ARRAY, CONT
	}

	/** A field's storage type plus mutability. */
	public static class StorageType {
		public static final int REF_NULL = 0x63; // (ref null <heaptype>)
		public static final int REF = 0x64; // (ref <heaptype>)
		public static final int PACKED_I8 = 0x78;
		public static final int PACKED_I16 = 0x77;

		/** Raw valtype byte, or one of the PACKED / REF / REF_NULL codes. */
		public final int code;
		/** Concrete type index or negative abstract heap-type code (REF / REF_NULL only). */
		public final long heapType;
		/** Encoded byte length of the storage type (1, or 2 for the ref forms with a 1-byte ht). */
		public final int encodedLength;
		private final boolean mutable;
		private ValType resolvedReference;

		StorageType(int code, long heapType, int encodedLength, boolean mutable) {
			this.code = code;
			this.heapType = heapType;
			this.encodedLength = encodedLength;
			this.mutable = mutable;
		}

		public boolean isMutable() {
			return mutable;
		}

		public boolean isPacked() {
			return code == PACKED_I8 || code == PACKED_I16;
		}

		public boolean isRef() {
			return code == REF || code == REF_NULL || isRefByte(code);
		}

		/**
		 * Value type used for pre-analysis stack effects: references collapse to a
		 * single canonical 4-byte reference type; packed i8/i16 behave like i32
		 * (they are only ever read/written as i32 on the operand stack).
		 */
		public ValType asValType() {
			switch (code) {
				case PACKED_I8:
				case PACKED_I16:
					return ValType.i32;
				case REF:
				case REF_NULL:
					return heapTypeValType();
				default: {
					ValType t = ValType.fromByte(code);
					return (t != null) ? t : (isRefByte(code) ? ValType.anyref : ValType.i32);
				}
			}
		}

		private ValType heapTypeValType() {
			return resolvedReference != null ? resolvedReference : ValType.forHeapType(heapType);
		}

		/** Data type used when the (byte-faithful) listing shows this storage byte blob. */
		public DataType asDataType() {
			switch (code) {
				case PACKED_I8:
					return ByteDataType.dataType;
				case PACKED_I16:
					return ShortDataType.dataType;
				default:
					return Undefined4DataType.dataType;
			}
		}

		@Override
		public String toString() {
			switch (code) {
				case PACKED_I8:
					return "i8";
				case PACKED_I16:
					return "i16";
				case REF_NULL:
					return "(ref null " + heapTypeName() + ")";
				case REF:
					return "(ref " + heapTypeName() + ")";
				default: {
					ValType t = ValType.fromByte(code);
					return (t != null) ? t.name() : String.format("0x%02x", code);
				}
			}
		}

		/** Component name for the listing, e.g. "i32_mut" or "refnull_type0". */
		public String componentName() {
			StringBuilder sb = new StringBuilder();
			switch (code) {
				case REF_NULL:
					sb.append("refnull_").append(heapTypeName());
					break;
				case REF:
					sb.append("ref_").append(heapTypeName());
					break;
				default:
					sb.append(toString());
					break;
			}
			if (mutable) {
				sb.append("_mut");
			}
			return sb.toString().replaceAll("[^A-Za-z0-9_]", "_");
		}

		private String heapTypeName() {
			if (heapType >= 0) {
				return "type" + heapType;
			}
			int b = (int) (heapType + 0x80);
			if (b >= 0x69 && b <= 0x74) {
				ValType t = ValType.fromByte(b);
				if (t != null) {
					return t.name();
				}
			}
			return heapType + "";
		}

		private static boolean isRefByte(int b) {
			return b == 0x6f || b == 0x70 || (b >= 0x69 && b <= 0x74);
		}
	}

	private final Kind kind;
	private final boolean hasSubtype;
	private final boolean subtypeFinal;
	private final long[] supertypes;
	private final int subtypeHeaderLength; // 1 (0x4F/0x50) + encoded supertype vector
	private final int recGroupLength; // 0, or 1 (0x4E) + encoded count, on the first rec member
	private final List<StorageType> fields; // STRUCT
	private final int fieldCountLength; // encoded length of the field-count LEB
	private final StorageType element; // ARRAY
	private final WasmFuncType funcType; // FUNC (subtype wrapper around 0x60)
	private final long contTypeIndex; // CONT: the referenced function type index, or -1 if unknown
	private final int contTypeIndexLength; // CONT: encoded byte length of the type index LEB
	private WasmFuncType resolvedContFuncType; // CONT: the referenced function type, resolved by WasmTypeSection

	private WasmGCType(Kind kind, boolean hasSubtype, boolean subtypeFinal, long[] supertypes,
			int subtypeHeaderLength, int recGroupLength, List<StorageType> fields, int fieldCountLength,
			StorageType element, WasmFuncType funcType) {
		this(kind, hasSubtype, subtypeFinal, supertypes, subtypeHeaderLength, recGroupLength, fields,
			fieldCountLength, element, funcType, -1, 0);
	}

	private WasmGCType(Kind kind, boolean hasSubtype, boolean subtypeFinal, long[] supertypes,
			int subtypeHeaderLength, int recGroupLength, List<StorageType> fields, int fieldCountLength,
			StorageType element, WasmFuncType funcType, long contTypeIndex, int contTypeIndexLength) {
		this.kind = kind;
		this.hasSubtype = hasSubtype;
		this.subtypeFinal = subtypeFinal;
		this.supertypes = supertypes;
		this.subtypeHeaderLength = subtypeHeaderLength;
		this.recGroupLength = recGroupLength;
		this.fields = fields;
		this.fieldCountLength = fieldCountLength;
		this.element = element;
		this.funcType = funcType;
		this.contTypeIndex = contTypeIndex;
		this.contTypeIndexLength = contTypeIndexLength;
	}

	// #region Parsing
	private static long readLeb(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::unsigned);
	}

	/**
	 * Parse one type-section entry. Returns the type index(es) it introduces: a
	 * rec group introduces one per member, everything else exactly one. A plain
	 * 0x60 function type is returned as a vanilla {@link WasmFuncType}.
	 */
	public static List<WasmFuncType> parseTypeEntry(BinaryReader reader) throws IOException {
		List<WasmFuncType> result = new ArrayList<>();
		long start = reader.getPointerIndex();
		int form = reader.readNextUnsignedByte();
		if (form == 0x4E) {
			long recStart = reader.getPointerIndex();
			long n = readLeb(reader);
			WasmParsing.checkedCount(reader, n, 1, "recursive type");
			int recPrefix = (int) (reader.getPointerIndex() - (recStart - 1));
			for (long i = 0; i < n; i++) {
				result.add(parseSubType(reader, i == 0 ? recPrefix : 0));
			}
		} else {
			reader.setPointerIndex(start);
			result.add(parseSubType(reader, 0));
		}
		return result;
	}

	private static WasmFuncType parseSubType(BinaryReader reader, int recGroupLength) throws IOException {
		long start = reader.getPointerIndex();
		int b = reader.readNextUnsignedByte();
		boolean hasSubtype = false;
		boolean finalFlag = true;
		long[] supers = new long[0];
		int headerLength = 0;
		if (b == 0x50 || b == 0x4F) {
			hasSubtype = true;
			finalFlag = (b == 0x4F);
			long n = readLeb(reader);
			supers = new long[WasmParsing.checkedCount(reader, n, 1, "supertype")];
			for (int i = 0; i < n; i++) {
				supers[i] = readLeb(reader);
			}
			headerLength = (int) (reader.getPointerIndex() - start);
			start = reader.getPointerIndex();
			b = reader.readNextUnsignedByte();
		}
		switch (b) {
			case 0x60: {
				reader.setPointerIndex(start);
				WasmFuncType func = new WasmFuncType(reader);
				if (!hasSubtype && recGroupLength == 0) {
					return func;
				}
				return new WasmGCType(Kind.FUNC, hasSubtype, finalFlag, supers, headerLength, recGroupLength,
					null, 0, null, func);
			}
			case 0x5F: {
				long countPos = reader.getPointerIndex();
				long n = readLeb(reader);
				WasmParsing.checkedCount(reader, n, 2, "struct field");
				int countLength = (int) (reader.getPointerIndex() - countPos);
				List<StorageType> fields = new ArrayList<>();
				for (long i = 0; i < n; i++) {
					fields.add(readField(reader));
				}
				return new WasmGCType(Kind.STRUCT, hasSubtype, finalFlag, supers, headerLength,
					recGroupLength, fields, countLength, null, null);
			}
			case 0x5E: {
				StorageType element = readField(reader);
				return new WasmGCType(Kind.ARRAY, hasSubtype, finalFlag, supers, headerLength,
					recGroupLength, null, 0, element, null);
			}
			case 0x5D: {
				/* cont <func typeidx> (stack-switching proposal). The index is an s33 (like a heap
				 * type), and is resolved to the referenced function type by WasmTypeSection once the
				 * whole type section is read (it may be a forward reference). Verified against
				 * binaryen version_133: index 64 must be encoded as 0xC0 0x00 (s33), not 0x40. */
				long idxPos = reader.getPointerIndex();
				long idx = reader.readNext(LEB128::signed);
				int idxLength = (int) (reader.getPointerIndex() - idxPos);
				return new WasmGCType(Kind.CONT, hasSubtype, finalFlag, supers, headerLength,
					recGroupLength, null, 0, null, null, idx, idxLength);
			}
			default:
				reader.setPointerIndex(start);
				throw new IOException(
					String.format("unsupported wasm type form 0x%02x in type section at %d", b, start));
		}
	}

	private static StorageType readField(BinaryReader reader) throws IOException {
		long start = reader.getPointerIndex();
		int b = reader.readNextUnsignedByte();
		long heapType = -1;
		if (b == StorageType.REF || b == StorageType.REF_NULL) {
			heapType = reader.readNext(LEB128::signed);
		}
		int encodedLength = (int) (reader.getPointerIndex() - start);
		boolean mutable = reader.readNextUnsignedByte() != 0;
		return new StorageType(b, heapType, encodedLength, mutable);
	}
	// #endregion

	// #region Accessors
	/**
	 * The function type whose signature this entry reports: the wrapped 0x60 for a FUNC subtype,
	 * or the referenced function type for a CONT entry (null until resolved).
	 */
	private WasmFuncType signatureSource() {
		return (kind == Kind.CONT) ? resolvedContFuncType : funcType;
	}

	@Override
	public ValType[] getParamTypes() {
		WasmFuncType source = signatureSource();
		return (source != null) ? source.getParamTypes() : new ValType[0];
	}

	@Override
	public ValType[] getReturnTypes() {
		WasmFuncType source = signatureSource();
		return (source != null) ? source.getReturnTypes() : new ValType[0];
	}

	public Kind getKind() {
		return kind;
	}

	@Override public ValType.TypeInfo[] getParamTypeInfo() {
		WasmFuncType source = signatureSource(); return source == null ? new ValType.TypeInfo[0] : source.getParamTypeInfo();
	}
	@Override public ValType.TypeInfo[] getReturnTypeInfo() {
		WasmFuncType source = signatureSource(); return source == null ? new ValType.TypeInfo[0] : source.getReturnTypeInfo();
	}

	@Override
	public void resolveReferenceTypes(java.util.function.LongFunction<ValType> resolver) {
		if (funcType != null) { funcType.resolveReferenceTypes(resolver); }
		if (fields != null) {
			for (StorageType field : fields) {
				if (field.code == StorageType.REF || field.code == StorageType.REF_NULL) {
					field.resolvedReference = resolver.apply(field.heapType);
				}
			}
		}
		if (element != null && (element.code == StorageType.REF || element.code == StorageType.REF_NULL)) {
			element.resolvedReference = resolver.apply(element.heapType);
		}
	}

	public boolean hasSubtype() {
		return hasSubtype;
	}

	public boolean isSubtypeFinal() {
		return subtypeFinal;
	}

	public long[] getSupertypes() {
		return supertypes;
	}

	public int getFieldCount() {
		return (fields != null) ? fields.size() : 0;
	}

	public StorageType getFieldStorage(int idx) {
		if (fields == null || idx < 0 || idx >= fields.size()) {
			return null;
		}
		return fields.get(idx);
	}

	public ValType getFieldValType(int idx) {
		StorageType st = getFieldStorage(idx);
		return (st != null) ? st.asValType() : null;
	}

	public StorageType getElementStorage() {
		return element;
	}

	public ValType getElementValType() {
		return (element != null) ? element.asValType() : null;
	}

	/** CONT: the referenced (function) type index, or -1 when the entry is not a continuation. */
	public long getContTypeIndex() {
		return contTypeIndex;
	}

	/**
	 * CONT: bind the referenced function type once the whole type section has been parsed. A
	 * missing/out-of-range reference leaves this null and the signature degrades to an empty
	 * parameter/return tuple (the pre-analyzer then models the continuation with no operands).
	 */
	public void resolveContType(WasmFuncType referenced) {
		this.resolvedContFuncType = referenced;
	}
	// #endregion

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (hasSubtype) {
			sb.append("sub").append(subtypeFinal ? " final" : "");
			if (supertypes.length > 0) {
				sb.append(" (super");
				for (long s : supertypes) {
					sb.append(" ").append(s);
				}
				sb.append(")");
			}
			sb.append(" ");
		}
		switch (kind) {
			case FUNC:
				return sb.append(funcType.toString()).toString();
			case STRUCT: {
				sb.append("struct {");
				for (int i = 0; i < fields.size(); i++) {
					if (i != 0) {
						sb.append(", ");
					}
					sb.append(fields.get(i));
					sb.append(fields.get(i).isMutable() ? " mut" : " const");
				}
				return sb.append("}").toString();
			}
			case ARRAY: {
				return sb.append("array ").append(element).append(element.isMutable() ? " mut" : " const")
						.toString();
			}
			case CONT:
			default: {
				return sb.append("cont ").append(contTypeIndex).toString();
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (kind == Kind.FUNC && funcType != null) {
			StructureBuilder builder = new StructureBuilder("gc_func_type");
			if (recGroupLength > 0) {
				builder.add(BYTE, recGroupLength, "rec_group");
			}
			if (subtypeHeaderLength > 0) { builder.add(BYTE, subtypeHeaderLength, "subtype"); }
			builder.add(funcType.toDataType(), "func_type");
			return builder.toStructure();
		}
		switch (kind) {
			case STRUCT: {
				StructureBuilder builder = new StructureBuilder("gc_struct_type");
				if (recGroupLength > 0) {
					builder.add(BYTE, recGroupLength, "rec_group");
				}
				if (subtypeHeaderLength > 0) {
					builder.add(BYTE, subtypeHeaderLength, "subtype");
				}
				builder.add(BYTE, "form");
				builder.add(BYTE, fieldCountLength, "field_count");
				for (int i = 0; i < fields.size(); i++) {
					StorageType st = fields.get(i);
					builder.add(BYTE, st.encodedLength, "field_" + i + "_" + st.componentName());
					builder.add(BYTE, "field_" + i + "_mut");
				}
				return builder.toStructure();
			}
			case CONT: {
				StructureBuilder builder = new StructureBuilder("gc_cont_type");
				if (recGroupLength > 0) {
					builder.add(BYTE, recGroupLength, "rec_group");
				}
				if (subtypeHeaderLength > 0) {
					builder.add(BYTE, subtypeHeaderLength, "subtype");
				}
				builder.add(BYTE, "form");
				builder.add(BYTE, contTypeIndexLength, "cont_type_index");
				return builder.toStructure();
			}
			case ARRAY:
			default: {
				StructureBuilder builder = new StructureBuilder("gc_array_type");
				if (recGroupLength > 0) {
					builder.add(BYTE, recGroupLength, "rec_group");
				}
				if (subtypeHeaderLength > 0) {
					builder.add(BYTE, subtypeHeaderLength, "subtype");
				}
				builder.add(BYTE, "form");
				builder.add(BYTE, element.encodedLength, "element_" + element.componentName());
				builder.add(BYTE, "element_mut");
				return builder.toStructure();
			}
		}
	}
}
