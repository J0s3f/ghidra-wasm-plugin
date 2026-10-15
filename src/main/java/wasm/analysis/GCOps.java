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
package wasm.analysis;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.LEB128;
import ghidra.util.Msg;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmEnums.ValType.TypeInfo;
import wasm.format.WasmTypeGraph;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmGCType;

/**
 * Decoder and stack-effect model for the WebAssembly 0xFB-prefixed GC
 * instructions (proposal: garbage collection).
 *
 * <p>This class owns the opcode, the immediate/operand byte lengths and the
 * pre-analysis stack effects for every 0xFB instruction. All references are
 * modelled as opaque 32-bit values in their abstract reference family; no real GC heap
 * semantics are attempted. Composite/struct/array field types are read from the
 * parsed type section ({@link WasmGCType}) so that e.g. a struct field of type
 * i64 leaves the correct value type on the stack. When the referenced type is
 * not a parsed GC composite, a conservative i32/reference is assumed.
 *
 * <p>Encodings follow the current core spec (binary/instructions.html):
 * <pre>
 *   0xFB 0  struct.new t          0xFB 1  struct.new_default t
 *   0xFB 2  struct.get t f        0xFB 3  struct.get_s t f    0xFB 4 struct.get_u t f
 *   0xFB 5  struct.set t f
 *   0xFB 6  array.new t           0xFB 7  array.new_default t 0xFB 8 array.new_fixed t n
 *   0xFB 9  array.new_data t d    0xFB 10 array.new_elem t e
 *   0xFB 11 array.get t           0xFB 12 array.get_s t      0xFB 13 array.get_u t
 *   0xFB 14 array.set t           0xFB 15 array.len
 *   0xFB 16 array.fill t          0xFB 17 array.copy t1 t2
 *   0xFB 18 array.init_data t d   0xFB 19 array.init_elem t e
 *   0xFB 20/21 ref.test (ref [null] ht)   0xFB 22/23 ref.cast (ref [null] ht)
 *   0xFB 24/25 br_on_cast[_fail] castop l ht1 ht2
 *   0xFB 26 any.convert_extern    0xFB 27 extern.convert_any
 *   0xFB 28 ref.i31               0xFB 29 i31.get_s         0xFB 30 i31.get_u
 * </pre>
 */
public final class GCOps {

	private GCOps() {
	}

	/** Canonical 4-byte reference value type used on the value stack. */
	private static final ValType REF = ValType.anyref;

	/**
	 * Decode the sub-opcode and its immediates, and apply the stack effect.
	 *
	 * @param owner the function analysis (for value-stack / context access)
	 * @param analysis module analysis (for type-section lookups)
	 * @param instAddress address of the 0xFB opcode byte
	 * @param reader positioned immediately after the 0xFB byte
	 */
	public static void handle(WasmFunctionAnalysis owner, WasmAnalysis analysis, Address instAddress,
			BinaryReader reader) throws IOException {
		owner.gcMarkPresent();
		long opcode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		long operands=reader.getPointerIndex();
		try {nominalInputs(owner,analysis,instAddress,(int)opcode,reader);}
		catch(RuntimeException e) {owner.gcDiagnostic(instAddress,"Invalid GC type operand: "+e.getMessage());}
		finally {reader.setPointerIndex(operands);}
		switch ((int) opcode) {
			case 0x00: { // struct.new t: [t^n] -> [(ref t)]
				long t = readLeb(reader);
				int n = fieldCount(analysis, t);
				owner.gcSetInputCount(instAddress, n);
				for (int i = 0; i < n; i++) {
					owner.gcPop(instAddress);
				}
				owner.gcPush(instAddress, ValType.structref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				break;
			}
			case 0x01: { // struct.new_default t: [] -> [(ref t)]
				long t=readLeb(reader);
				owner.gcPush(instAddress, ValType.structref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				break;
			}
			case 0x02: // struct.get t f: [(ref null t)] -> [field]
			case 0x03: // struct.get_s t f: [(ref null t)] -> [i32]
			case 0x04: { // struct.get_u t f
				long t = readLeb(reader);
				long f = readLeb(reader);
				boolean signed = opcode == 0x03 || opcode == 0x04;
				ValType result = signed ? ValType.i32 : fieldValType(analysis, t, f);
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, result);
				if(!signed) {var gc=gcType(analysis,t);if(gc!=null) owner.gcPreciseTop(WasmTypeGraph.storage(gc.getFieldStorage((int)f)));}
				owner.gcSetOperandSize(instAddress, result);
				break;
			}
			case 0x05: { // struct.set t f: [(ref null t) field] -> []
				long t = readLeb(reader);
				long f = readLeb(reader);
				ValType field = fieldValType(analysis, t, f);
				owner.gcPop(instAddress);
				owner.gcPop(instAddress);
				owner.gcSetOperandSize(instAddress, field);
				break;
			}
			case 0x06: { // array.new t: [field i32] -> [(ref t)]
				long t = readLeb(reader);
				ValType elem = elemValType(analysis, t);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, ValType.arrayref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				owner.gcSetOperandSize(instAddress, elem);
				break;
			}
			case 0x07: { // array.new_default t: [i32] -> [(ref t)]
				long t=readLeb(reader);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPush(instAddress, ValType.arrayref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				break;
			}
			case 0x08: { // array.new_fixed t n: [field^n] -> [(ref t)]
				long t = readLeb(reader);
				long n = readLeb(reader);
				/* Pops below the block floor only return null (or fail once, in reachable code), so
				   stop after the first one: n is unbounded (up to 2^32-1) in unreachable code. */
				int available = owner.gcStackAvailable(instAddress);
				owner.gcSetInputCount(instAddress, Math.min(n, available));
				for (long i = 0, pops = Math.min(n, available + 1L); i < pops; i++) {
					owner.gcPop(instAddress);
				}
				owner.gcPush(instAddress, ValType.arrayref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				owner.gcSetOperandSize(instAddress, elemValType(analysis, t));
				break;
			}
			case 0x09: // array.new_data t d: [i32 i32] -> [(ref t)]
			case 0x0A: { // array.new_elem t e: [i32 i32] -> [(ref t)]
				long t=readLeb(reader);
				readLeb(reader);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPush(instAddress, ValType.arrayref);
				owner.gcPreciseTop(TypeInfo.reference(t,false));
				break;
			}
			case 0x0B: // array.get t: [(ref null t) i32] -> [field]
			case 0x0C: // array.get_s t: -> [i32]
			case 0x0D: { // array.get_u t
				long t = readLeb(reader);
				boolean signed = opcode == 0x0C || opcode == 0x0D;
				ValType result = signed ? ValType.i32 : elemValType(analysis, t);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, result);
				if(!signed) {var gc=gcType(analysis,t);if(gc!=null) owner.gcPreciseTop(WasmTypeGraph.storage(gc.getElementStorage()));}
				owner.gcSetOperandSize(instAddress, result);
				break;
			}
			case 0x0E: { // array.set t: [(ref null t) i32 field] -> []
				long t = readLeb(reader);
				ValType elem = elemValType(analysis, t);
				owner.gcPop(instAddress);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcSetOperandSize(instAddress, elem);
				break;
			}
			case 0x0F: // array.len: [(ref null array)] -> [i32]
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, ValType.i32);
				break;
			case 0x10: { // array.fill t: [(ref null t) i32 field i32] -> []
				long t = readLeb(reader);
				ValType elem = elemValType(analysis, t);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcSetOperandSize(instAddress, elem);
				break;
			}
			case 0x11: // array.copy t1 t2: [(ref null x1) i32 (ref null x2) i32 i32] -> []
				readLeb(reader);
				readLeb(reader);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				break;
			case 0x12: // array.init_data t d: [(ref null t) i32 i32 i32] -> []
			case 0x13: // array.init_elem t e
				readLeb(reader);
				readLeb(reader);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPop(instAddress);
				break;
			case 0x14: // ref.test (ref ht): [(ref null ht')] -> [i32]
			case 0x15: // ref.test (ref null ht)
				readHeapType(reader);
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, ValType.i32);
				break;
			case 0x16: // ref.cast (ref ht): [(ref null ht')] -> [(ref ht)]
			case 0x17: { // ref.cast (ref null ht)
				long heap=reader.readNext(LEB128::signed);
				ValType castType = analysis.getModule().resolveHeapType(heap);
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, castType);
				owner.gcPreciseTop(TypeInfo.reference(heap,opcode==0x17));
				break;
			}
			case 0x18: // br_on_cast castop l ht1 ht2
			case 0x19: { // br_on_cast_fail castop l ht1 ht2
				int flags=reader.readNextUnsignedByte(); // castop (nullability flags)
				long labelidx = readLeb(reader);
				long from=reader.readNext(LEB128::signed),to=reader.readNext(LEB128::signed);
				ValType source=analysis.getModule().resolveHeapType(from),target=analysis.getModule().resolveHeapType(to);
				owner.gcConditionalRefBranch(instAddress,labelidx,opcode==0x18?source:target,TypeInfo.reference(from,(flags&1)!=0),TypeInfo.reference(to,(flags&2)!=0),opcode==0x19);
				break;
			}
			case 0x1A: // any.convert_extern: [(ref null extern)] -> [(ref null any)]
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, REF);
				owner.gcPreciseTop(TypeInfo.reference(-18,true));
				break;
			case 0x1B: // extern.convert_any: [(ref null any)] -> [(ref null extern)]
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, ValType.externref);
				owner.gcPreciseTop(TypeInfo.reference(-17,true));
				break;
			case 0x1C: // ref.i31: [i32] -> [(ref i31)]
				owner.gcPop(instAddress, ValType.i32);
				owner.gcPush(instAddress, ValType.i31ref);
				owner.gcPreciseTop(TypeInfo.reference(-20,false));
				break;
			case 0x1D: // i31.get_s: [(ref null i31)] -> [i32]
			case 0x1E: // i31.get_u
				owner.gcPop(instAddress);
				owner.gcPush(instAddress, ValType.i32);
				break;
			default:
				Msg.warn(GCOps.class, "Unsupported GC opcode 0xFB " + String.format("0x%02x", opcode)
						+ " at " + instAddress + " (operand length unknown)");
				break;
		}
	}

	private static void nominalInputs(WasmFunctionAnalysis owner,WasmAnalysis analysis,Address address,int opcode,BinaryReader reader) throws IOException {
		if(opcode<=0x13 && opcode!=0x0f) {
			long index=readLeb(reader);var type=gcType(analysis,index);
			if(type==null) return;
			TypeInfo ref=TypeInfo.reference(index,true);
			if(opcode<=5) {
				if(opcode<=1) {
					TypeInfo[] fields=new TypeInfo[type.getFieldCount()];
					for(int i=0;i<fields.length;i++) {
						fields[i]=WasmTypeGraph.storage(type.getFieldStorage(i));
						if(opcode==1 && fields[i].type.isReferenceType() && !fields[i].nullable) owner.gcDiagnostic(address,"Non-defaultable struct field "+i);
					}
					if(opcode==0) owner.gcCheckTuple(address,fields,0);
				} else {
					var field=type.getFieldStorage((int)readLeb(reader));
					if(opcode==5) {
						owner.gcCheckTop(address,WasmTypeGraph.storage(field));
						if(!field.isMutable()) owner.gcDiagnostic(address,"Write to immutable struct field");
					}
					owner.gcCheckTuple(address,new TypeInfo[]{ref},opcode==5?1:0);
				}
			} else {
				var element=type.getElementStorage();TypeInfo value=WasmTypeGraph.storage(element);
				switch(opcode) {
					case 6: owner.gcCheckTuple(address,new TypeInfo[]{value},1);break;
					case 7: if(value.type.isReferenceType() && !value.nullable) owner.gcDiagnostic(address,"Non-defaultable array element");break;
					case 8: {long count=readLeb(reader);if(count<=1000000) {TypeInfo[] values=new TypeInfo[(int)count];java.util.Arrays.fill(values,value);owner.gcCheckTuple(address,values,0);}break;}
					case 11: case 12: case 13: owner.gcCheckTuple(address,new TypeInfo[]{ref},1);break;
					case 14: owner.gcCheckTop(address,value);owner.gcCheckTuple(address,new TypeInfo[]{ref},2);break;
					case 16: owner.gcCheckTuple(address,new TypeInfo[]{value},1);owner.gcCheckTuple(address,new TypeInfo[]{ref},3);break;
					case 17: {long source=readLeb(reader);owner.gcCheckTuple(address,new TypeInfo[]{TypeInfo.reference(source,true)},2);owner.gcCheckTuple(address,new TypeInfo[]{ref},4);break;}
					case 18: case 19: owner.gcCheckTuple(address,new TypeInfo[]{ref},3);break;
				}
				if((opcode==14 || opcode>=16) && !element.isMutable()) owner.gcDiagnostic(address,"Write to immutable array");
			}
		} else if(opcode==0x1d || opcode==0x1e) owner.gcCheckTop(address,TypeInfo.reference(-20,true));
	}

	private static long readLeb(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::unsigned);
	}

	private static void readHeapType(BinaryReader reader) throws IOException {
		reader.readNext(LEB128::signed); // heaptype = s33
	}

	/**
	 * Decode the immediates of a 0xFB GC instruction followed by its terminating {@code end}
	 * (0x0b) byte, for use inside a WebAssembly constant expression (globals, data/element
	 * offsets).
	 *
	 * <p>Hook for the constant-expression parser (see REPORT-E.md): {@code ConstantExpression}
	 * currently throws {@code IllegalArgumentException("Invalid instruction opcode 251 ...")}
	 * when it meets a GC initializer. The one-line fix is to add
	 * <pre>
	 *   case 0xFB:
	 *       GCOps.decodeConstantExpression(reader);
	 *       return; // the end byte is consumed here
	 * </pre>
	 * to that switch (and to accept the resulting value). The immediate lengths below mirror
	 * {@link #handle} exactly, so the byte stream stays aligned.
	 */
	public static void decodeConstantExpression(BinaryReader reader) throws IOException {
		long opcode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		switch ((int) opcode) {
			case 0x00: // struct.new t
			case 0x01: // struct.new_default t
			case 0x06: // array.new t
			case 0x07: // array.new_default t
			case 0x0B: // array.get t
			case 0x0C: // array.get_s t
			case 0x0D: // array.get_u t
			case 0x0E: // array.set t
			case 0x10: // array.fill t
				readLeb(reader);
				break;
			case 0x02: // struct.get t f
			case 0x03: // struct.get_s t f
			case 0x04: // struct.get_u t f
			case 0x05: // struct.set t f
			case 0x08: // array.new_fixed t n
			case 0x09: // array.new_data t d
			case 0x0A: // array.new_elem t e
			case 0x11: // array.copy t1 t2
			case 0x12: // array.init_data t d
			case 0x13: // array.init_elem t e
				readLeb(reader);
				readLeb(reader);
				break;
			case 0x0F: // array.len
			case 0x1A: // any.convert_extern
			case 0x1B: // extern.convert_any
			case 0x1C: // ref.i31
			case 0x1D: // i31.get_s
			case 0x1E: // i31.get_u
				break;
			case 0x14: // ref.test (ref ht)
			case 0x15: // ref.test (ref null ht)
			case 0x16: // ref.cast (ref ht)
			case 0x17: // ref.cast (ref null ht)
				readHeapType(reader);
				break;
			case 0x18: // br_on_cast castop l ht1 ht2
			case 0x19: // br_on_cast_fail
				reader.readNextUnsignedByte();
				readLeb(reader);
				readHeapType(reader);
				readHeapType(reader);
				break;
			default:
				throw new IOException("unsupported GC opcode 0xFB " + opcode + " in constant expression");
		}
		reader.readNextUnsignedByte(); /* trailing end (0x0b) */
	}

	private static WasmGCType gcType(WasmAnalysis analysis, long typeidx) {
		try {
			WasmFuncType type = analysis.getType((int) typeidx);
			return (type instanceof WasmGCType) ? (WasmGCType) type : null;
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static int fieldCount(WasmAnalysis analysis, long typeidx) {
		WasmGCType gc = gcType(analysis, typeidx);
		return (gc != null) ? gc.getFieldCount() : 0;
	}

	private static ValType fieldValType(WasmAnalysis analysis, long typeidx, long fieldidx) {
		WasmGCType gc = gcType(analysis, typeidx);
		ValType t = (gc != null) ? gc.getFieldValType((int) fieldidx) : null;
		return (t != null) ? t : ValType.i32;
	}

	private static ValType elemValType(WasmAnalysis analysis, long typeidx) {
		WasmGCType gc = gcType(analysis, typeidx);
		ValType t = (gc != null) ? gc.getElementValType() : null;
		return (t != null) ? t : ValType.i32;
	}
}
