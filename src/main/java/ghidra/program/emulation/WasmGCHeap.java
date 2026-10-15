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
package ghidra.program.emulation;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.*;
import java.util.*;
import ghidra.app.util.bin.*;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.LEB128;
import wasm.WasmLoader;
import wasm.format.*;
import wasm.format.WasmEnums.*;
import wasm.format.sections.structures.*;

/** Per-emulator Core 3.0 object identities, aggregate storage, casts, and initializer execution. */
final class WasmGCHeap {
	private enum Kind { STRUCT, ARRAY, I31, FOREIGN, EXTERNAL }
	private static final class ObjectValue {
		Kind kind; int type, payload; BigInteger[] fields;
		long length; final TreeMap<Long,BigInteger> ranges = new TreeMap<>();
		ObjectValue(Kind kind, int type) { this.kind = kind; this.type = type; }
		BigInteger get(long index) { return ranges.floorEntry(index).getValue(); }
		void fill(long start, long count, BigInteger value) {
			if (count == 0) { return; }
			long end = start + count;
			BigInteger after = end < length ? get(end) : null;
			ranges.subMap(start,true,end,false).clear(); ranges.put(start,value);
			if (after != null) { ranges.put(end,after); }
		}
	}
	private final WasmModule module;
	private final WasmTypeGraph graph;
	private final MemoryState state;
	private final Map<Integer,ObjectValue> objects = new HashMap<>();
	private final Map<Integer,Integer> i31s = new HashMap<>(), externalized = new HashMap<>(), internalized = new HashMap<>();
	private final Set<Integer> droppedData = new HashSet<>(), droppedElements = new HashSet<>();
	private final Map<Integer,BigInteger[]> elementValues = new HashMap<>();
	private int nextReference = 1;
	WasmGCHeap(WasmModule module, Emulate emulate) {
		this.module = module; this.graph = new WasmTypeGraph(module); this.state = emulate.getMemoryState();
	}
	private LowlevelError trap(String message) { return new LowlevelError(message); }
	private long value(Varnode node) { return state.getValue(node) & 0xffffffffL; }
	private int integer(Varnode node) { return (int) state.getValue(node); }
	private WasmGCType type(int index) { return (WasmGCType) module.getType(index); }
	private int allocate(ObjectValue object) {
		if (nextReference >= 0x7f000000) { throw trap("GC allocation exhausted"); }
		int reference = nextReference++; objects.put(reference,object); return reference;
	}
	private ObjectValue object(long reference) {
		if (reference == 0) { throw trap("null reference"); }
		ObjectValue result = objects.get((int) reference);
		if (result == null) { throw trap("invalid aggregate reference"); }
		return result;
	}
	private ObjectValue aggregate(long reference, Kind kind, int expected) {
		ObjectValue result = object(reference);
		if (result.kind != kind || !graph.isHeapSubtype(result.type,expected)) { throw trap("cast failure"); }
		return result;
	}
	private void range(long start,long count,long length,String error) {
		if (start > length || count > length-start) { throw trap(error); }
	}
	private static BigInteger mask(BigInteger value,int bytes) { return value.and(BigInteger.ONE.shiftLeft(bytes*8).subtract(BigInteger.ONE)); }
	private int width(WasmGCType.StorageType field) { return field.code==0x78?1:field.code==0x77?2:field.asValType().getSize(); }
	private BigInteger stored(WasmGCType.StorageType field,BigInteger value) { return mask(value,width(field)); }
	private BigInteger loaded(WasmGCType.StorageType field,BigInteger value,boolean signed) {
		int bits=width(field)*8;
		return signed && field.isPacked() && value.testBit(bits-1) ? value.subtract(BigInteger.ONE.shiftLeft(bits)).and(BigInteger.valueOf(0xffffffffL)) : value;
	}
	private int newStruct(int index,BigInteger[] fields) {
		ObjectValue object=new ObjectValue(Kind.STRUCT,index); object.fields=fields.clone();
		for(int i=0;i<fields.length;i++) { object.fields[i]=stored(type(index).getFieldStorage(i),fields[i]); }
		return allocate(object);
	}
	private int newArray(int index,long length,BigInteger initial) {
		ObjectValue object=new ObjectValue(Kind.ARRAY,index);object.length=length;
		object.ranges.put(0L,stored(type(index).getElementStorage(),initial));return allocate(object);
	}
	private int i31(int bits) {
		int payload=bits & 0x7fffffff;
		return i31s.computeIfAbsent(payload,key->{ObjectValue object=new ObjectValue(Kind.I31,-1);object.payload=key;return allocate(object);});
	}
	private int convert(int reference,boolean toExternal) {
		if(reference==0) { return 0; }
		ObjectValue object=objects.get(reference);
		if(toExternal && object!=null && object.kind==Kind.FOREIGN || !toExternal && object!=null && object.kind==Kind.EXTERNAL) { return object.payload; }
		Map<Integer,Integer> cache=toExternal?externalized:internalized;
		return cache.computeIfAbsent(reference,key->{ObjectValue box=new ObjectValue(toExternal?Kind.EXTERNAL:Kind.FOREIGN,-1);box.payload=key;return allocate(box);});
	}
	private boolean matches(int reference,long heap,boolean nullable) {
		if(reference==0) { return nullable; }
		ObjectValue object=objects.get(reference);
		if(object==null) {
			// Function references retain their real code addresses for call_ref/call_indirect.
			for(int i=0;i<module.getFunctionCount();i++) if((int)WasmLoader.getFunctionAddressOffset(module,i)==reference) {
				if(heap<0) { return ValType.funcref.isSubtypeOf(ValType.forHeapType(heap)); }
				return graph.isHeapSubtype(module.getFunctionTypeIndex(i),heap);
			}
			return false;
		}
		if(object.kind==Kind.STRUCT || object.kind==Kind.ARRAY) { return graph.isHeapSubtype(object.type,heap); }
		if(heap>=0) { return false; }
		ValType target=ValType.forHeapType(heap);
		return switch(object.kind) {
			case I31 -> ValType.i31ref.isSubtypeOf(target);
			case FOREIGN -> target==ValType.anyref;
			case EXTERNAL -> target==ValType.externref;
			default -> false;
		};
	}
	private BigInteger[] stack(long base,int count,int typeIndex,boolean array) {
		BigInteger[] values=new BigInteger[count];
		for(int i=0;i<count;i++) {
			int size=array?type(typeIndex).getElementValType().getSize():type(typeIndex).getFieldValType(i).getSize();
			values[i]=state.getBigInteger(stateSpace("register"),base+(long)i*WasmLoader.REG_SIZE,size,false);
		}
		return values;
	}
	private ghidra.program.model.address.AddressSpace stateSpace(String name) { return languageFactory.getAddressSpace(name); }
	private ghidra.program.model.address.AddressFactory languageFactory;
	void evaluate(String name,Varnode out,Varnode[] a,Emulate emulate) {
		languageFactory=emulate.getLanguage().getAddressFactory();
		BigInteger result=null;
		switch(name) {
		case "struct_new": result=BigInteger.valueOf(newStruct(integer(a[0]),stack(value(a[1]),type(integer(a[0])).getFieldCount(),integer(a[0]),false)));break;
		case "struct_new_default": {
			BigInteger[] fields=new BigInteger[type(integer(a[0])).getFieldCount()];Arrays.fill(fields,BigInteger.ZERO);
			result=BigInteger.valueOf(newStruct(integer(a[0]),fields));break;
		}
		case "struct_get": {
			var object=aggregate(value(a[2]),Kind.STRUCT,integer(a[0]));int field=integer(a[1]);
			result=loaded(type(integer(a[0])).getFieldStorage(field),object.fields[field],value(a[3])!=0);break;
		}
		case "struct_set": {
			var object=aggregate(value(a[3]),Kind.STRUCT,integer(a[0]));int field=integer(a[1]);var storage=type(integer(a[0])).getFieldStorage(field);
			if(!storage.isMutable()) { throw trap("immutable struct field"); }
			object.fields[field]=stored(storage,state.getBigInteger(a[2],false));break;
		}
		case "array_new": result=BigInteger.valueOf(newArray(integer(a[0]),value(a[1]),state.getBigInteger(a[2],false)));break;
		case "array_new_default": result=BigInteger.valueOf(newArray(integer(a[0]),value(a[1]),BigInteger.ZERO));break;
		case "array_new_fixed": {
			int index=integer(a[0]),count=integer(a[1]);BigInteger[] values=stack(value(a[2]),count,index,true);
			int ref=newArray(index,count,BigInteger.ZERO);ObjectValue object=object(ref);
			for(int i=0;i<count;i++) { object.fill(i,1,stored(type(index).getElementStorage(),values[i])); }
			result=BigInteger.valueOf(ref);break;
		}
		case "array_new_data": case "array_new_elem": {
			int index=integer(a[0]);long length=value(a[2]);BigInteger[] values=segment(integer(a[1]),value(a[3]),length,index,name.endsWith("data"));
			int ref=newArray(index,length,BigInteger.ZERO);ObjectValue object=object(ref);
			for(int i=0;i<values.length;i++) { object.fill(i,1,values[i]); } result=BigInteger.valueOf(ref);break;
		}
		case "array_get": {
			var object=aggregate(value(a[2]),Kind.ARRAY,integer(a[0]));long index=value(a[1]);range(index,1,object.length,"out of bounds array access");
			result=loaded(type(integer(a[0])).getElementStorage(),object.get(index),value(a[3])!=0);break;
		}
		case "array_set": {
			var object=aggregate(value(a[3]),Kind.ARRAY,integer(a[0]));long index=value(a[2]);range(index,1,object.length,"out of bounds array access");
			var storage=type(integer(a[0])).getElementStorage();if(!storage.isMutable()) { throw trap("immutable array element"); }
			object.fill(index,1,stored(storage,state.getBigInteger(a[1],false)));break;
		}
		case "array_len": { var object=object(value(a[0]));if(object.kind!=Kind.ARRAY) { throw trap("cast failure"); }result=BigInteger.valueOf(object.length);break; }
		case "array_fill": {
			var object=aggregate(value(a[1]),Kind.ARRAY,integer(a[0]));long start=value(a[2]),count=value(a[4]);range(start,count,object.length,"out of bounds array access");
			var storage=type(integer(a[0])).getElementStorage();if(!storage.isMutable()) { throw trap("immutable array element"); }
			object.fill(start,count,stored(storage,state.getBigInteger(a[3],false)));break;
		}
		case "array_copy": {
			var dst=aggregate(value(a[2]),Kind.ARRAY,integer(a[0]));var src=aggregate(value(a[4]),Kind.ARRAY,integer(a[1]));
			long d=value(a[3]),s=value(a[5]),n=value(a[6]);range(d,n,dst.length,"out of bounds array access");range(s,n,src.length,"out of bounds array access");
			var storage=type(integer(a[0])).getElementStorage();if(!storage.isMutable()) { throw trap("immutable array element"); }
			if(n!=0) {
				var snapshot=new TreeMap<Long,BigInteger>();snapshot.put(0L,src.get(s));
				for(var entry:src.ranges.subMap(s,false,s+n,false).entrySet()) { snapshot.put(entry.getKey()-s,entry.getValue()); }
				var entries=new ArrayList<>(snapshot.entrySet());
				for(int i=0;i<entries.size();i++) { long end=i+1<entries.size()?entries.get(i+1).getKey():n;var entry=entries.get(i);dst.fill(d+entry.getKey(),end-entry.getKey(),stored(storage,entry.getValue())); }
			}break;
		}
		case "array_init_data": case "array_init_elem": {
			int index=integer(a[0]);var dst=aggregate(value(a[2]),Kind.ARRAY,index);long start=value(a[3]),n=value(a[5]);range(start,n,dst.length,"out of bounds array access");
			var storage=type(index).getElementStorage();if(!storage.isMutable()) { throw trap("immutable array element"); }
			BigInteger[] values=segment(integer(a[1]),value(a[4]),n,index,name.endsWith("data"));
			for(int i=0;i<values.length;i++) { dst.fill(start+i,1,values[i]); }break;
		}
		case "ref_test": result=matches(integer(a[1]),integer(a[0]),value(a[2])!=0)?BigInteger.ONE:BigInteger.ZERO;break;
		case "ref_cast": if(!matches(integer(a[1]),integer(a[0]),value(a[2])!=0)) { throw trap("cast failure"); }result=state.getBigInteger(a[1],false);break;
		case "wasm_br_on_cast": result=matches(integer(a[2]),integer(a[1]),(value(a[3])&2)!=0)?BigInteger.ONE:BigInteger.ZERO;break;
		case "ref_eq": result=integer(a[0])==integer(a[1])?BigInteger.ONE:BigInteger.ZERO;break;
		case "ref_i31": result=BigInteger.valueOf(i31(integer(a[0])));break;
		case "i31_get_s": case "i31_get_u": {
			var object=object(value(a[0]));if(object.kind!=Kind.I31) { throw trap("cast failure"); }
			long bits=object.payload;if(name.endsWith("_s") && (bits&0x40000000L)!=0) { bits|=0x80000000L; }result=BigInteger.valueOf(bits);break;
		}
		case "any_convert_extern": result=BigInteger.valueOf(convert(integer(a[0]),false));break;
		case "extern_convert_any": result=BigInteger.valueOf(convert(integer(a[0]),true));break;
		case "data_drop": droppedData.add(integer(a[0]));break;
		case "elem_drop": droppedElements.add(integer(a[0]));break;
		default: throw trap("Unknown GC operation " + name);
		}
		if(out!=null && result!=null) { state.setValue(out,mask(result,out.getSize())); }
	}
	byte[] data(int index) { return droppedData.contains(index)?new byte[0]:module.getDataSegments().get(index).getData(); }
	private BigInteger[] segment(int index,long offset,long length,int typeIndex,boolean data) {
		var storage=type(typeIndex).getElementStorage();int bytes=width(storage);
		byte[] raw=data?data(index):null;
		BigInteger[] refs=data?null:droppedElements.contains(index)?new BigInteger[0]:elementValues.get(index);
		long available=data?raw.length:refs.length;
		long count=data?length*bytes:length;
		range(offset,count,available,data?"out of bounds memory access":"out of bounds table access");
		if(length>1_000_000) { throw trap("GC allocation exhausted"); }
		BigInteger[] values=new BigInteger[(int)length];
		for(int i=0;i<values.length;i++) { values[i]=data?little(raw,(int)offset+i*bytes,bytes):refs[(int)offset+i]; }
		return values;
	}
	private static BigInteger little(byte[] bytes,int offset,int length) {
		byte[] big=new byte[length];for(int i=0;i<length;i++) { big[length-1-i]=bytes[offset+i]; }return new BigInteger(1,big);
	}
	void initialize(Emulate emulate) {
		languageFactory=emulate.getLanguage().getAddressFactory();
		int imported=module.getImports(WasmExternalKind.EXT_GLOBAL).size();
		for(int i=0;i<module.getNonImportedGlobals().size();i++) {
			var global=module.getNonImportedGlobals().get(i);
			BigInteger value=expression(global.getExpression().getRawBytes());
			state.setValue(stateSpace("global"),(long)(imported+i)*WasmLoader.REG_SIZE,global.getGlobalType().getType().getSize(),value);
		}
		for(int i=0;i<module.getDataSegments().size();i++) if(module.getDataSegments().get(i).isActive()) { droppedData.add(i); }
		for(int i=0;i<module.getElementSegments().size();i++) {
			var segment=module.getElementSegments().get(i);BigInteger[] values;
			if(segment.getExpressions()!=null) { values=segment.getExpressions().stream().map(e->expression(e.getRawBytes())).toArray(BigInteger[]::new); }
			else { byte[] raw=segment.getInitData(module);values=new BigInteger[raw.length/4];for(int j=0;j<values.length;j++) { values[j]=little(raw,j*4,4); } }
			elementValues.put(i,values);
			if(segment.getMode()!=WasmElementSegment.ElementSegmentMode.passive) { droppedElements.add(i); }
			if(segment.getOffset()!=null) {
				for(int j=0;j<values.length;j++) { var address=WasmLoader.getTableAddress(languageFactory,(int)segment.getTableIndex(),segment.getOffset()+j);state.setValue(address.getAddressSpace(),address.getOffset(),4,values[j]); }
			}
		}
	}
	private BigInteger expression(byte[] code) {
		List<BigInteger> stack=new ArrayList<>();
		try {
			BinaryReader reader=new BinaryReader(new ByteArrayProvider(code),true);
			while(reader.getPointerIndex()<code.length) {
				int op=reader.readNextUnsignedByte();if(op==0x0b) { break; }
				switch(op) {
				case 0x41: stack.add(mask(BigInteger.valueOf(reader.readNext(LEB128::signed)),4));break;
				case 0x42: stack.add(WasmLoader.unsignedLong(reader.readNext(LEB128::signed)));break;
				case 0x43: stack.add(little(reader.readNextByteArray(4),0,4));break;
				case 0x44: stack.add(little(reader.readNextByteArray(8),0,8));break;
				case 0xfd: if(reader.readNext(LEB128::unsigned)!=12) { throw trap("Invalid vector initializer"); }stack.add(little(reader.readNextByteArray(16),0,16));break;
				case 0xd0: reader.readNext(LEB128::signed);stack.add(BigInteger.ZERO);break;
				case 0xd2: stack.add(BigInteger.valueOf(WasmLoader.getFunctionAddressOffset(module,(int)(long)reader.readNext(LEB128::unsigned))));break;
				case 0x23: {int index=(int)(long)reader.readNext(LEB128::unsigned);stack.add(state.getBigInteger(stateSpace("global"),(long)index*WasmLoader.REG_SIZE,module.getGlobalType(index).getType().getSize(),false));break;}
				case 0x6a: case 0x6b: case 0x6c: case 0x7c: case 0x7d: case 0x7e: {
					BigInteger right=stack.remove(stack.size()-1),left=stack.remove(stack.size()-1);int operation=op<0x7c?op-0x6a:op-0x7c;
					stack.add(mask(operation==0?left.add(right):operation==1?left.subtract(right):left.multiply(right),op<0x7c?4:8));break;
				}
				case 0xfb: {
					int sub=(int)(long)reader.readNext(LEB128::unsigned);int index=sub<=8?(int)(long)reader.readNext(LEB128::unsigned):-1;int ref;
					if(sub==0 || sub==1) {
						int n=type(index).getFieldCount();BigInteger[] fields=new BigInteger[n];
						for(int j=n-1;j>=0;j--) {fields[j]=sub==1?BigInteger.ZERO:stack.remove(stack.size()-1);}ref=newStruct(index,fields);
					} else if(sub==6 || sub==7) {
						long n=stack.remove(stack.size()-1).longValue()&0xffffffffL;BigInteger initial=sub==7?BigInteger.ZERO:stack.remove(stack.size()-1);ref=newArray(index,n,initial);
					} else if(sub==8) {
						int n=(int)(long)reader.readNext(LEB128::unsigned);BigInteger[] values=new BigInteger[n];for(int j=n-1;j>=0;j--){values[j]=stack.remove(stack.size()-1);}
						ref=newArray(index,n,BigInteger.ZERO);for(int j=0;j<n;j++){object(ref).fill(j,1,stored(type(index).getElementStorage(),values[j]));}
					} else if(sub==28) {ref=i31(stack.remove(stack.size()-1).intValue());}
					else if(sub==26 || sub==27) {ref=convert(stack.remove(stack.size()-1).intValue(),sub==27);}
					else {throw trap("Unsupported GC initializer opcode "+sub);}
					stack.add(BigInteger.valueOf(ref));break;
				}
				default: throw trap("Unsupported initializer opcode "+op);
				}
			}
			return stack.get(stack.size()-1);
		} catch(IOException e) {throw new LowlevelError("Invalid initializer",e);}
	}
}
