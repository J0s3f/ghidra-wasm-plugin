from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test-scripts'))
from wasm_probe_lib import *
from released_core_fixtures import fixtures as released_fixtures, EXPECTED as released_expected, TRAPS as released_traps, invalid_fixtures, valid_type_graphs
set_output_dir(sys.argv[1] if len(sys.argv)>1 else str(Path(__file__).parent / 'fixtures'))
for name,data in released_fixtures().items():
    write(name,data)
import json
Path(sys.argv[1],'released-expected.json').write_text(json.dumps(released_expected))
Path(sys.argv[1],'released-traps.json').write_text(json.dumps(released_traps))
invalid_dir=Path(sys.argv[1],'released-invalid');invalid_dir.mkdir(exist_ok=True)
for name,data in invalid_fixtures().items(): (invalid_dir/name).write_bytes(data)
valid_dir=Path(sys.argv[1],'released-validtypes');valid_dir.mkdir(exist_ok=True)
for name,data in valid_type_graphs().items(): (valid_dir/name).write_bytes(data)

def simple(filename, result, code, extra=(), locals_raw=b'\x00'):
    raw = locals_raw + code + END
    write(filename + '.wasm', module(type_section(functype([], result)),func_section([0]),
        *extra,export_section([('test_'+filename,0,0)]),section(10,vec([uleb(len(raw))+raw]))))

simple('typed_local',[I32],local_get(0)+b'\xd1',locals_raw=b'\x01\x01\x63\x70')
simple('typed_select',[I32],b'\xd0\x70\xd0\x70'+i32_const(1)+b'\x1c\x01\x63\x70\xd1')
simple('table64_size',[I64],misc_op(16)+b'\x00',extra=[table_section([(FUNCREF,4,1)])])
simple('table64_get',[I32],i64_const(0)+b'\x25\x00\xd1',extra=[table_section([(FUNCREF,4,1)])])
write('gc_return.wasm',module(type_section(struct_type([]),b'\x60\x00\x01\x64\x00'),func_section([1]),
    export_section([('test_gc_return',0,0)]),code_section([gc_op(1)+b'\x00'+END])))

# The branch must relocate 42 from s1 to s0, discarding the temporary 99 below it.
simple('br_on_null',[I32],block(I32,i32_const(99)+i32_const(42)+b'\xd0\x70\xd5\x00'+drop()+b'\x6a'))
# For non-null reference branch the reference in s1 must move to result slot s0.
write('br_on_non_null.wasm',module(type_section(functype([], [I32])),func_section([0,0]),
    export_section([('test_br_on_non_null',0,0)]),elem_section([b'\x03\x00'+vec([uleb(1)])]),code_section([
        block(ref_null(0),i32_const(99)+b'\xd2\x01\xd6\x00'+drop()+b'\xd0\x00')+call_ref(0)+END,i32_const(7)+END])))

simple('trunc_lower',[I32],f64_const(-2147483648.5)+b'\xaa')
simple('trunc_unsigned',[I32],f64_const(4294967295.0)+b'\xab')
simple('sat_nan',[I32],f64_const(float('nan'))+misc_op(2))
simple('sat_unsigned_negative',[I32],f64_const(-1.0)+misc_op(3))
simple('sat_unsigned_max',[I32],f64_const(1e100)+misc_op(3))
simple('sat_signed_max',[I32],f64_const(1e100)+misc_op(2))
simple('sat_unsigned_2p32',[I32],f64_const(4294967296.0)+misc_op(3))
simple('trunc_unsigned_i64',[I64],f64_const(9223372036854775808.0)+b'\xb1')
simple('grow_overflow',[I64],i64_const(0x7fffffffffffffff)+b'\x40\x00',extra=[memory_section([(5,1,2)])])
simple('min_zero',[I32],f32_const(-0.0)+f32_const(0.0)+b'\x96\xbc')
simple('max_zero',[I32],f32_const(0.0)+f32_const(-0.0)+b'\x97\xbc')
simple('nearest_half',[I32],f32_const(2.5)+b'\x90\xbc')
simple('oob_store',[],i32_const(65534)+i32_const(0x11223344)+b'\x36\x02\x00',extra=[
    memory_section([(0,1)]),data_section([active_data(i32_const(65532)+END,b'ABCD')])])
simple('oob_store64',[],i64_const(65534)+i32_const(0x11223344)+b'\x36\x02\x00',extra=[
    memory_section([(4,1)]),data_section([active_data(i64_const(65532)+END,b'ABCD')])])
simple('oob_store_simd',[],i32_const(65528)+b'\xfd\x0c'+bytes(16)+b'\xfd\x0b\x04\x00',extra=[
    memory_section([(0,1)]),data_section([active_data(i32_const(65532)+END,b'ABCD')])])

# Struct-synthesis and memarg operand selection fixtures.
simple('multi_memarg',[I32],i32_const(0)+b'\x28\x42\x01\x10',extra=[memory_section([(0,1),(0,1)])])
simple('overlap_struct',[],local_get(0)+b'\x29\x03\x00'+drop()+local_get(0)+b'\x28\x02\x04'+drop(),extra=[memory_section([(0,1)])],locals_raw=b'\x01\x01\x7f')

# A section claiming 5 payload bytes, with just the count byte present.
write('truncated_datacount.wasm',module(b'\x0c\x05\x00'))
# A type section with size 1 whose count/type/arity parser reads the next custom section as types.
write('cross_section_type.wasm',module(b'\x01\x01\x01',custom_section('',b'\x60\x00\x00'),sort=False))
# Deliberately malformed: a huge parameter count in a 16-byte file.
write('huge_params.wasm',module(section(1,b'\x01\x60'+uleb(0x10000000))))

# A valid table initializer expression from typed function references.
write('table_initializer.wasm',module(type_section(functype([],[])),func_section([0]),
    section(4,vec([b'\x40\x00\x64\x00\x00\x01\xd2\x00\x0b'])),code_section([END])))
write('rec_functype.wasm',module(type_section(rectype(functype([],[]))),func_section([0]),code_section([END])))

write('mutable_memory.wasm',module(type_section(functype([I32,I32],[]),functype([],[I32])),func_section([0,1]),
    memory_section([(0,1)]),export_section([('setter',0,0),('read_mutable',0,1)]),code_section([
        local_get(0)+local_get(1)+b'\x36\x02\x00'+END,
        i32_const(1024)+b'\x28\x02\x00'+END]),data_section([active_data(i32_const(1024)+END,b'\x07\x00\x00\x00')])))

write('copy_overlap.wasm',module(type_section(functype([I32],[])),func_section([0]),memory_section([(0,1)]),
    export_section([('copy_overlap',0,0)]),code_section([
        local_get(0)+i32_const(4096)+i32_const(3)+misc_op(10)+b'\x00\x00'+END]),
    data_section([active_data(i32_const(4096)+END,b'ABCD')])))
write('copy_dynamic_len.wasm',module(type_section(functype([I32],[])),func_section([0]),memory_section([(0,1)]),
    export_section([('copy_dynamic_len',0,0)]),code_section([
        i32_const(16)+i32_const(4096)+local_get(0)+misc_op(10)+b'\x00\x00'+END])))
write('typed_signature.wasm',module(type_section(b'\x60\x01\x63\x70\x00')))
write('local_names.wasm',module(type_section(functype([I32],[])),func_section([0]),
    section(10,vec([body(i64_const(3)+local_set(1)+local_get(1)+drop()+END,[(1,I64)])])),
    custom_section('name',name_subsection(2,vec([uleb(0)+name_map([(1,'wide_local')])])))))
simple('global_index64',[],global_get(64)+drop(),extra=[global_section([(I32,True,i32_const(4096))]*65)])

# Reference-family compatibility: these are analysis tests, not a GC heap emulator.
write('gc_array_return.wasm',module(type_section(array_type(I32,False),b'\x60\x00\x01\x64\x00'),func_section([1]),
    code_section([i32_const(0)+gc_op(7)+b'\x00'+END])))
write('gc_i31_return.wasm',module(type_section(functype([],[0x6c])),func_section([0]),
    code_section([i32_const(1)+gc_op(28)+END])))
write('gc_external_return.wasm',module(type_section(functype([0x6e],[EXTERNREF])),func_section([0]),
    code_section([local_get(0)+gc_op(27)+END])))
write('typed_table_call.wasm',module(type_section(functype([],[I32])),func_section([0,0]),
    section(4,vec([b'\x40\x00\x64\x00\x00\x01\xd2\x00\x0b'])),
    export_section([('test_typed_table_call',0,1)]),code_section([i32_const(42)+END,i32_const(0)+b'\x11\x00\x00'+END])))
for fails in (False,True):
    write('br_on_cast'+('_fail' if fails else '')+'.wasm',module(
        type_section(functype([],[]),functype([],[I64,0x6b])),func_section([0]),
        code_section([block(1,i32_const(99)+i64_const(42)+b'\xd0\x6b'+gc_op(25 if fails else 24)+b'\x03\x00\x6b\x6b'+b'\x0c\x00')+drop()+drop()+END])))

table_ops=[
    i64_const(0)+b'\x25\x00'+drop(),
    i64_const(0)+b'\xd0\x70\x26\x00',
    b'\xd0\x70'+i64_const(0)+misc_op(15)+b'\x00'+drop(),
    misc_op(16)+b'\x00'+drop(),
    i64_const(0)+b'\xd0\x70'+i64_const(0)+misc_op(17)+b'\x00',
    i64_const(0)+i32_const(0)+i32_const(0)+misc_op(12)+b'\x00\x00',
    i64_const(0)+i64_const(0)+i64_const(0)+misc_op(14)+b'\x00\x00',
    i64_const(0)+i32_const(0)+i32_const(0)+misc_op(14)+b'\x00\x01',
    i32_const(0)+i64_const(0)+i32_const(0)+misc_op(14)+b'\x01\x00',
    i64_const(0)+b'\x11\x00\x00',
    i64_const(0)+b'\x13\x00\x00',
]
write('table64_ops.wasm',module(type_section(functype([],[])),func_section([0]*len(table_ops)),
    table_section([(FUNCREF,4,1),(FUNCREF,0,1)]),elem_section([b'\x01\x00\x00']),
    code_section([op+END for op in table_ops])))

# Format strings live in linear memory; the same offset in ram contains no format string.
write('varargs.wasm',module(type_section(functype([I32,I32],[I32]),functype([],[I32])),
    import_section([('env','printf',0,uleb(0))]),func_section([1]),memory_section([(0,1)]),
    code_section([i32_const(1024)+i32_const(2048)+call(0)+END]),
    data_section([active_data(i32_const(1024)+END,b'%d\x00')])) )

# Cross-width IEEE edge cases. Expected integer bits are computed independently in Python.
import math, struct, json
numeric=[]
for dest in (32,64):
    for source in (32,64):
        for unsigned in (False,True):
            for value in (float('nan'),float('-inf'),-1e30,-1.5,-0.5,0.0,1.5,2.0**31,2.0**32,2.0**63,2.0**64,float('inf')):
                encoded=f32_const(value) if source==32 else f64_const(value)
                actual=struct.unpack('<f' if source==32 else '<d',encoded[1:])[0]
                minimum=0 if unsigned else -(1 << (dest-1)); maximum=(1 << (dest-int(not unsigned)))-1
                result=0 if math.isnan(actual) else minimum if actual<=minimum else maximum if actual>=maximum else math.trunc(actual)
                op=(4 if dest==64 else 0)+(2 if source==64 else 0)+int(unsigned)
                numeric.append((dest,encoded+misc_op(op),str(result & ((1<<dest)-1))))
for source in (32,64):
    for value in (2.5,3.5,-2.5,-3.5,0.5,-0.5,0.0,-0.0,2**24,2**53,float('inf'),float('-inf')):
        encoded=f32_const(value) if source==32 else f64_const(value)
        actual=struct.unpack('<f' if source==32 else '<d',encoded[1:])[0]
        result=actual if not math.isfinite(actual) else math.copysign(float(round(abs(actual))),actual)
        expected=int.from_bytes(struct.pack('<f' if source==32 else '<d',result),'little')
        numeric.append((source,encoded+bytes([0x90 if source==32 else 0x9e,0xbc if source==32 else 0xbd]),str(expected)))
for source in (32,64):
    for maximum in (False,True):
        for a,b in ((0.0,-0.0),(-0.0,0.0),(-0.0,-0.0),(0.0,0.0),(2.0,3.0),(3.0,2.0)):
            const=f32_const if source==32 else f64_const
            result=(max(a,b) if maximum else min(a,b)) if a!=b else math.copysign(0.0,1 if maximum and (math.copysign(1,a)>0 or math.copysign(1,b)>0) else -1 if not maximum and (math.copysign(1,a)<0 or math.copysign(1,b)<0) else math.copysign(1,a))
            expected=int.from_bytes(struct.pack('<f' if source==32 else '<d',result),'little')
            numeric.append((source,const(a)+const(b)+bytes([(0x97 if maximum else 0x96) if source==32 else (0xa5 if maximum else 0xa4),0xbc if source==32 else 0xbd]),str(expected)))
write('numeric_matrix.wasm',module(type_section(functype([],[I32]),functype([],[I64])),
    func_section([int(width==64) for width,code,result in numeric]),
    export_section([('test_numeric_'+str(i),0,i) for i in range(len(numeric))]),
    code_section([code+END for width,code,result in numeric])))
Path(sys.argv[1],'numeric-expected.tsv').write_text(''.join(str(i)+'\t'+result+'\n' for i,(_,_,result) in enumerate(numeric)))
# Keep existing call/return and operand-cache regressions in this source-compiled run.
import shutil
for fixture in ('call32','call64','cache32','cache64','cache32_controls','cache64_controls','brtable_default'):
    shutil.copyfile(Path(__file__).resolve().parents[1]/'fixtures'/(fixture+'.wasm'),Path(sys.argv[1],fixture+'.wasm'))

# Isolation regressions: grow after import so testing high offsets does not materialize
# hundreds of MiB in Ghidra. Distinct memories must remain distinct above the old stride.
def access(op, index, offset=0, align=2):
    return bytes([op])+uleb(0x40|align)+uleb(index)+uleb(offset)
def load32(index,address): return i32_const(address)+access(0x28,index)
def store32(index,address,value): return i32_const(address)+i32_const(value)+access(0x36,index)
simple('isolation32',[I32],i32_const(2048)+b'\x40\x00'+drop()+
    store32(0,0x08000000,0x44)+store32(1,0,0x11)+
    load32(0,0x08000000)+i32_const(256)+b'\x6c'+load32(1,0)+b'\x6a',
    extra=[memory_section([(0,1),(0,1)])])
simple('isolation_index32',[I32],store32(0,0,0x22)+store32(32,0,0x77)+
    load32(0,0)+i32_const(256)+b'\x6c'+load32(32,0)+b'\x6a',
    extra=[memory_section([(0,1)]*33)])
high=0x100000010
simple('isolation64',[I32],i64_const(65536)+b'\x40\x00'+drop()+i64_const(65536)+b'\x40\x01'+drop()+
    i64_const(high)+i32_const(0x55)+access(0x36,0)+i64_const(high)+i32_const(0x66)+access(0x36,1)+
    i64_const(high)+access(0x28,0)+i32_const(256)+b'\x6c'+i64_const(high)+access(0x28,1)+b'\x6a',
    extra=[memory_section([(4,1),(4,1)])])
simple('isolation_simd',[I32],store32(0,0,0x12)+i32_const(0)+b'\xfd\x0c'+bytes([0x34])+bytes(15)+
    b'\xfd\x0b\x44\x01\x00'+i32_const(0)+b'\xfd\x00\x44\x01\x00\xfd\x1b\x00'+
    i32_const(256)+b'\x6c'+load32(0,0)+b'\x6a',extra=[memory_section([(0,1),(0,1)])])
simple('isolation_atomic',[I32],store32(0,0,0x12)+store32(1,0,0x30)+i32_const(0)+i32_const(4)+
    b'\xfe\x1e\x42\x01\x00'+drop()+load32(1,0)+i32_const(256)+b'\x6c'+load32(0,0)+b'\x6a',
    extra=[memory_section([(0,1),(3,1,1)])])
simple('isolation_copy',[I32],store32(0,0,0x12345678)+store32(1,0,0x11223344)+
    i32_const(0)+i32_const(0)+i32_const(4)+misc_op(10)+b'\x01\x00'+load32(1,0),
    extra=[memory_section([(0,1),(0,1)])])
simple('isolation_oob',[],store32(0,65532,0x12345678)+store32(1,65534,0x11223344),
    extra=[memory_section([(0,1),(0,1)])])
simple('isolation_zero',[I32],i32_const(1)+b'\x40\x01'+drop()+load32(1,0),
    extra=[memory_section([(0,1),(0,0)]),data_section([active_data(i32_const(0)+END,b'ABCD')])])
simple('isolation_copy_overlap',[I32],store32(0,0,0xaa)+store32(0,8199,0xbb)+
    i32_const(1)+i32_const(0)+i32_const(8200)+misc_op(10)+b'\x00\x00'+
    i32_const(0)+i32_const(1)+i32_const(8200)+misc_op(10)+b'\x00\x00'+
    i32_const(0)+access(0x2d,0,align=0)+i32_const(256)+b'\x6c'+i32_const(8199)+access(0x2d,0,align=0)+b'\x6a',
    extra=[memory_section([(0,1)])])

# Alternating labels include distinct targets above the former 1023-case cutoff.
# Test both scalar and mixed i64/v128 label arguments with an extra discarded value.
for mixed in (False,True):
    count=16384
    labels=b'\x0e'+uleb(count)+b''.join(uleb(i%2) for i in range(count))+uleb(1)
    vector=b'\xfd\x0c'+bytes(range(16))
    typ=1 if mixed else I64
    branch=i32_const(99)+i64_const(42)+(vector if mixed else b'')+local_get(0)+labels
    inner=block(typ,branch)+(drop() if mixed else b'')+i64_const(1)+b'\x7c'+(vector if mixed else b'')
    code=block(typ,inner)+(drop() if mixed else b'')+END
    write('brtable_large'+('_mixed' if mixed else '')+'.wasm',module(
        type_section(functype([I32],[I64]),functype([],[I64,V128])),func_section([0]),
        export_section([('dispatch',0,0)]),code_section([code])))
