from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test-scripts'))
from wasm_probe_lib import *
set_output_dir(sys.argv[1] if len(sys.argv)>1 else str(Path(__file__).parent / 'fixtures'))

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
