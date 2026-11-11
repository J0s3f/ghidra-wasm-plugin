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

# Constant-address accesses of distinct widths, intersections and memories. The
# harness adds pre-existing data and symbols before running the analyzer.
def load_at(address, op):
    return i32_const(address)+op+drop()
globals_ops = [
    load_at(0x100,b'\x28\x02\x00'),  # initialized i32
    load_at(0x200,b'\x29\x03\x00'),  # zero-filled i64
    load_at(0x300,b'\x28\x02\x00'),  # partly initialized
    load_at(0x400,b'\x28\x02\x00'),  # user-defined data
    load_at(0x500,b'\x28\x02\x00'),  # user-defined symbol
    load_at(0x600,simd_op(0)+b'\x04\x00'),  # v128.load: 16 bytes
    load_at(0x700,simd_op(7)+b'\x00\x00'),  # v128.load8_splat: 1 byte
    load_at(0x800,b'\x28\x02\x00'),  # narrow access at same address as i64
    load_at(0x800,b'\x29\x03\x00'),  # overlapping 8-byte access
    load_at(0x804,b'\x28\x02\x00'),  # inside the preceding access
    load_at(0x100,b'\x28\x42\x01\x00'),  # memory 1
    i32_const(0x900)+i32_const(1)+b'\x36\x02\x00',  # zero-filled store target
    load_at(0xa00,b'\x28\x02\x00'),  # existing undefined4 data
    load_at(0xb04,b'\x28\x02\x00'),  # interior of existing defined data
    load_at(0xc00,b'\x28\x02\x00'),  # existing undefined8, different width
]
write('linear_globals.wasm',module(type_section(functype([I32],[])),func_section([0]),
    memory_section([(0,1),(0,1)]),code_section([b''.join(globals_ops)+END]),
    data_section([active_data(i32_const(0x100)+END,b'ABCD'),
                  active_data(i32_const(0x300)+END,b'XY'),
                  active_data(i32_const(0x600)+END,bytes(range(16))),
                  active_data(i32_const(0x100)+END,b'WXYZ',1)])))
# The middle function has a stack-invalid body; both valid neighbors must still
# receive linear-memory analysis when the loader accepts the module.
write('linear_globals_invalid_function.wasm',module(
    type_section(functype([],[])),func_section([0,0,0]),memory_section([(0,1)]),
    code_section([load_at(0x100,b'\x28\x02\x00')+END,drop()+END,
                  load_at(0x200,b'\x28\x02\x00')+END]),
    data_section([active_data(i32_const(0x100)+END,b'\x01\x02\x03\x04'),
                  active_data(i32_const(0x200)+END,b'\x05\x06\x07\x08')])))
# A passive segment may be copied to any location at runtime. It must prevent a
# definite bss classification, but not a fully covered active data classification.
write('linear_globals_unknown.wasm',module(type_section(functype([I32],[])),func_section([0]),
    memory_section([(0,1)]),code_section([
        load_at(0x100,b'\x28\x02\x00')+load_at(0x200,b'\x28\x02\x00')+END]),
    data_section([active_data(i32_const(0x100)+END,b'ABCD'),b'\x01\x01Z'])))
#
# These accesses must be discovered without pre-existing references. The dynamic
# pointer's memarg is deliberately distinct from all constant target addresses.
# Constant bases must survive calls, unmodelled operations and locals, and joins
# where every path agrees, but not dropped values, joins of different values, loop
# induction variables, the null region or a wrapping address.
direct_code = (
    i32_const(0x100)+b'\x28\x02\x08'+drop()+
    i32_const(0x200)+i32_const(17)+b'\x36\x02\x0c'+
    i32_const(0x100)+b'\x28\x42\x01\x10'+drop()+
    local_get(0)+b'\x28\x02'+uleb(0x400)+drop()+
    i32_const(0x200)+call(1)+b'\x36\x02\x40'+
    i32_const(0x200)+local_get(0)+i32_const(3)+b'\x74'+b'\x36\x02\x50'+
    i32_const(0x260)+local_set(1)+local_get(1)+b'\x28\x02\x00'+drop()+
    i32_const(0x680)+drop()+call(1)+b'\x28\x02\x00'+drop()+
    local_get(0)+if_(I32,i32_const(0x600),i32_const(0x700))+b'\x28\x02\x00'+drop()+
    i32_const(0x2c0)+local_set(1)+local_get(0)+if_(0x40,b'\x01')+local_get(1)+b'\x28\x02\x00'+drop()+
    i32_const(0x2e0)+local_set(1)+loop(0x40,local_get(1)+b'\x28\x02\x00'+drop()+
        local_get(1)+i32_const(4)+b'\x6a'+local_set(1)+local_get(0)+br_if(0))+
    i32_const(0)+b'\x28\x02\x00'+drop()+
    i32_const(-4)+b'\x28\x02'+uleb(0x304)+drop()+END)  # 0xfffffffc+0x304 traps
write('linear_globals_direct.wasm',module(type_section(functype([I32],[]),functype([],[I32])),
    func_section([0,1]),memory_section([(0,1),(0,1)]),
    section(10,vec([body(direct_code,[(1,I32)]),body(i32_const(7)+END)])),
    data_section([active_data(i32_const(0x108)+END,b'ABCD'),
                  active_data(i32_const(0x110)+END,b'WXYZ',1)])))

# Handler landings are entered by a caught exception or a suspended continuation from any
# point of the protected code, so constants of the instruction that set up the handler must
# not reach them. The thrower (the last function) stands for any call that may throw.
def try_table(clauses, code):
    return b'\x1f\x40'+vec(clauses)+code+END
def load_local1(control):
    """Load through the landing's local, then a constant load proving the landing is analyzed."""
    return local_get(1)+b'\x28\x02\x00'+drop()+i32_const(control)+b'\x28\x02\x00'+drop()
def handler_module(name, codes):
    """codes: (i32)->() bodies with one i32 local, then a ()->() thrower; tag 0 carries an i32."""
    write(name,module(type_section(functype([I32],[]),functype([],[])),
        func_section([0]*len(codes)+[1]),memory_section([(0,1)]),tag_section([(0,0)]),
        section(10,vec([body(code,[(1,I32)]) for code in codes]+[body(END)])),
        data_section([active_data(i32_const(0x10)+END,b'Z')])))
handler_module('linear_globals_eh.wasm',[
    # The try_table dispatches its only clause to the block end, whose sole other path returns.
    i32_const(0x320)+local_set(1)+
    block(I32,try_table([b'\x00\x00\x00'],i32_const(0x340)+local_set(1)+call(2))+b'\x0f')+
    drop()+load_local1(0x360)+END,
    # A second clause (catch_all) lands on a label that normal flow reaches with 0x3a0.
    i32_const(0x3a0)+local_set(1)+
    block(0x40,block(I32,try_table([b'\x00\x00\x00',b'\x02\x01'],
        i32_const(0x3c0)+local_set(1)+call(2)+i32_const(0x3a0)+local_set(1))+br(1))+drop()+b'\x0f')+
    load_local1(0x3e0)+END])
# Legacy try (V8 rejects mixing it with try_table): the first handler is the try's branch
# target, the second has no static entry and is analyzed from an empty state.
handler_module('linear_globals_legacy_eh.wasm',[
    i32_const(0x500)+local_set(1)+
    b'\x06\x40'+i32_const(0x520)+local_set(1)+call(1)+
    b'\x07\x00'+drop()+load_local1(0x560)+
    b'\x19'+i32_const(0x540)+b'\x28\x02\x00'+drop()+END+END])
# A resume handler clause lands on a label that normal flow reaches with 0x600. V8 does not
# implement stack switching, so the oracle expects it to reject this module.
handler_module('linear_globals_resume.wasm',[
    i32_const(0x600)+local_set(1)+
    block(0x40,i32_const(0x620)+local_set(1)+b'\xd0\x70'+b'\xe3\x01'+vec([b'\x00\x00\x00'])+
        i32_const(0x600)+local_set(1))+
    load_local1(0x640)+END])

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

# Regression fixtures for review findings. gc_new_fixed_const uses element count 11 (0x0b), which a
# byte scan for the constant expression's `end` would mistake for the terminator; the second
# global makes the resulting desynchronisation observable.
write('gc_new_fixed_const.wasm',module(type_section(array_type(I32,False)),
    global_section([(ref_(0),False,i32_const(1)*11+gc_op(8)+uleb(0)+uleb(11)),(I32,False,i32_const(7))])))
# Invalid by design (function section declares two functions, the code section holds one body).
write('func_code_mismatch.wasm',module(type_section(functype([],[])),func_section([0,0]),code_section([END])))
# Passive element segment with an explicit multi-byte reftype, (ref null $0).
write('elem_reftype_multibyte.wasm',module(type_section(functype([],[])),func_section([0]),
    elem_section([b'\x05c\x00\x01\xd2\x00\x0b']),code_section([END])))
# array.new_fixed with the maximum count in unreachable code pops nothing from the stack.
write('unreachable_array_new_fixed.wasm',module(type_section(array_type(I32,False),functype([],[])),func_section([1]),
    code_section([b'\x00'+gc_op(8)+uleb(0)+uleb(0xFFFFFFFF)+drop()+END])))
# table64 with a maximum of 2^64-1 (a negative signed long).
write('table64_max_unsigned.wasm',module(type_section(functype([],[])),
    section(4,vec([bytes([FUNCREF])+b'\x05'+uleb(0)+uleb(2**64-1)]))))
# The same label name in two functions must label both, each in its own function namespace.
write('label_names_repeat.wasm',module(type_section(functype([],[])),func_section([0,0]),
    code_section([b'\x02@\x0b'+END,b'\x02@\x0b'+END]),
    custom_section('name',name_subsection(3,vec([uleb(0)+vec([uleb(0)+uleb(4)+b'exit']),uleb(1)+vec([uleb(0)+uleb(4)+b'exit'])])))))

# Several exports of one function: the indexed export lookup must keep the first one.
write('export_lookup.wasm',module(type_section(functype([],[])),func_section([0,0]),
    export_section([('first',0,0),('second',0,0),('other',0,1)]),code_section([END,END])))

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
