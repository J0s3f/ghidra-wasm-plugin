"""Released Core 1.0--3.0 behaviors shared by semantic tests and the probe gate."""
from wasm_probe_lib import *

EXPECTED = {
    'RC01_sparse32.wasm': 42,
    'RC02_sparse64.wasm': 77,
    'RC03_sparse_overlap.wasm': 0x5a5a7877,
    'RC04_sparse32_upper.wasm': 91,
    'RC10_reanalysis.wasm': 0,
    'RC11_inline.wasm': 123,
    'RC12_inline_nested.wasm': 123,
    'RC20_struct_mixed.wasm': 65678,
    'RC21_struct_empty.wasm': 0,
    'RC22_array_wide.wasm': 10,
    'RC23_array_vector.wasm': 49,
    'RC24_array_fixed.wasm': 66,
    'RC25_array_fill_copy.wasm': 254,
    'RC27_cast_null.wasm': 3,
    'RC28_cast_subtypes.wasm': 9,
    'RC29_i31.wasm': 2,
    'RC30_extern_roundtrip.wasm': 2,
    'RC31_gc_global.wasm': 42,
    'RC32_array_data.wasm': 128,
    'RC33_array_elem.wasm': 14,
    'RC34_nominal_call.wasm': 7,
    'RC35_recursive_cast.wasm': 1,
    'RC36_cast_branches.wasm': 0,
    'RC40_named_types.wasm': 42,
    **{f'RC{n}_{name}.wasm': 0 for n,name in [(50,'interior_struct'),(51,'simd_struct'),(52,'global_struct'),(53,'local_struct'),(54,'indirect_struct'),(55,'wide_struct'),(56,'memory_separation')]},
}

TRAPS = {
    'RC60_null_struct.wasm': 'null reference',
    'RC61_null_cast.wasm': 'cast failure',
    'RC62_wrong_cast.wasm': 'cast failure',
    'RC63_array_bounds.wasm': 'out of bounds array access',
    'RC64_dropped_data.wasm': 'out of bounds memory access',
    'RC65_copy_atomic.wasm': 'out of bounds array access',
}

def fixtures():
    out = {}
    def one(name, code, memories=(), segments=(), globals_=()):
        out[name+'.wasm'] = module(type_section(functype([],[I32])),func_section([0]),
            *([memory_section(memories)] if memories else []),
            *([global_section(globals_)] if globals_ else []),
            export_section([('test',0,0)]),code_section([code+END]),
            *([data_section(segments)] if segments else []))
    cap=0x08000000
    one('RC01_sparse32',i32_const(cap+32)+b'\x28\x02\x00',[(0,4097)],
        [active_data(i32_const(cap+32)+END,b'\x2a\0\0\0')])
    high=0x100000020
    one('RC02_sparse64',i64_const(high)+b'\x28\x42\x01\x00',[(4,1),(4,65537)],
        [active_data(i64_const(high)+END,b'\x4d\0\0\0',1)])
    one('RC03_sparse_overlap',i32_const(cap)+b'\x28\x02\x00',[(0,4097)],
        [active_data(i32_const(cap-4)+END,b'ABCDwxyz'),active_data(i32_const(cap+2)+END,b'ZZYY')])
    one('RC04_sparse32_upper',i32_const(-16)+b'\x28\x02\x00',[(0,65536)],
        [active_data(i32_const(-16)+END,b'\x5b\0\0\0')])
    one('RC10_reanalysis',global_get(0)+drop()+global_get(1)+drop()+i32_const(0),[(0,1)],
        globals_=[(I32,True,i32_const(8192)),(I32,True,i32_const(16384))])
    # Caller preserves s0=100 and local0=20 while inline callee overwrites both slots.
    caller=i32_const(20)+local_set(0)+i32_const(100)+i32_const(1)+call(1)+b'\x6a'+local_get(0)+b'\x6a'+END
    callee=i32_const(99)+local_set(1)+local_get(0)+i32_const(2)+b'\x6a'+END
    out['RC11_inline.wasm']=module(type_section(functype([],[I32]),functype([I32],[I32])),func_section([0,1]),
        export_section([('test',0,0),('callee',0,1)]),
        section(10,vec([body(caller,[(1,I32)]),body(callee,[(1,I32)])])))

    def gc(name,types,code,locals_=(),extra=()):
        out[name+'.wasm']=module(type_section(*types,functype([],[I32])),func_section([len(types)]),
            *extra,export_section([('test',0,0)]),section(10,vec([body(code+END,locals_)])))
    def op(number,*indices): return gc_op(number)+b''.join(uleb(i) for i in indices)
    def get(number,*indices): return local_get(0)+op(number,*indices)
    ref0=b'\x63\x00'
    vector=lambda value:b'\xfd\x0c'+value.to_bytes(4,'little')+bytes(12)

    caller=vector(100)+i64_const(1)+call(1)+local_set(0)+b'\xfd\x1b\x00'+local_get(0)+b'\xa7\x6a'+END
    middle=local_get(0)+call(2)+END
    leaf=vector(99)+drop()+local_get(0)+i64_const(22)+b'\x7c'+END
    out['RC12_inline_nested.wasm']=module(type_section(functype([],[I32]),functype([I64],[I64])),func_section([0,1,1]),
        export_section([('test',0,0)]),section(10,vec([body(caller,[(1,I64)]),body(middle),body(leaf)])))
    fields=[(I32,True),(I64,True),(V128,True),(0x78,True),(0x77,True)]
    code=i32_const(7)+i64_const(42)+vector(3)+i32_const(255)+i32_const(65535)+op(0,0)+local_set(0)
    code+=local_get(0)+i32_const(99)+op(5,0,0)+get(2,0,0)+get(2,0,1)+b'\xa7\x6a'
    code+=get(2,0,2)+b'\xfd\x1b\x00\x6a'+get(3,0,3)+b'\x6a'+get(4,0,4)+b'\x6a'
    gc('RC20_struct_mixed',[struct_type(fields)],code,[(1,ref0)])
    gc('RC21_struct_empty',[struct_type([])],op(0,0)+b'\xd1')
    code=i64_const(0x100000003)+i32_const(3)+op(6,0)+local_set(0)
    code+=local_get(0)+i32_const(1)+i64_const(0x100000007)+op(14,0)
    code+=local_get(0)+i32_const(2)+op(11,0)+b'\xa7'+local_get(0)+i32_const(1)+op(11,0)+b'\xa7\x6a'
    gc('RC22_array_wide',[array_type(I64,True)],code,[(1,ref0)])
    code=vector(42)+i32_const(2)+op(6,0)+local_set(0)+local_get(0)+i32_const(1)+vector(7)+op(14,0)
    code+=local_get(0)+i32_const(0)+op(11,0)+b'\xfd\x1b\x00'+local_get(0)+i32_const(1)+op(11,0)+b'\xfd\x1b\x00\x6a'
    gc('RC23_array_vector',[array_type(V128,True)],code,[(1,ref0)])
    code=i32_const(11)+i32_const(22)+i32_const(33)+op(8,0,3)+local_set(0)
    code+=local_get(0)+i32_const(0)+op(11,0)+local_get(0)+i32_const(1)+op(11,0)+b'\x6a'+local_get(0)+i32_const(2)+op(11,0)+b'\x6a'
    gc('RC24_array_fixed',[array_type(I32,True)],code,[(1,ref0)])
    code=i32_const(8)+op(7,0)+local_set(0)+local_get(0)+i32_const(0)+i32_const(511)+i32_const(5)+op(16,0)
    code+=local_get(0)+i32_const(2)+local_get(0)+i32_const(0)+i32_const(5)+op(17,0,0)
    code+=local_get(0)+i32_const(6)+op(13,0)+local_get(0)+i32_const(3)+op(12,0)+b'\x6a'
    gc('RC25_array_fill_copy',[array_type(0x78,True)],code,[(1,ref0)])
    code=op(1,0)+op(20)+sleb(-0x15)+b'\xd0\x6b'+op(21)+sleb(-0x15)+b'\x6a'
    code+=b'\xd0\x6b'+op(20)+sleb(-0x15)+b'\x6a\xd0\x6b'+op(23)+sleb(-0x15)+b'\xd1\x6a'
    gc('RC27_cast_null',[struct_type([])],code)
    base=b'\x50\x00'+struct_type([(I32,False)])
    sub=b'\x4f\x01\x00'+struct_type([(I32,False),(I64,False)])
    code=i32_const(7)+i64_const(42)+op(0,1)+local_set(0)
    code+=get(20)+sleb(0)+get(22)+sleb(0)+op(2,0,0)+b'\x6a'+get(20)+sleb(2)+b'\x6a'+get(20)+sleb(3)+b'\x6a'
    gc('RC28_cast_subtypes',[base,sub,sub,struct_type([(I64,False)])],code,[(1,b'\x63\x01')])
    code=i32_const(-1)+op(28)+local_set(0)+local_get(0)+i32_const(0x7fffffff)+op(28)+b'\xd3'
    code+=get(29)+i32_const(1)+b'\x6a\x6a'+get(30)+i32_const(0x7fffffff)+b'\x46\x6a'
    gc('RC29_i31',[],code,[(1,bytes([0x6c]))])
    code=op(1,0)+local_set(0)+get(27)+op(26)+op(22)+sleb(0)+local_get(0)+b'\xd3\xd0\x6f'+op(26)+b'\xd1\x6a'
    gc('RC30_extern_roundtrip',[struct_type([])],code,[(1,ref0)])
    gc('RC31_gc_global',[struct_type([(I32,False)])],global_get(0)+op(2,0,0),
        extra=[global_section([(b'\x64\x00',False,i32_const(42)+op(0,0))])])
    code=i32_const(0)+i32_const(4)+op(9,0,0)+local_set(0)
    code+=local_get(0)+i32_const(0)+op(12,0)+local_get(0)+i32_const(1)+op(13,0)+b'\x6a'
    code+=local_get(0)+i32_const(1)+i32_const(2)+i32_const(2)+op(18,0,0)
    code+=local_get(0)+i32_const(2)+op(13,0)+b'\x6a'+misc_op(9)+uleb(0)
    code+=i32_const(0)+i32_const(0)+op(9,0,0)+drop()
    gc('RC32_array_data',[array_type(0x78,True)],code,[(1,ref0)],extra=[data_count_section(1),data_section([passive_data(bytes([255,127,1,2]))])])
    code=i32_const(0)+i32_const(2)+op(10,0,0)+local_set(0)
    code+=local_get(0)+i32_const(0)+op(11,0)+op(22)+sleb(1)+call_ref(1)
    code+=local_get(0)+i32_const(1)+i32_const(0)+i32_const(1)+op(19,0,0)
    code+=local_get(0)+i32_const(1)+op(11,0)+op(22)+sleb(1)+call_ref(1)+b'\x6a'+END
    out['RC33_array_elem.wasm']=module(type_section(array_type(FUNCREF,True),functype([],[I32])),func_section([1,1]),
        export_section([('test',0,0)]),elem_section([b'\x01\x00'+vec([uleb(1),uleb(1)])]),
        section(10,vec([body(code,[(1,ref0)]),body(i32_const(7)+END)])))

    base=b'\x50\x00'+struct_type([(I32,False)])
    sub=b'\x4f\x01\x00'+struct_type([(I32,False),(I64,False)])
    out['RC34_nominal_call.wasm']=module(type_section(base,sub,functype([b'\x63\x00'],[I32]),functype([],[I32])),
        func_section([3,2]),export_section([('test',0,0)]),code_section([
        i32_const(7)+i64_const(42)+op(0,1)+call(1)+END,local_get(0)+op(2,0,0)+END]))
    pair=lambda start:b'\x4e\x02'+b'\x5f\x01\x63'+uleb(start+1)+b'\x00'+b'\x5f\x01\x63'+uleb(start)+b'\x00'
    out['RC35_recursive_cast.wasm']=module(type_section(pair(0),pair(2),functype([],[I32])),func_section([4]),
        export_section([('test',0,0)]),code_section([op(1,0)+op(20)+sleb(2)+END]))
    types=[b'\x50\x00'+struct_type([]),b'\x4f\x01\x00'+struct_type([(I32,False)])]
    success=block(b'\x63\x01',i32_const(7)+op(0,1)+op(24)+b'\x03\x00'+sleb(0)+sleb(1)+drop()+b'\xd0\x01')+b'\xd1'
    failure=block(b'\x63\x00',op(1,0)+op(25)+b'\x03\x00'+sleb(0)+sleb(1)+drop()+b'\xd0\x00')+b'\xd1'
    gc('RC36_cast_branches',types,success+failure+b'\x6a')
    gc('RC60_null_struct',[struct_type([(I32,False)])],b'\xd0\x00'+op(2,0,0))
    gc('RC61_null_cast',[struct_type([])],b'\xd0\x00'+op(22)+sleb(0)+drop()+i32_const(0))
    gc('RC62_wrong_cast',[struct_type([(I32,False)]),struct_type([(I64,False)])],i32_const(0)+op(0,0)+op(22)+sleb(1)+drop()+i32_const(0))
    gc('RC63_array_bounds',[array_type(I32,True)],i32_const(1)+op(7,0)+i32_const(-1)+op(11,0))
    code=misc_op(9)+uleb(0)+i32_const(0)+i32_const(1)+op(9,0,0)+drop()+i32_const(0)
    gc('RC64_dropped_data',[array_type(0x78,True)],code,extra=[data_count_section(1),data_section([passive_data(b'X')])])
    init=i32_const(8)+i32_const(3)+op(6,0)
    code=global_get(0)+i32_const(0)+global_get(0)+i32_const(2)+i32_const(2)+op(17,0,0)+i32_const(0)+END
    after=global_get(0)+i32_const(0)+op(11,0)+END
    out['RC65_copy_atomic.wasm']=module(type_section(array_type(I32,True),functype([],[I32])),func_section([1,1]),
        global_section([(b'\x64\x00',False,init)]),export_section([('test',0,0),('after',0,1)]),code_section([code,after]))
    named=block(I32,i32_const(42))+drop()
    for length in range(2,6):
        heap=b'\xeb'+b'\xff'*(length-2)+b'\x7f'
        named+=op(1,0)+op(20)+heap+drop()
    gc('RC40_named_types',[struct_type([])],named+i32_const(42))

    def struct_probe(name,types,codes,locals_=(),extra=(),indices=None):
        out[name+'.wasm']=module(type_section(*types),func_section(indices or list(range(len(codes)))),
            *([memory_section([(0,1)])] if not any(x[0]==5 for x in extra) else []),*extra,export_section([('test',0,0)]),
            section(10,vec([body(c+END,l) for c,l in zip(codes,locals_ or [()]*len(codes))])))
    load=lambda base,offset:base+b'\x28\x02'+uleb(offset)+drop()
    struct_probe('RC50_interior_struct',[functype([],[I32]),functype([I32],[I32]),functype([I32],[I32])],
        [i32_const(0)+call(1),local_get(0)+i32_const(16)+b'\x6a'+call(2),
         load(local_get(0),0)+load(local_get(0),8)+i32_const(0)])
    # One byte lane access at 0, float at 4: never infer a 16-byte overlap.
    struct_probe('RC51_simd_struct',[functype([],[I32]),functype([I32],[I32])],
        [i32_const(0)+call(1),local_get(0)+vector(0)+b'\xfd\x54\x00\x00\x00'+drop()+
         local_get(0)+b'\x2a\x02\x04'+drop()+i32_const(0)])
    struct_probe('RC52_global_struct',[functype([],[I32])],
        [load(global_get(0),0)+load(global_get(0),8)+i32_const(0)],extra=[global_section([(I32,False,i32_const(0))])])
    struct_probe('RC53_local_struct',[functype([],[I32])],
        [i32_const(0)+local_set(0)+load(local_get(0),0)+load(local_get(0),8)+i32_const(0)],locals_=[[(1,I32)]])
    struct_probe('RC54_indirect_struct',[functype([],[I32]),functype([I32],[I32]),functype([I32],[I32])],
        [i32_const(0)+call(1),local_get(0)+i32_const(0)+call_indirect(2),
         load(local_get(0),0)+load(local_get(0),8)+i32_const(0)],
        extra=[table_section([(FUNCREF,0,1)]),elem_section([b'\x00'+i32_const(0)+END+vec([uleb(2)])])])
    wide=lambda offset:local_get(0)+b'\x28\x02'+uleb(offset)+drop()
    out['RC55_wide_struct.wasm']=module(type_section(functype([],[I32]),functype([I64],[I32])),func_section([0,1]),
        memory_section([(4,1)]),export_section([('test',0,0)]),code_section([
            i64_const(0)+call(1)+END,wide(0)+wide(8)+i32_const(0)+END]))
    struct_probe('RC56_memory_separation',[functype([],[I32]),functype([I32],[I32])],
        [i32_const(0)+call(1),load(local_get(0),0)+local_get(0)+b'\x28\x42\x01\x08'+drop()+i32_const(0)],
        extra=[memory_section([(0,1),(0,1)])])
    return out


def invalid_fixtures():
    """Nominal diagnostics must preserve decoding of intentionally invalid modules."""
    base=b'\x50\x00'+struct_type([(I32,True)])
    changed=b'\x4f\x01\x00'+struct_type([(I64,True)])
    final=struct_type([])
    finalchild=b'\x4f\x01\x00'+struct_type([])
    def graph(*types): return module(type_section(*types))
    unrelated=[struct_type([(I32,False)]),struct_type([(I64,False)]),functype([b'\x63\x01'],[I32]),functype([],[I32])]
    badcall=module(type_section(*unrelated),func_section([3,2]),export_section([('test',0,0)]),code_section([
        i32_const(0)+gc_op(0)+uleb(0)+call(1)+END,i32_const(0)+END]))
    nullcall=module(type_section(struct_type([]),functype([b'\x64\x00'],[I32]),functype([],[I32])),
        func_section([2,1]),export_section([('test',0,0)]),code_section([b'\xd0\x00'+call(1)+END,i32_const(0)+END]))
    openstruct=b'\x50\x00'+struct_type([])
    substruct=b'\x4f\x01\x00'+struct_type([(I32,False)])
    openfunc=b'\x50\x00'+functype([b'\x63\x00'],[])
    badfunc=b'\x4f\x01\x02'+functype([b'\x63\x01'],[])
    openarray=b'\x50\x00\x5e\x63\x00\x01'
    badarray=b'\x4f\x01\x02\x5e\x63\x01\x01'
    return {'mutable_variance.wasm':graph(base,changed),'final_super.wasm':graph(final,finalchild),
            'function_variance.wasm':graph(openstruct,substruct,openfunc,badfunc),
            'array_variance.wasm':graph(openstruct,substruct,openarray,badarray),
            'unrelated_call.wasm':badcall,'nullable_call.wasm':nullcall}


def valid_type_graphs():
    types=[b'\x50\x00'+struct_type([]), b'\x4f\x01\x00'+struct_type([(I32,False)]),
           b'\x50\x00'+functype([b'\x63\x01'],[b'\x63\x00']),
           b'\x4f\x01\x02'+functype([b'\x63\x00'],[b'\x63\x01']),
           b'\x50\x00\x5e\x63\x00\x00',b'\x4f\x01\x04\x5e\x63\x01\x00',
           b'\x50\x00\x5e\x63\x00\x01',b'\x4f\x01\x06\x5e\x63\x00\x01']
    return {'variance.wasm':module(type_section(*types))}
