# Repository-wide code review

**Date:** 15 October 2026 · **Revision:** `542698b8c0865aed279d337e15ea065c01508ec7`

**Follow-up:** patch release **v2.8.1** addresses all findings; see [fixes and regression coverage](https://github.com/J0s3f/ghidra-wasm-plugin/blob/v2.8.1/reports/full-code-review-2026-10-15/FIXES.md). The review below describes the original revision.

## Result

**28 actionable findings: 6 high priority (P1), 22 medium priority (P2).** The main risks are incorrect decompiler semantics, loss of valid modern Wasm function bodies, unchecked parser allocations, and destructive installation scripts. No production code was changed.

This review covered the repository as a whole, without using the recent diff as its scope: the 73 Java source files, 22 language/specification files, shipped Python scripts, build configuration, test harness, and four CI workflows. Runtime checks targeted suspected defects; this is not a claim that every instruction, analyzer, platform, or input was exhaustively tested.

**Evidence labels:** **Reproduced** means the relevant behavior was exercised against freshly compiled repository Java classes, the Ghidra decoder/emulator, or a direct API call. **Source-confirmed** identifies a concrete erroneous path established by inspection, with runtime impact explicitly bounded below. P1 means fix promptly because of data loss, incorrect analysis, or resource exhaustion; P2 means a narrower correctness or reliability defect.

## Findings at a glance

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| F01 | P1 | Compiler specs still classify linear memory as nonglobal and put the C stack in `ram` | Reproduced |
| F02 | P1 | Reference branches do not move branch arguments into target slots | Reproduced |
| F03 | P1 | `memory.copy` analyzer mistakes a small destination address for the copy length | Reproduced |
| F04 | P1 | Tiny type declarations can allocate enormous arrays before validation | Reproduced |
| F05 | P1 | Build installer deletes unrelated Ghidra extensions | Source-confirmed |
| F06 | P1 | Test-install helper can delete its source or an unrelated existing directory | Source-confirmed |
| F07 | P2 | Pre-analysis does not consume multibyte local types | Reproduced |
| F08 | P2 | Typed `select` cannot decode multibyte reference types | Reproduced |
| F09 | P2 | Concrete reference types and GC instruction results use incompatible placeholders | Reproduced |
| F10 | P2 | Table initializer expressions are parsed as ordinary table types | Reproduced |
| F11 | P2 | Table64 operations still use i32 indices/results | Reproduced |
| F12 | P2 | Expanded `memory.copy` is unsafe for overlapping ranges | Source-confirmed |
| F13 | P2 | The i32 bulk-copy expansion discards memory indices | Source-confirmed |
| F14 | P2 | Vararg string lookup and injected loads use the wrong address space | Source-confirmed |
| F15 | P2 | Named locals use a parameter-subtracted index into a parameter-inclusive type array | Reproduced |
| F16 | P2 | Stack/struct analyzers read `memidx` as the memarg offset | Reproduced |
| F17 | P2 | Struct synthesis appends overlapping fields at incorrect offsets | Reproduced |
| F18 | P2 | Saturating conversions do not implement saturation | Reproduced |
| F19 | P2 | Unsigned i64 float conversions use signed truncation | Reproduced |
| F20 | P2 | Floating-point `nearest` rounds ties incorrectly | Reproduced |
| F21 | P2 | Floating-point min/max mishandle signed zero | Reproduced |
| F22 | P2 | Signed truncation rejects a valid lower-bound fraction | Reproduced |
| F23 | P2 | `memory.grow` can overflow before checking the maximum | Reproduced |
| F24 | P2 | Trapping stores corrupt previously initialized memory | Reproduced |
| F25 | P2 | Listing structures omit multibyte type bytes and some `rec` prefixes | Reproduced |
| F26 | P2 | Section readers are not bounded to their declared payloads | Reproduced / source-confirmed |
| F27 | P2 | C-stack guessing decodes unsigned indices as signed LEBs | Reproduced |
| F28 | P2 | The emulation runner can report test failures and still exit successfully | Reproduced / source-confirmed |

## High-priority findings

### F01 — Complete the linear-memory address-space migration in both compiler specs

**Location:** [WebAssembly.cspec:16](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.cspec#L16), [WebAssembly-pos-stack.cspec:16](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly-pos-stack.cspec#L16), [WebAssembly.pspec:9](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.pspec#L9).

Loads/stores and loaded data now use `memory`/`memory64`, but both compiler specs declare only `global`, `table`, and `ram` as global storage. Their stack pointer still belongs to `ram`; pointer-inference bounds also mention only `ram`.

**Reproduction:** the live compiler-spec API reports `stack=ram`, `memoryGlobal=false`, and `ramGlobal=true`. A function loading the initialized integer 7 at linear-memory offset 1024 decompiles to a return of the uninitialized-looking local `in_memory_00000400`. The corresponding data exists in the program's `memory` block. This undermines global data recovery and the relationship between the reconstructed C stack and actual memory accesses.

**Fix:** define the intended global linear-memory spaces, C-stack backing space, and pointer-inference policy consistently in both compiler variants. Add decompiler assertions for an initialized global, a string pointer, and a frame-relative store/load; merely counting successful decompiles will miss this.

### F02 — Record stack effects for reference branches

**Location:** [WasmFunctionAnalysis.java:1978](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L1978), [WasmFunctionAnalysis.java:939](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L939), [WebAssembly.sinc:560](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.sinc#L560).

`br_on_null` and `br_on_non_null` add a branch target but never call `setStackEffect`. Their SLEIGH constructors invoke `doBranch`, whose dynamic pop/push injections return without moving anything when that effect is absent. The GC conditional-reference-branch bridge has the same missing bookkeeping.

**Reproduction:** a valid `br_on_null` with an extra temporary below its branch argument returns **99 instead of 42**. A valid typed `br_on_non_null` leaves 99 in the result slot and subsequently attempts `call_ref` at address `0x63`, instead of invoking the function that returns 7. Node accepts both modules and returns 42 and 7 respectively.

**Fix:** model the taken and fall-through stack shapes separately and relocate all label arguments, including the reference when required. Cover nested blocks whose target stack height differs from the source height.

### F03 — Identify `memory.copy` operands by position, not magnitude

**Location:** [WasmMemoryCopyAnalyzer.java:114](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmMemoryCopyAnalyzer.java#L114), [InjectPayloadWasmMemoryCopy.java:64](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/InjectPayloadWasmMemoryCopy.java#L64).

The analyzer iterates an unordered set of input registers, classifies any constant in 1–1024 as `len`, and any constant at least `0x1000` as `src`. It does not establish which operand actually supplied either value. The recorded length controls replacement of the real instruction with a fixed number of loads/stores.

**Reproduction:** `memory.copy(dst=16, src=4096, len=param0)` records **length 16**, even though the length is dynamic. The decompiled function emits sixteen stores and no longer depends on its length parameter. Calling the original with length 0, 1, or 4 has different behavior.

**Fix:** locate the actual `(dst, src, len)` operand-stack slots using pre-analysis/context and inspect those exact values. Only specialize a proven constant length; separately prove any claimed read-only-source property.

### F04 — Bound type-vector allocations before allocating

**Location:** [WasmFuncType.java:39](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmFuncType.java#L39), [WasmGCType.java:277](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmGCType.java#L277).

Parameter/result counts and supertype counts are cast to array sizes without checking remaining bytes or an allocation budget. This bypasses the otherwise careful locals/memory/table bounds. Catching `OutOfMemoryError` in the outer loader occurs after heap exhaustion, and module re-parsing also happens outside that loader wrapper.

**Reproduction:** a **17-byte** file declaring `0x10000000` parameters raises `OutOfMemoryError: Java heap space` in a deliberately bounded 64 MiB diagnostic JVM, before missing type bytes are rejected. Larger normal heaps only make the attempted allocation more expensive.

**Fix:** enforce unsigned range checks, minimum encoded-byte requirements, and per-module allocation budgets before all count-driven allocations. Reuse the same checks on every parse path.

### F05 — Restrict extension replacement to this extension

**Location:** [build-install.ps1:74](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/test-scripts/build-install.ps1#L74), especially line 91.

The installer enumerates `<GhidraDir>/Ghidra/Extensions` and recursively removes **every child**, including unrelated extensions. Its default pin currently selects a normal installation under `C:/Tools`. The version-scoped settings cleanup does not constrain this earlier deletion.

**Impact:** running the advertised local build/check workflow against a populated installation uninstalls other plugins. The lock preflight also rejects an install because of unrelated locked extension jars. No destructive reproduction was run.

**Fix:** identify existing Wasm extension directories by their manifest/language marker and replace only those. Extract and validate the replacement before removing the old copy; propagate extraction errors instead of accepting a partial extraction containing any jar.

### F06 — Validate test-install source/destination relationships before deletion

**Location:** [new-test-install.ps1:20](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/test-scripts/new-test-install.ps1#L20).

Any existing `-Dest` is recursively deleted before the copy. There is no resolved-path check preventing `Dest == Source`, a destination that contains the source, or an unrelated valuable directory. The `robocopy` exit code is also ignored.

**Impact:** an equal source/destination destroys the reference installation; an incorrectly chosen existing destination destroys its contents. A failed copy can proceed into configuration edits or report an incomplete installation. No deletion was exercised.

**Fix:** resolve and validate both paths before mutation, require a destination known to belong to this helper, reject unsafe ancestry/equality, and check `robocopy`'s documented success/failure exit-code range.

## Additional correctness and reliability findings

### F07 — Consume full local value types during pre-analysis

**Location:** [WasmFunctionAnalysis.java:2700](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L2700), [WebAssembly.sinc:282](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.sinc#L282).

The binary parser correctly accepts `(ref null ht)`/`(ref ht)` local declarations. The function walker instead reads their type as one unsigned LEB, leaving the heap type to be interpreted as an opcode; the `.local` directive also consumes only a single LEB for the type. **Reproduced:** a valid nullable-funcref local followed by `local.get 0; ref.is_null` fails with `pop from empty stack`; Node returns 1. Use the shared multibyte-aware type reader and matching SLEIGH local directive.

### F08 — Decode full reference types in typed `select`

**Location:** [WebAssembly.sinc:606](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.sinc#L606).

The Java walker consumes a complete value type, but `select_valtype` accepts only the one-byte name table. **Reproduced:** typed `select (ref null func)` fails decoding with `No corresponding entry in nametable <valtype>, index=99`; Node accepts it and returns 1. Add complete multibyte type constructors, preserving the declared operand width.

### F09 — Use a consistent, hierarchy-aware model for concrete references

**Location:** [WasmEnums.java:113](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/WasmEnums.java#L113), [GCOps.java:63](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/GCOps.java#L63), [WasmFunctionAnalysis.java:1513](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L1513).

Every concrete heap-type reference is mapped to `externref`, whereas GC constructors produce `anyref` and `ref.func` produces `funcref`. Strict pop validation then rejects valid flows. **Reproduced:** `(func (result (ref $S)) struct.new_default $S)` fails with `got anyref, expected externref`; Node accepts and executes it. Typed function tables also fail the exact `== funcref` check. Retain enough type identity/hierarchy to preserve valid subtyping; globally disabling validation would conceal other stack-width errors.

### F10 — Parse table definitions with initializer expressions

**Location:** [WasmTableSection.java:37](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/WasmTableSection.java#L37), [WasmTableType.java:32](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmTableType.java#L32).

The table section always reads `reftype + limits`, ignoring the `0x40 0x00 tabletype expr` definition form. **Reproduced:** a valid one-element `(ref $ft)` table initialized with `ref.func 0` becomes a **100-element i32 table** in Ghidra. The initializer bytes are never applied. Distinguish table definitions from imported table types and evaluate/model the initializer explicitly; reject unsupported framing visibly rather than inventing a table shape.

### F11 — Propagate table64 index width into instructions

**Location:** [WasmFunctionAnalysis.java:1658](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L1658), [WasmFunctionAnalysis.java:2111](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionAnalysis.java#L2111), [WebAssembly.sinc:681](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/WebAssembly.sinc#L681).

Table declarations record the i64 flag, but `table.get/set`, indirect calls, and bulk table instructions continue to consume/produce i32. **Reproduced:** valid table64 `table.get` fails with `got i64, expected i32`; `table.size` in an i64-returning function fails with the inverse mismatch. Resolve each table's index type and implement corresponding SLEIGH variants. The loader comment that an eight-byte table space makes table64 fully modeled is inaccurate.

### F12 — Preserve overlap semantics in bulk-copy lowering

**Location:** [PcodeOpEmitter.java:109](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/PcodeOpEmitter.java#L109), [PcodeOpEmitter.java:142](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/PcodeOpEmitter.java#L142), [InjectPayloadWasmMemoryCopy.java:79](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/InjectPayloadWasmMemoryCopy.java#L79).

Both unrolled paths alternate forward loads and stores; the fallback is named `memcpy`. Wasm `memory.copy` permits overlapping ranges. A copy of three bytes from 4096 to 4097 must transform `ABCD` into `AABC`; these emitted operations instead repeatedly read the overwritten byte and produce `AAAA`. The analyzer does not prove disjointness. The retained `copy_overlap` fixture demonstrates that this lowering is selected; the wrong-byte consequence follows directly from the emitted operation order. Stage source values first or use overlap-aware copying, and keep an appropriate bulk operation when disjointness is unknown.

### F13 — Preserve both memory indices in the i32 bulk-copy path

**Location:** [InjectPayloadWasmMemoryCopy.java:72](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/InjectPayloadWasmMemoryCopy.java#L72), [PcodeOpEmitter.java:109](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/PcodeOpEmitter.java#L109).

Only the path with an eight-byte source or destination passes `srcMemidx`/`dstMemidx`. The all-i32 expansion addresses both pointers in memory 0, without either stride. The fallback also drops the indices when emitting `memcpy(dst, src, len)`. **Source-confirmed impact:** copies involving nonzero i32 memories decompile as accesses to the wrong memory. Carry indices through all expansions and retain space identity in the dynamic representation.

### F14 — Read vararg data from linear memory

**Location:** [WasmVarargAnalyzer.java:247](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmVarargAnalyzer.java#L247), [InjectPayloadWasmCallPrologue.java:69](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/pcode/InjectPayloadWasmCallPrologue.java#L69), [emulate_writev.py:33](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/ghidra_scripts/emulate_writev.py#L33).

The vararg analyzer resolves a format pointer in the default `ram` space, where ordinary low-address linear data is absent. If a vararg property exists, its injected buffer loads also use `ram`. The shipped `writev` example reads its iovecs and payloads there as well. **Source-confirmed impact:** format recovery silently skips ordinary Emscripten strings, and injected/example reads target the wrong storage. Use the target linear-memory space consistently, including pointer width where applicable.

### F15 — Index named-local types with the actual local index

**Location:** [WasmFunctionVariableNameAnalyzer.java:189](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmFunctionVariableNameAnalyzer.java#L189), [WasmAnalysis.java:160](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmAnalysis.java#L160).

`WasmFuncSignature.locals` already includes parameters, but the name applier subtracts `paramCount` before looking up a type. **Reproduced through the real applier with first-use discovery isolated:** an i32 parameter followed by a named i64 local creates `wide_local` as **four-byte `l1`**, not eight-byte `l1q`. The filter also does not verify the name index against the actual locals-array length. Index directly, validate the bound, and select a matching register for each width.

### F16 — Distinguish memarg offsets from explicit memory indices

**Location:** [WasmStackVariableAnalyzer.java:395](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmStackVariableAnalyzer.java#L395), [WasmStructSynthAnalyzer.java:690](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmStructSynthAnalyzer.java#L690).

Both helpers assume operand-object element 1 is the offset. **Reproduced:** `i32.load align=2 memidx=1 offset=16` exposes `[2, 1, 16]`, and struct synthesis returns offset **1**. Stack references and synthesized field layouts are consequently wrong for explicit-memory memargs. Decode the operand shape or extract the effective address from p-code; account for memory identity rather than merging unrelated memories.

### F17 — Do not append overlapping struct fields sequentially

**Location:** [WasmStructSynthAnalyzer.java:765](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmStructSynthAnalyzer.java#L765).

The structure builder adds padding only for forward gaps, then always appends the next field. It does not handle `offset < prevEnd`. **Reproduced through `createStructure`:** accesses `(offset=0,width=8)` and `(offset=4,width=4)` produce `field_0@0` and **`field_4@8`**. Parameters are subsequently retyped to this incorrect layout. Merge overlapping extents conservatively, model unions where appropriate, or decline the class; never attach a field name that disagrees with its actual byte offset.

### F18 — Implement actual saturating conversions

**Location:** [BasicOps.sinc:668](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L668).

All eight `trunc_sat` constructors emit plain `trunc`, with no explicit NaN/range/signedness handling; the emulator deliberately skips conversion traps for this family. **Reproduced:** `i32.trunc_sat_f64_u(-1)` returns `0xffffffff` instead of 0; the unsigned conversion of `2^32` returns 0 instead of `0xffffffff`; the signed conversion of `1e100` returns `0xffffffff` instead of `0x7fffffff`. Implement destination-width clamps in the semantics and test boundary values across all variants.

### F19 — Implement unsigned i64 truncation separately from signed truncation

**Location:** [BasicOps.sinc:604](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L604), [BasicOps.sinc:610](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L610).

The `_u` variants emit the same signed floating-to-integer p-code operation as `_s`. Trap checks recognize the unsigned range but do not correct its result. **Reproduced:** `i64.trunc_f64_u(2^63)` yields **`0x7fffffffffffffff`**, instead of `0x8000000000000000`. Node returns the correct bit pattern. Implement the upper half of the unsigned range explicitly, including the f32 source variant.

### F20 — Use ties-to-even for `nearest`

**Location:** [BasicOps.sinc:502](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L502), [BasicOps.sinc:550](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L550).

Wasm `nearest` is mapped directly to Ghidra `round`. **Reproduced:** f32 `nearest(2.5)` returns **3.0** (`0x40400000`) rather than 2.0 (`0x40000000`). This is observable in both numerical results and subsequent branches. Implement the Wasm rounding rule, including negative half-integers and signed zero, rather than assuming host/p-code rounding semantics match.

### F21 — Handle signed zero in min/max

**Location:** [BasicOps.sinc:520](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L520), [BasicOps.sinc:568](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/data/languages/BasicOps.sinc#L568).

The compare/select implementations treat equal positive and negative zero as interchangeable and can select the wrong sign. **Reproduced:** `f32.min(-0,+0)` returns **+0**; `f32.max(+0,-0)` returns **-0**. Node returns the opposite, required signs. Handle zero ties by sign bits and retain explicit NaN behavior; cover both operand orders and both float widths.

### F22 — Check truncation range after truncating toward zero

**Location:** [WasmEmulateInstructionStateModifier.java:797](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java#L797).

The signed lower-bound test requires the original floating value to be at least the integer minimum. **Reproduced:** `i32.trunc_f64_s(-2147483648.5)` incorrectly traps with `integer overflow`, although truncation toward zero yields the valid integer `-2147483648`. Adjust the representability test for the truncated value and cover fractional values immediately below the lower bound.

### F23 — Check memory-growth overflow before addition

**Location:** [WasmEmulateInstructionStateModifier.java:164](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java#L164).

`old + deltaPages` is computed in signed arithmetic before comparison against the maximum. **Reproduced:** a memory64 with initial 1 and maximum 2 accepts growth by `Long.MAX_VALUE`, returns **1**, and stores a wrapped negative page count. Node returns failure (`-1`). Compare the unsigned delta against remaining capacity before addition; handle unsigned maximums consistently too.

### F24 — Check trapping stores before modifying memory

**Location:** [WasmEmulateInstructionStateModifier.java:727](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java#L727), [WasmEmulateInstructionStateModifier.java:1058](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java#L1058).

Bounds checks run after execution. When a store partly overlaps valid memory, the attempted repair zeros its in-bounds bytes rather than restoring them. **Reproduced:** initialize the final four bytes of a one-page memory to `ABCD`, then execute an i32 store at offset 65534. The emulator traps but leaves **`AB\0\0`**. Wasm's trapping store must preserve `ABCD`. Validate effective addresses before side effects, or snapshot and restore exact original bytes; zeroing is not rollback.

### F25 — Preserve encoded lengths in listing structures

**Location:** [WasmFuncType.java:87](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmFuncType.java#L87), [WasmGCType.java:287](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmGCType.java#L287), [WasmGlobalType.java:53](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmGlobalType.java#L53), [WasmTableType.java:61](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmTableType.java#L61).

Several `toDataType` methods still count one byte per value type after their parsers gained multibyte references. An unwrapped function as the first `rec` member also returns a plain `WasmFuncType`, dropping `recGroupLength`. **Reproduced:** a type section with a nullable-funcref parameter declares 8 bytes but gets 7 bytes of markup; a one-function `rec` type section declares 8 but gets 6. Subsequent field offsets in the listing are misleading. Retain encoded spans, including group headers, and assert structure length against bytes consumed.

### F26 — Bound section and function readers to their own payloads

**Location:** [WasmSection.java:47](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/WasmSection.java#L47), [WasmCodeEntry.java:80](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmCodeEntry.java#L80), [WasmNameSubsection.java:59](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/format/sections/structures/WasmNameSubsection.java#L59).

The outer section reader skips by the declared length without an EOF/overflow check; child readers are whole-provider clones rather than bounded payload readers. Local-group checks measure the remainder of the module, not the function body. Name-subsection bounds likewise use the whole reader length. **Reproduced:** the 11-byte module `00 61 73 6d 01 00 00 00 0c 05 00` is accepted despite a five-byte data-count payload with only one byte present. Other short payloads can consume following sections before failing. This concerns safe framing, independent of the intentional policy of accepting semantically invalid Wasm. Enforce checked ends and bounded subproviders at every container boundary.

### F27 — Decode C-stack indices/counts as unsigned

**Location:** [WasmPreAnalyzer.java:102](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmPreAnalyzer.java#L102), [WasmPreAnalyzer.java:114](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/src/main/java/wasm/analysis/WasmPreAnalyzer.java#L114).

The stack-pointer guesser reads local-group counts and global indices as signed LEBs. **Reproduced:** a valid function beginning with `global.get 64` yields guess **-64**, so the real global is never marked as `SP`. Counts 64–127 can similarly skip the locals loop incorrectly. Use unsigned readers for counts/indices and the full value-type reader for local types. Keep a guessed value local to the program instead of overwriting the analyzer's configured auto mode.

### F28 — Propagate semantic-test failures to the runner exit code

**Location:** [spectest.py:638](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/ghidra_scripts/spectest.py#L638), [run_emulate.ps1:118](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/test-scripts/spectest/run_emulate.ps1#L118), [parse_emulate_report.py:126](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/test-scripts/spectest/parse_emulate_report.py#L126).

The script accumulates failures and prints a summary without failing the process. The wrapper does not check each PyGhidra exit code or require each report to exist, and the aggregator returns 0 even with failed assertions; empty reports are skipped. **Reproduced:** a report containing `RESULT assert_return fail mismatch` produces a failure table but **exit code 0**. This allows shell automation to treat semantic failures or missing runs as success. Add a distinct checker or strict mode that enforces expected reports, nonzero command coverage, allowed skips, and failure totals; make the wrapper propagate that result.

## Verification and retained evidence

- Compiled **all 73 production Java files** with `javac --release 21` against local Ghidra **12.1.4** dependencies. Compilation succeeded, with deprecation/removal warnings for the legacy emulator API.
- Runtime diagnostics loaded those fresh classes from `build/full-code-review-replay/classes`, not the differing installed extension jar. The installed language source/configuration files were byte-compared with the repository and matched. The installed compiled SLEIGH language was reused; a fresh Gradle extension package/SLEIGH rebuild was not run.
- Generated **33** small byte-level fixtures (**30 valid**, plus 3 deliberately malformed inputs) and independently validated/executed them with **Node v26.10.0**. Numeric comparisons use bit patterns where signed JS return presentation differs from Wasm's unsigned interpretation.
- Used real Ghidra program loading, disassembly, decompilation, and `EmulatorHelper`; used direct calls/reflection for the isolated struct, local-name, compiler-spec, offset, and stack-guess checks. Destructive installer paths were inspected only.
- Ran the existing **`test-build-install-cleanup.ps1`** and **`test-stderr-capture.ps1`** regressions in workspace scratch directories; both exited 0. Their success does not cover F05/F06 or semantic instruction correctness.
- The official full probe/spec/real-corpus pipelines were **not** rerun. The targeted checks establish the listed defects, not an overall regression-pass claim.

Files alongside this report:

| File | Purpose |
| --- | --- |
| [oracle-results.json](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/oracle-results.json) | Independent validation and execution results |
| [integration-results.txt](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/integration-results.txt) | Full Ghidra diagnostic output from the verified replay |
| [parser-results.txt](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/parser-results.txt) | Allocation, framing, and markup results |
| [make_review_fixtures.py](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/make_review_fixtures.py) | Reproducible fixture generator using the repository's byte helpers |
| [ReviewHarness.java](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/ReviewHarness.java) / [ParserReview.java](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/ParserReview.java) | Diagnostic drivers |
| [run-review.ps1](https://github.com/J0s3f/ghidra-wasm-plugin/blob/542698b8c0865aed279d337e15ea065c01508ec7/reports/full-code-review-2026-10-15/run-review.ps1) | Recompile current Java sources and regenerate receipts without installing/removing extensions |

Run the diagnostic replay from PowerShell with Java 21+ and Node available:

```powershell
& D:/code/Ghidra-WASM/reports/full-code-review-2026-10-15/run-review.ps1 -GhidraDir C:/Tools/ghidra_12.1.4_PUBLIC
```

The replay records behavior, including defects; its exit code means the diagnostics completed, not that all findings are fixed. The bounded OOM check runs in its own JVM.

## Recommended fix order and further improvements

1. Fix the destructive path selection in the two installation helpers and the unchecked parser allocations.
2. Complete the compiler-spec memory migration, branch-argument movement, and bulk-copy semantics; these can produce plausible but incorrect decompilations.
3. Unify binary/type decoding across parser, pre-analyzer, SLEIGH, and listing markup. Use the valid typed-reference/table fixtures as regression inputs.
4. Add value-based numeric and trap-side-effect assertions, then make the emulation runner enforce them. Keep decode/decompile counts as additional coverage signals.

Other worthwhile improvements, not counted as additional confirmed bugs:

- Track semantic coverage separately from mnemonic/decompile coverage. Many SIMD/proposal instructions intentionally remain opaque userops, and the positive CI spec job primarily checks decode/decompile metrics.
- Replace fixture-preservation validation exceptions (`usesProposalOps`, GC leftovers, tolerant `call_ref`) with explicit expectations for deliberately invalid fixtures, so frozen test data does not determine production validation policy.
- Review blanket read-only memory/table markings against dynamic writes and imported mutation before relying on constant folding. This review did not establish an additional standalone constant-folding repro.
- Bound parser/analysis work with cancellation and aggregate budgets, not only individual array/block limits. Deduplicate per-slot caches where possible.
- Keep documentation aligned with the current `memory64` address space, table64 instruction gaps, and the distinction between decoding an instruction and modeling its semantics.
- Existing documented limits—large `br_table` case truncation, 128 MiB materialization/stride aliasing, component extraction scope, and inline/re-analysis restrictions—remain relevant but were not re-counted as new findings.
