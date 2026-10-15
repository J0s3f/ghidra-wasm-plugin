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
package wasm.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.analysis.WasmMemoryCopyInfo;

/**
 * Fixup for the memory.copy pcodeop. Inputs are
 * (memidx, memidx2, len, src, dst).
 *
 * If WasmMemoryCopyAnalyzer marked this callsite as a constant .rodata
 * initializer (a known byte length), unroll the copy into element loads/stores
 * so the decompiler folds the read-only source into inline constant stores:
 * <code>memory_copy(...)</code> becomes <code>dst[i] = &lt;const&gt;</code>.
 *
 * Dynamic copies retain an explicit Wasm intrinsic with both memory identities;
 * callers must preserve memory.copy's overlapping-range semantics.
 */
public class InjectPayloadWasmMemoryCopy extends InjectPayloadCallother {

	private int copyOpIndex = -1;

	public InjectPayloadWasmMemoryCopy(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		if (con.inputlist == null || con.inputlist.size() < 5) {
			return ops.getPcodeOps();
		}
		Varnode len = con.inputlist.get(2);
		Varnode src = con.inputlist.get(3);
		Varnode dst = con.inputlist.get(4);

		Integer nbytes = null;
		try {
			nbytes = WasmMemoryCopyInfo.getLength(program, con.baseAddr);
		} catch (Exception e) {
			/* fall through to the dynamic intrinsic */
		}

		if (nbytes != null && nbytes > 0) {
			/*
			 * Byte granularity: a byte value (0..255) can never be mistaken for
			 * a pointer, so the folded constants render as char/int literals
			 * (dst[i] = 'A') rather than &UNK_ram_<word> pointer symbols that
			 * would not link. Word granularity is more compact but the
			 * address-table analyzer types the folded words as pointers.
			 */
			ops.emitUnrolledCopy64(src, dst, nbytes, 1,
					con.inputlist.get(1).getOffset(), con.inputlist.get(0).getOffset());
		} else {
			int idx = copyIndex(program);
			if (idx >= 0) {
				// Preserve both memory identities and pointer widths in the opaque dynamic form.
				ops.emitCallOther(idx, con.inputlist.get(0), con.inputlist.get(1), dst, src, len);
			}
		}
		return ops.getPcodeOps();
	}

	private int copyIndex(Program program) {
		if (copyOpIndex >= 0) {
			return copyOpIndex;
		}
		SleighLanguage lang = (SleighLanguage) program.getLanguage();
		for (int i = 0; i < lang.getNumberOfUserDefinedOpNames(); i++) {
			if ("wasm_memory_copy".equals(lang.getUserDefinedOpName(i))) {
				copyOpIndex = i;
				break;
			}
		}
		return copyOpIndex;
	}
}
