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
import wasm.format.sections.structures.WasmFuncType;

/**
 * The <i>new</i> WebAssembly exception handling instructions (the exception-handling proposal, as
 * emitted by LLVM &gt;= 19): {@code try_table} (0x1f) and {@code throw_ref} (0x0a). The legacy
 * encoding (try/catch/catch_all/throw/rethrow/delegate) stays in {@link WasmFunctionAnalysis}; this
 * class only decodes the new operand bytes and models their stack effects through the same
 * control-frame machinery.
 *
 * <p>Encoding ({@code try_table blocktype catch* instr* end}):
 *
 * <pre>
 * 0x00 catch         tagidx labelidx
 * 0x01 catch_ref     tagidx labelidx
 * 0x02 catch_all     labelidx
 * 0x03 catch_all_ref labelidx
 * </pre>
 *
 * A catch clause's label is resolved in the context <i>enclosing</i> the try_table (label 0 is the
 * block around the try_table, not the try_table itself) and names the code to run when the exception
 * is caught. That code expects the clause's values on the stack: the tag's payload for catch, the
 * payload plus an {@code exnref} for catch_ref, nothing for catch_all, and an {@code exnref} for
 * catch_all_ref. Since the label target is an ordinary block (or loop), the values it expects are
 * exactly that block's branch arguments, and the linear walk over the block already produces them;
 * this class additionally
 * <ul>
 * <li>validates that the clause's values match the label (advisory: a mismatch is reported as a
 * warning, so that an unexpected module still disassembles), and</li>
 * <li>marks the try_table instruction as an exception dispatcher to the first clause's label (via
 * {@link WasmFunctionAnalysis#ehEnterTryTable}), so the decompiler shows the branch taken when an
 * exception is caught, with the caught value (for a single-value clause) like legacy try does.</li>
 * </ul>
 *
 * The clause bytes themselves are decoded as separate directive instructions (see
 * {@code data/languages/EH2Ops.sinc}); {@link WasmFunctionAnalysis} marks their addresses here.
 */
public class EH2Ops {

	/* catch clause kinds, as encoded after the try_table's blocktype */
	private static final int CLAUSE_CATCH = 0x00;
	private static final int CLAUSE_CATCH_REF = 0x01;
	private static final int CLAUSE_CATCH_ALL = 0x02;
	private static final int CLAUSE_CATCH_ALL_REF = 0x03;

	private EH2Ops() {
	}

	// #region BinaryReader utilities
	private static long readLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::unsigned);
	}

	private static long readSignedLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::signed);
	}
	// #endregion

	/** The payload a tag throws: the tag's type params. Same rule as legacy throw/catch. */
	private static ValType[] tagPayload(WasmAnalysis analysis, long tagidx) {
		WasmFuncType tagType = analysis.getTagType((int) tagidx);
		return tagType == null ? new ValType[0] : tagType.getParamTypes();
	}

	private static ValType[] append(ValType[] types, ValType extra) {
		ValType[] result = new ValType[types.length + 1];
		System.arraycopy(types, 0, result, 0, types.length);
		result[types.length] = extra;
		return result;
	}

	private static String clauseName(int kind) {
		switch (kind) {
		case CLAUSE_CATCH:
			return "catch";
		case CLAUSE_CATCH_REF:
			return "catch_ref";
		case CLAUSE_CATCH_ALL:
			return "catch_all";
		case CLAUSE_CATCH_ALL_REF:
			return "catch_all_ref";
		default:
			return String.format("0x%02x", kind);
		}
	}

	/**
	 * Report (but do not reject) a catch clause whose pushed values do not match its label. Null
	 * types are treated as wildcards.
	 */
	private static void checkClause(Address instAddress, int kind, ValType[] expected, ValType[] pushed) {
		boolean matches = (expected.length == pushed.length);
		if (matches) {
			for (int i = 0; i < expected.length; i++) {
				if (expected[i] != null && pushed[i] != null && expected[i] != pushed[i]) {
					matches = false;
					break;
				}
			}
		}
		if (!matches) {
			Msg.warn(EH2Ops.class, "try_table " + clauseName(kind) + " clause at " + instAddress
					+ " pushes " + pushed.length + " value(s) but its label expects " + expected.length
					+ "; the listing may be inaccurate");
		}
	}

	/**
	 * Decode a {@code try_table} instruction's operands (blocktype plus catch-clause vector) and
	 * update the analysis state: enter the block, and model the exception dispatch to the first
	 * clause's handler label.
	 */
	public static void analyzeTryTable(WasmFunctionAnalysis func, WasmAnalysis analysis, Address instAddress, BinaryReader reader) throws IOException {
		Address functionStart = func.getSignature().getStartAddr();
		/* Read the block type via ValType.readBlockType so that multi-byte forms (a (ref null ht)/
		   (ref ht) value type, or a type index >= 128) are fully consumed. */
		ValType.BlockTypeInfo blockTypeInfo = ValType.readBlockType(reader);
		long count = readLeb128(reader);

		long handlerLabel = -1;
		ValType[] handlerValues = null;

		for (long i = 0; i < count; i++) {
			Address clauseAddress = functionStart.add(reader.getPointerIndex());
			int kind = reader.readNextUnsignedByte();
			ValType[] pushed;
			switch (kind) {
			case CLAUSE_CATCH:
				pushed = tagPayload(analysis, readLeb128(reader));
				break;
			case CLAUSE_CATCH_REF:
				pushed = append(tagPayload(analysis, readLeb128(reader)), ValType.exnref);
				break;
			case CLAUSE_CATCH_ALL:
				pushed = new ValType[0];
				break;
			case CLAUSE_CATCH_ALL_REF:
				pushed = new ValType[] { ValType.exnref };
				break;
			default:
				/*
				 * Not a clause kind we know: stop decoding clauses (the module is malformed; the
				 * rest of the body cannot be located reliably). The block is still entered below.
				 */
				Msg.warn(EH2Ops.class, "Invalid try_table catch clause kind " + String.format("0x%02x", kind)
						+ " at " + clauseAddress);
				func.ehEnterTryTable(instAddress, analysis, blockTypeInfo, handlerLabel, handlerValue(handlerValues, func.ehBlockTypeParamCount(analysis, blockTypeInfo)));
				return;
			}

			long labelidx = readLeb128(reader);
			/* Resolve and validate against the enclosing labels: throws if the index is invalid. */
			checkClause(instAddress, kind, func.ehClauseLabelTypes(instAddress, labelidx), pushed);

			if (i == 0) {
				handlerLabel = labelidx;
				handlerValues = pushed;
			}
			func.ehMarkClause(clauseAddress);
		}

		func.ehEnterTryTable(instAddress, analysis, blockTypeInfo, handlerLabel,
			handlerValue(handlerValues, func.ehBlockTypeParamCount(analysis, blockTypeInfo)));
	}

	/**
	 * The value to hand to the exception dispatch (and so the value the decompiler shows as the
	 * caught exception): the single value the first clause pushes, but only when the try_table has
	 * no params of its own (otherwise the slot the dispatch would write is not the label's slot).
	 * Null means "dispatch without a value".
	 */
	private static ValType handlerValue(ValType[] pushed, int blockTypeParams) {
		if (pushed != null && pushed.length == 1 && blockTypeParams == 0 && pushed[0] != null
				&& pushed[0].getSize() <= 8) {
			return pushed[0];
		}
		return null;
	}

	/** Decode a {@code throw_ref} instruction: it pops an exnref and ends the current block. */
	public static void analyzeThrowRef(WasmFunctionAnalysis func, Address instAddress) {
		func.ehThrowRef(instAddress);
	}
}
