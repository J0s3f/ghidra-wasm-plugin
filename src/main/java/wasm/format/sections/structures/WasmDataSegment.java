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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmDataSegment implements StructConverter {

	private LEB128Info mode;
	private LEB128Info index;
	private ConstantExpression offsetExpr;
	private long fileOffset;
	private LEB128Info size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		mode = reader.readNext(LEB128Info::unsigned);
		long modeVal = mode.asLong();
		if (modeVal == 2) {
			index = reader.readNext(LEB128Info::unsigned);
		} else {
			/* for mode < 2, index defaults to 0 */
			index = null;
		}

		if (modeVal == 0 || modeVal == 2) {
			/* "active" segment with predefined offset */
			offsetExpr = new ConstantExpression(reader);
		} else {
			/* "passive" segment loaded dynamically at runtime */
			offsetExpr = null;
		}

		size = reader.readNext(LEB128Info::unsigned);
		fileOffset = reader.getPointerIndex();
		if (size.asLong() == 0) {
			data = new byte[0];
		} else {
			data = reader.readNextByteArray((int) size.asLong());
		}
	}

	public long getIndex() {
		if (index == null)
			return 0;
		return index.asLong();
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public Long getMemoryOffset() {
		if (offsetExpr != null) {
			/*
			 * B2 (REPORT-N.md §7 item 8): asI32() could not read an i64.const offset, so a memory64
			 * active segment was dropped before the loader placed its bytes. asConstValue() returns
			 * the value for both i32.const and i64.const.
			 */
			return offsetExpr.asConstValue();
		}
		return null;
	}

	/** The global index of a `global.get` offset expression, or null for a const/other offset. */
	public Long getOffsetGlobalIndex() {
		if (offsetExpr != null) {
			return offsetExpr.asGlobalGet();
		}
		return null;
	}

	/** True if this is an active segment (mode 0, or mode 2 with an explicit memory index). */
	public boolean isActive() {
		long modeVal = mode.asLong();
		return modeVal == 0 || modeVal == 2;
	}

	/** True if the segment is active but its offset expression contains unparsed opcodes. */
	public boolean hasUnknownOffset() {
		return offsetExpr != null && offsetExpr.isUnknown();
	}

	public long getSize() {
		return size.asLong();
	}

	public byte[] getData() {
		return data;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String structName = "data_segment_" + getIndex();
		if (getMemoryOffset() != null) {
			structName += "_" + getMemoryOffset();
		}
		StructureBuilder builder = new StructureBuilder(structName);

		builder.addUnsignedLeb128(mode, "mode");
		if (index != null) {
			builder.addUnsignedLeb128(index, "index");
		}
		if (offsetExpr != null) {
			builder.add(offsetExpr, "offset");
		}
		builder.addUnsignedLeb128(size, "size");
		if (data.length != 0) {
			builder.addArray(BYTE, data.length, "data");
		}
		return builder.toStructure();
	}
}
