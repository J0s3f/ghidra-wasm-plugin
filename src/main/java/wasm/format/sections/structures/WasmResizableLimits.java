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

/**
 * WebAssembly resizable limits (for memories and tables).
 * 
 * Flags bitfield (per WebAssembly spec):
 *   bit 0 (0x01): has maximum
 *   bit 1 (0x02): shared
 *   bit 2 (0x04): 64-bit index (memory64 / table64)
 *   bit 3 (0x08): custom page size (followed by page-size exponent uleb128)
 */
public class WasmResizableLimits implements StructConverter {

	private int flags;
	private LEB128Info initial;
	private LEB128Info maximum;
	private LEB128Info pageSizeExponent; // present when flags & 0x08 != 0

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		initial = reader.readNext(LEB128Info::unsigned);
		
		// Bit 0: has maximum
		if ((flags & 0x01) != 0) {
			maximum = reader.readNext(LEB128Info::unsigned);
		}
		
		// Bit 3: custom page size (page-size exponent follows)
		if ((flags & 0x08) != 0) {
			pageSizeExponent = reader.readNext(LEB128Info::unsigned);
		}
	}

	public long getInitial() {
		return initial.asLong();
	}

	public long getMaximum() {
		if (maximum != null) {
			return maximum.asLong();
		}
		return -1;
	}

	public boolean hasMaximum() {
		return (flags & 0x01) != 0;
	}

	public boolean isShared() {
		return (flags & 0x02) != 0;
	}

	public boolean is64Bit() {
		return (flags & 0x04) != 0;
	}

	public boolean hasCustomPageSize() {
		return (flags & 0x08) != 0;
	}

	public long getPageSizeExponent() {
		if (pageSizeExponent != null) {
			return pageSizeExponent.asLong();
		}
		return -1;
	}

	public int getFlags() {
		return flags;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("limits");
		builder.add(BYTE, "flags");
		builder.addUnsignedLeb128(initial, "initial");
		if (maximum != null) {
			builder.addUnsignedLeb128(maximum, "maximum");
		}
		if (pageSizeExponent != null) {
			builder.addUnsignedLeb128(pageSizeExponent, "page_size_exponent");
		}
		return builder.toStructure();
	}
}
