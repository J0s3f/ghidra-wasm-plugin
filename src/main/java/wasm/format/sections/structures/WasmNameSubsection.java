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

public abstract class WasmNameSubsection implements StructConverter {

	protected int id;
	private LEB128Info contentLength;
	private long sectionOffset;

	// see https://github.com/WebAssembly/extended-name-section/blob/main/proposals/extended-name-section/Overview.md
	public enum WasmNameSubsectionId {
		NAME_MODULE,
		NAME_FUNCTION,
		NAME_LOCAL,
		NAME_LABELS,
		NAME_TYPE,
		NAME_TABLE,
		NAME_MEMORY,
		NAME_GLOBAL,
		NAME_ELEM,
		NAME_DATA,
		/* ext: extended-name-section */
		NAME_FIELD,
		NAME_TAG
	}

	public static WasmNameSubsection createSubsection(BinaryReader reader) throws IOException {
		long sectionOffset = reader.getPointerIndex();
		int id = reader.readNextUnsignedByte();
		LEB128Info contentLength = reader.readNext(LEB128Info::unsigned);
		/*
		 * @@NAME: bound the skip to the end of the section reader. A malformed (or
		 * deliberately huge) content length must not move the pointer past the end of
		 * the buffer: BinaryReader.setPointerIndex would then fail on the next read.
		 */
		long afterHeader = reader.getPointerIndex();
		long declaredEnd = afterHeader + contentLength.asLong();
		long end = Math.min(declaredEnd, reader.length());
		if (end < afterHeader) {
			end = afterHeader;
		}
		reader.setPointerIndex(end);

		BinaryReader sectionReader = reader.clone(sectionOffset);

		if (id >= WasmNameSubsectionId.values().length) {
			return new WasmNameUnknownSubsection(sectionReader);
		}

		/*
		 * @@NAME: a malformed subsection must never fail the import. Any parse error
		 * (or an out-of-range index) degrades to the "unknown" representation, which
		 * simply keeps the raw bytes for the listing.
		 */
		try {
			switch (WasmNameSubsectionId.values()[id]) {
			case NAME_MODULE:
				return new WasmNameModuleSubsection(sectionReader);
			case NAME_FUNCTION:
				return new WasmNameMapSubsection("function", sectionReader);
			case NAME_LOCAL:
				return new WasmNameLocalSubsection(sectionReader);
			case NAME_LABELS:
				return new WasmNameLabelSubsection(sectionReader);
			case NAME_TYPE:
				return new WasmNameMapSubsection("type", sectionReader);
			case NAME_TABLE:
				return new WasmNameMapSubsection("table", sectionReader);
			case NAME_MEMORY:
				return new WasmNameMapSubsection("memory", sectionReader);
			case NAME_GLOBAL:
				return new WasmNameMapSubsection("global", sectionReader);
			case NAME_ELEM:
				return new WasmNameMapSubsection("elem", sectionReader);
			case NAME_DATA:
				return new WasmNameMapSubsection("data", sectionReader);
			case NAME_FIELD:
				return new WasmNameFieldSubsection(sectionReader);
			case NAME_TAG:
				return new WasmNameMapSubsection("tag", sectionReader);
			default:
				return new WasmNameUnknownSubsection(sectionReader);
			}
		}
		catch (IOException | RuntimeException e) {
			try {
				return new WasmNameUnknownSubsection(reader.clone(sectionOffset));
			}
			catch (IOException | RuntimeException e2) {
				/* The subsection is unparseable even as raw bytes: skip it. */
				return null;
			}
		}
	}

	protected WasmNameSubsection(BinaryReader reader) throws IOException {
		sectionOffset = reader.getPointerIndex();
		id = reader.readNextUnsignedByte();
		contentLength = reader.readNext(LEB128Info::unsigned);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder(getName());
		builder.add(BYTE, "id");
		builder.addUnsignedLeb128(contentLength, "size");
		addToStructure(builder);
		return builder.toStructure();
	}

	public abstract String getName();

	protected abstract void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException;

	public WasmNameSubsectionId getId() {
		if (id < WasmNameSubsectionId.values().length) {
			return WasmNameSubsectionId.values()[id];
		}
		return null;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getContentSize() {
		return contentLength.asLong();
	}

	public long getSectionSize() {
		return 1 + contentLength.getLength() + contentLength.asLong();
	}
}
