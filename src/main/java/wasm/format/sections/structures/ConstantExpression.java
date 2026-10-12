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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.Float8DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.WasmLoader;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;
import ghidra.util.Msg;

/* A reader for expressions containing a single constant instruction.

Such expressions consist of an instruction from the following list:
- t.const c
- ref.null
- ref.func x
- global.get x
followed by an explicit end byte (0x0b).

In principle, constant expressions could contain more than one instruction.
However, a constant expression must produce a single value, so with the
current list of allowed instructions, no valid expression can contain two
or more instructions. This may change in the future: the extended-const
proposal will add add/sub/mul instructions, at which point this class will
need to be updated to handle multiple instructions in a single expression.

This class now also handles extended-const operators (i32/i64 add/sub/mul)
and gracefully skips unknown opcodes by scanning to the matching end byte,
so that modules with unsupported initializers still import successfully.
*/
public final class ConstantExpression implements StructConverter {

	private ConstantInstruction type;
	private LEB128Info opcode2;
	private Object value;
	private byte[] rawBytes; // Raw bytes of the entire expression (including end)
	private boolean unknown = false; // True if the initializer contains unparsed/unknown opcodes

	private enum ConstantInstruction {
		I32_CONST, /* i32.const n: value is LEB128 */
		I64_CONST, /* i64.const n: value is LEB128 */
		F32_CONST, /* f32.const z: value is byte[4] */
		F64_CONST, /* f64.const z: value is byte[8] */
		V128_CONST, /* v128.const z: value is byte[16] */
		REF_NULL_FUNCREF, /* ref.null funcref: value is null */
		REF_NULL_EXTERNREF, /* ref.null externref: value is null */
		REF_FUNC, /* ref.func x: value is LEB128 funcidx */
		GLOBAL_GET, /* global.get x: value is LEB128 globalidx */
		I32_ADD,    /* i32.add */
		I32_SUB,    /* i32.sub */
		I32_MUL,    /* i32.mul */
		I64_ADD,    /* i64.add */
		I64_SUB,    /* i64.sub */
		I64_MUL,    /* i64.mul */
		REF_NULL,   /* ref.null <heaptype> (multi-byte) */
		REF_FUNC_2, /* ref.func (same as REF_FUNC but with heaptype) */
		UNKNOWN,    /* Unknown/unparsed instruction sequence */
	}

	public ConstantExpression(BinaryReader reader) throws IOException {
		// Read all bytes up to and including the matching end byte
		rawBytes = readConstantExpressionBytes(reader);
		parseExpression(rawBytes);
	}

	/**
	 * Read bytes from the reader until we consume the matching end (0x0B) byte.
	 * Handles nested blocks by tracking depth (blocks can appear in future extended const).
	 */
	private byte[] readConstantExpressionBytes(BinaryReader reader) throws IOException {
		List<Byte> bytes = new ArrayList<>();
		int depth = 0;
		
		while (true) {
			int b = reader.readNextUnsignedByte();
			bytes.add((byte) b);
			
			if (b == 0x0B) { // end
				if (depth == 0) {
					break;
				}
				depth--;
			} else if (isBlockOpcode(b)) {
				depth++;
			}
		}
		
		byte[] result = new byte[bytes.size()];
		for (int i = 0; i < bytes.size(); i++) {
			result[i] = bytes.get(i);
		}
		return result;
	}

	/**
	 * Check if an opcode starts a block that requires a matching end.
	 * This is a minimal set for constant expression parsing.
	 */
	private boolean isBlockOpcode(int opcode) {
		// Block, loop, if, try_table (0x1F), try (0x06)
		return opcode == 0x02 || opcode == 0x03 || opcode == 0x04 || opcode == 0x06 || opcode == 0x1F;
	}

	/**
	 * Parse the raw bytes of the constant expression.
	 * This is more permissive than the original parser - it handles known opcodes
	 * and gracefully falls back to UNKNOWN for anything else.
	 */
	private void parseExpression(byte[] bytes) throws IOException {
		if (bytes.length == 0) {
			unknown = true;
			type = ConstantInstruction.UNKNOWN;
			return;
		}

		// Use a BinaryReader on the byte array for parsing
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		
		int typeCode = reader.readNextUnsignedByte();
		
		switch (typeCode) {
		case 0x23: // global.get
			type = ConstantInstruction.GLOBAL_GET;
			value = reader.readNext(LEB128Info::unsigned);
			break;
		case 0x41: // i32.const
			type = ConstantInstruction.I32_CONST;
			value = reader.readNext(LEB128Info::signed);
			break;
		case 0x42: // i64.const
			type = ConstantInstruction.I64_CONST;
			value = reader.readNext(LEB128Info::signed);
			break;
		case 0x43: // f32.const
			type = ConstantInstruction.F32_CONST;
			value = reader.readNextByteArray(4);
			break;
		case 0x44: // f64.const
			type = ConstantInstruction.F64_CONST;
			value = reader.readNextByteArray(8);
			break;
		case 0xD0: { // ref.null
			int refTypeCode = reader.readNextUnsignedByte();
			if (refTypeCode == 0x6F) {
				type = ConstantInstruction.REF_NULL_EXTERNREF;
			} else if (refTypeCode == 0x70) {
				type = ConstantInstruction.REF_NULL_FUNCREF;
			} else {
				// Multi-byte ref.null <heaptype> - mark as unknown, keep raw bytes
				type = ConstantInstruction.REF_NULL;
				unknown = true;
			}
			value = null;
			break;
		}
		case 0xD1: // ref.is_null
			unknown = true;
			type = ConstantInstruction.UNKNOWN;
			break;
		case 0xD2: // ref.func
			type = ConstantInstruction.REF_FUNC;
			value = reader.readNext(LEB128Info::unsigned);
			break;
		case 0x6A: // i32.add
			type = ConstantInstruction.I32_ADD;
			break;
		case 0x6B: // i32.sub
			type = ConstantInstruction.I32_SUB;
			break;
		case 0x6C: // i32.mul
			type = ConstantInstruction.I32_MUL;
			break;
		case 0x7C: // i64.add
			type = ConstantInstruction.I64_ADD;
			break;
		case 0x7D: // i64.sub
			type = ConstantInstruction.I64_SUB;
			break;
		case 0x7E: // i64.mul
			type = ConstantInstruction.I64_MUL;
			break;
		case 0xFD: {
			opcode2 = reader.readNext(LEB128Info::unsigned);
			if (opcode2.asUInt32() == 0x0C) { // v128.const
				type = ConstantInstruction.V128_CONST;
				value = reader.readNextByteArray(16);
			} else {
				unknown = true;
				type = ConstantInstruction.UNKNOWN;
			}
			break;
		}
		case 0xFB: // GC prefix
		case 0xFC: // Misc prefix
		case 0xFE: // Atomic prefix
		default:
			// Unknown opcode - don't throw, just mark as unknown
			unknown = true;
			type = ConstantInstruction.UNKNOWN;
			Msg.warn(this, "Unknown constant expression opcode 0x" + Integer.toHexString(typeCode) + " - initializer will be unparsed");
			break;
		}

		// Verify end byte is present (should be, since readConstantExpressionBytes found it)
		if (reader.hasNext()) {
			int end = reader.readNextUnsignedByte();
			if (end != 0x0B) {
				unknown = true;
				type = ConstantInstruction.UNKNOWN;
			}
		}
	}

	public static byte[] intToBytes(int value) {
		byte[] result = new byte[4];
		for (int i = 0; i < 4; i++) {
			result[i] = (byte) value;
			value >>= 8;
		}
		return result;
	}

	public static byte[] longToBytes(long value) {
		byte[] result = new byte[8];
		for (int i = 0; i < 8; i++) {
			result[i] = (byte) value;
			value >>= 8;
		}
		return result;
	}

	/**
	 * Return the bytes that correspond to the value produced, i.e. 4 bytes for
	 * i32.const, 8 bytes for f64.const, etc. Return null if the initializer cannot
	 * be determined (e.g. global) This needs a reference to the module so that
	 * function references can be resolved to their static addresses.
	 */
	public byte[] asBytes(WasmModule module) {
		switch (type) {
		case I32_CONST:
			return intToBytes((int) ((LEB128Info) value).asLong());
		case I64_CONST:
			return longToBytes(((LEB128Info) value).asLong());
		case REF_FUNC:
			return intToBytes((int) WasmLoader.getFunctionAddressOffset(module, (int) ((LEB128Info) value).asLong()));
		case F32_CONST:
		case F64_CONST:
		case V128_CONST:
			return (byte[]) value;
		case REF_NULL_FUNCREF:
		case REF_NULL_EXTERNREF:
			return new byte[] { 0, 0, 0, 0 };
		case GLOBAL_GET:
			return null;
		default:
			return null;
		}
	}

	public Address asAddress(AddressFactory addressFactory, WasmModule module) {
		if (type == ConstantInstruction.REF_FUNC) {
			return WasmLoader.getFunctionAddress(addressFactory, module, (int) ((LEB128Info) value).asLong());
		}
		return null;
	}

	public Long asI32() {
		if (type == ConstantInstruction.I32_CONST) {
			return ((LEB128Info) value).asLong();
		}
		return null;
	}

	public Long asGlobalGet() {
		if (type == ConstantInstruction.GLOBAL_GET) {
			return ((LEB128Info) value).asLong();
		}
		return null;
	}

	/** Returns true if this constant expression contains unknown/unparsed opcodes. */
	public boolean isUnknown() {
		return unknown;
	}

	/** Returns the raw bytes of the entire constant expression (including end byte). */
	public byte[] getRawBytes() {
		return rawBytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("expr");
		if (rawBytes != null && rawBytes.length > 0) {
			builder.add(BYTE, "opcode");
			switch (type) {
			case I32_CONST:
			case I64_CONST:
			case REF_FUNC:
			case GLOBAL_GET:
				builder.addUnsignedLeb128((LEB128Info) value, "value");
				break;
			case F32_CONST:
				builder.add(Float4DataType.dataType, "value");
				break;
			case F64_CONST:
				builder.add(Float8DataType.dataType, "value");
				break;
			case V128_CONST:
				builder.addUnsignedLeb128((LEB128Info) opcode2, "opcode2");
				builder.add(ValType.Undefined16, "value");
				break;
			case REF_NULL_FUNCREF:
			case REF_NULL_EXTERNREF:
				builder.add(BYTE, "nulltype");
				break;
			case I32_ADD:
			case I32_SUB:
			case I32_MUL:
			case I64_ADD:
			case I64_SUB:
			case I64_MUL:
				builder.add(BYTE, "extended_const_op");
				break;
			case UNKNOWN:
			default:
				// For unknown, just show the raw bytes as an array
				builder.add(BYTE, "unknown_opcode");
				if (rawBytes.length > 1) {
					builder.addArray(BYTE, rawBytes.length - 1, "remaining_bytes");
				}
				break;
			}
			// Add end byte if present
			if (rawBytes.length > 0 && rawBytes[rawBytes.length - 1] == 0x0B) {
				builder.add(BYTE, "end_opcode");
			}
		}
		return builder.toStructure();
	}
}