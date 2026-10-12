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
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import wasm.WasmLoader;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;

/* A reader for initializer expressions (globals, data segment offsets, element segments).

When the constant-expression proposal (extended-const) was merged, an expression can contain several
instructions, so the expression has to be *decoded* to know where it ends: scanning bytes for the
next 0x0B is not enough, because any immediate (e.g. the value byte of `i32.const 2`, or the bytes of
an `f32.const`) can be 0x0B.

This class decodes the instruction sequence:
  * known opcodes are decoded exactly (immediates included), so the position after the expression is
    always correct;
  * `i32.const`/`i64.const` chains combined with the extended-const operators are folded to a value;
  * when an opcode is not understood the decoder switches (flagged) to a best-effort scan for the
    terminating `end`, so that an unsupported initializer degrades to "unparsed" instead of aborting
    the whole import.
*/
public final class ConstantExpression implements StructConverter {

	private ConstantInstruction type;
	private LEB128Info opcode2;
	private Object value;
	private byte[] rawBytes; // Raw bytes of the entire expression (including the end byte)
	private boolean unknown = false; // True if the initializer contains unparsed/unknown opcodes
	private boolean folded = false; // True if the value was produced by folding an extended-const chain

	private enum ConstantInstruction {
		I32_CONST, /* i32.const n: value is LEB128 */
		I64_CONST, /* i64.const n: value is LEB128 */
		F32_CONST, /* f32.const n: value is 4 bytes */
		F64_CONST, /* f64.const n: value is 8 bytes */
		V128_CONST, /* v128.const: opcode2 is 0xFD prefix, value is 16 bytes */
		REF_NULL_FUNCREF, /* ref.null func: value is null */
		REF_NULL_EXTERNREF, /* ref.null extern: value is null */
		REF_FUNC, /* ref.func x: value is LEB128 funcidx */
		GLOBAL_GET, /* global.get x: value is LEB128 globalidx */
		UNKNOWN /* anything else (kept as raw bytes) */
	}

	private static final byte[] EMPTY = new byte[0];

	/** One decoded instruction: the opcode byte plus its immediate operand bytes. */
	private static final class Inst {
		final int op;
		final byte[] imm;

		Inst(int op, byte[] imm) {
			this.op = op;
			this.imm = imm;
		}
	}

	/** Thrown when an opcode's operand length is not known; the scanner then falls back to a scan. */
	private static final class Undecodable extends Exception {
		private static final long serialVersionUID = 1L;
	}

	public ConstantExpression(BinaryReader reader) throws IOException {
		boolean[] wellFormed = new boolean[] { true };
		List<Inst> insts = readExpression(reader, wellFormed);
		rawBytes = flatten(insts);
		parseExpression(insts, wellFormed[0]);
	}

	/**
	 * Decode the instruction sequence up to and including the terminating `end` of the expression.
	 * The reader is left immediately after that byte.
	 */
	private List<Inst> readExpression(BinaryReader reader, boolean[] wellFormed) throws IOException {
		List<Inst> insts = new ArrayList<>();
		int depth = 0;
		boolean decoding = true;

		while (true) {
			int op = reader.readNextUnsignedByte();

			if (op == 0x0B) { /* end */
				insts.add(new Inst(op, EMPTY));
				if (depth == 0) {
					break;
				}
				depth--;
				continue;
			}

			if (!decoding) {
				/* best-effort mode: just look for the terminating end */
				insts.add(new Inst(op, EMPTY));
				continue;
			}

			byte[] imm;
			try {
				imm = readOperands(op, reader);
			}
			catch (Undecodable e) {
				wellFormed[0] = false;
				decoding = false;
				insts.add(new Inst(op, EMPTY));
				continue;
			}
			insts.add(new Inst(op, imm));

			switch (op) {
				case 0x02: /* block */
				case 0x03: /* loop */
				case 0x04: /* if */
				case 0x06: /* try (legacy EH) */
				case 0x1F: /* try_table */
					depth++;
					break;
				default:
					break;
			}
		}
		return insts;
	}

	/** Read the immediate operands of a single-opcode instruction. */
	private byte[] readOperands(int op, BinaryReader reader) throws IOException, Undecodable {
		switch (op) {
			case 0x00: /* unreachable */
			case 0x01: /* nop */
			case 0x05: /* else */
			case 0x19: /* catch_all */
			case 0x1A: /* drop */
			case 0x1B: /* select */
			case 0x6A: /* i32.add */
			case 0x6B: /* i32.sub */
			case 0x6C: /* i32.mul */
			case 0x7C: /* i64.add */
			case 0x7D: /* i64.sub */
			case 0x7E: /* i64.mul */
			case 0xD1: /* ref.is_null */
				return EMPTY;

			case 0x1C: { /* select t : valtype (may be a multi-byte reference type) */
				byte[] first = readFixed(reader, 1);
				int b = first[0] & 0xFF;
				if (b == 0x63 || b == 0x64) { /* (ref null <heaptype>) / (ref <heaptype>) */
					return concat(List.of(first, readSleb(reader)));
				}
				return first;
			}

			case 0x07: /* catch tagidx */
			case 0x08: /* throw tagidx */
			case 0x09: /* rethrow label */
			case 0x0C: /* br label */
			case 0x0D: /* br_if label */
			case 0x10: /* call funcidx */
			case 0x12: /* return_call funcidx */
			case 0x14: /* call_ref typeidx */
			case 0x18: /* delegate label */
			case 0x20: /* local.get */
			case 0x21: /* local.set */
			case 0x22: /* local.tee */
			case 0x23: /* global.get */
			case 0x24: /* global.set */
			case 0x25: /* table.get */
			case 0x26: /* table.set */
			case 0x3F: /* memory.size (memidx) */
			case 0x40: /* memory.grow (memidx) */
			case 0xD2: /* ref.func funcidx */
				return readUleb(reader);

			case 0x0E: { /* br_table: vec(label) + default */
				byte[] countBytes = readUleb(reader);
				int count = (int) decodeUleb(countBytes);
				List<byte[]> parts = new ArrayList<>();
				parts.add(countBytes);
				for (int i = 0; i <= count; i++) {
					parts.add(readUleb(reader));
				}
				return concat(parts);
			}

			case 0x11: /* call_indirect typeidx tableidx */
			case 0x13: /* return_call_indirect typeidx tableidx */
			{
				byte[] typeidx = readUleb(reader);
				byte[] tableidx = readUleb(reader);
				return concat(List.of(typeidx, tableidx));
			}

			case 0x02: /* block blocktype */
			case 0x03: /* loop blocktype */
			case 0x04: /* if blocktype */
			case 0x06: /* try blocktype */
				return readBlockType(reader);

			case 0x1F: { /* try_table blocktype vec(catch clause) */
				List<byte[]> parts = new ArrayList<>();
				parts.add(readBlockType(reader));
				byte[] countBytes = readUleb(reader);
				int count = (int) decodeUleb(countBytes);
				parts.add(countBytes);
				for (int i = 0; i < count; i++) {
					byte[] kind = readFixed(reader, 1);
					parts.add(kind);
					int k = kind[0] & 0xFF;
					if (k == 0x00 || k == 0x01) { /* catch/catch_ref tagidx label */
						parts.add(readUleb(reader));
						parts.add(readUleb(reader));
					}
					else if (k == 0x02 || k == 0x03) { /* catch_all/catch_all_ref label */
						parts.add(readUleb(reader));
					}
					else {
						throw new Undecodable();
					}
				}
				return concat(parts);
			}

			case 0x41: /* i32.const */
			case 0x42: /* i64.const */
			case 0xD0: /* ref.null heaptype */
				return readSleb(reader);

			case 0x43: /* f32.const */
				return readFixed(reader, 4);

			case 0x44: /* f64.const */
				return readFixed(reader, 8);

			case 0xFD: { /* SIMD prefix */
				byte[] sub = readUleb(reader);
				if (decodeUleb(sub) == 0x0C) { /* v128.const */
					return concat(List.of(sub, readFixed(reader, 16)));
				}
				throw new Undecodable();
			}

			case 0xFB: { /* GC prefix: only the simple initializer forms are decoded */
				byte[] sub = readUleb(reader);
				long subOp = decodeUleb(sub);
				switch ((int) subOp) {
					case 0x00: /* struct.new typeidx */
					case 0x01: /* struct.new_default typeidx */
					case 0x06: /* array.new typeidx */
					case 0x07: /* array.new_default typeidx */
					case 0x09: /* array.new_data typeidx dataidx */
					case 0x0A: /* array.new_elem typeidx elemidx */
					{
						byte[] typeidx = readUleb(reader);
						if (subOp == 0x09 || subOp == 0x0A) {
							return concat(List.of(sub, typeidx, readUleb(reader)));
						}
						return concat(List.of(sub, typeidx));
					}
					case 0x08: { /* array.new_fixed: typeidx + N field values, not decoded */
						throw new Undecodable();
					}
					case 0x14: /* ref.test heaptype */
					case 0x15: /* ref.test null heaptype */
					case 0x16: /* ref.cast heaptype */
					case 0x17: /* ref.cast null heaptype */
						return concat(List.of(sub, readSleb(reader)));
					case 0x1A: /* any.convert_extern */
					case 0x1B: /* extern.convert_any */
					case 0x1C: /* ref.i31 */
						return sub;
					default:
						throw new Undecodable();
				}
			}

			default:
				throw new Undecodable();
		}
	}

	private byte[] readBlockType(BinaryReader reader) throws IOException {
		/* blocktype is either a single value type byte or an s33 type index; both are LEB128, and
		   the reader is positioned on the first byte, so read it as a signed LEB. */
		return readSleb(reader);
	}

	private byte[] readUleb(BinaryReader reader) throws IOException {
		long offset = reader.getPointerIndex();
		LEB128Info info = reader.readNext(LEB128Info::unsigned);
		return reader.clone(offset).readNextByteArray(info.getLength());
	}

	private byte[] readSleb(BinaryReader reader) throws IOException {
		long offset = reader.getPointerIndex();
		LEB128Info info = reader.readNext(LEB128Info::signed);
		return reader.clone(offset).readNextByteArray(info.getLength());
	}

	private byte[] readFixed(BinaryReader reader, int length) throws IOException {
		return reader.readNextByteArray(length);
	}

	private static byte[] concat(List<byte[]> parts) {
		int length = 0;
		for (byte[] p : parts) {
			length += p.length;
		}
		byte[] result = new byte[length];
		int pos = 0;
		for (byte[] p : parts) {
			System.arraycopy(p, 0, result, pos, p.length);
			pos += p.length;
		}
		return result;
	}

	private static byte[] flatten(List<Inst> insts) {
		List<byte[]> parts = new ArrayList<>();
		for (Inst inst : insts) {
			parts.add(new byte[] { (byte) inst.op });
			if (inst.imm.length > 0) {
				parts.add(inst.imm);
			}
		}
		return concat(parts);
	}

	private static long decodeUleb(byte[] encoded) throws IOException {
		return new BinaryReader(new ByteArrayProvider(encoded), true).readNext(LEB128Info::unsigned)
				.asLong();
	}

	private static long decodeSleb(byte[] encoded) throws IOException {
		return new BinaryReader(new ByteArrayProvider(encoded), true)
				.readNext(LEB128Info::signed)
				.asLong();
	}

	/**
	 * Interpret the decoded instruction sequence: a single known instruction keeps its value, an
	 * `i32`/`i64` constants-plus-arithmetic chain is folded, everything else is kept as raw bytes.
	 */
	private void parseExpression(List<Inst> insts, boolean wellFormed) {
		if (insts.isEmpty()) {
			unknown = true;
			type = ConstantInstruction.UNKNOWN;
			return;
		}

		/* Drop the terminating `end` for the "body" of the expression. */
		List<Inst> body = insts;
		if (!body.isEmpty() && body.get(body.size() - 1).op == 0x0B) {
			body = body.subList(0, body.size() - 1);
		}

		if (body.size() == 1) {
			Inst inst = body.get(0);
			try {
				if (parseSingleInstruction(inst)) {
					return;
				}
			}
			catch (IOException e) {
				/* fall through to unknown */
			}
		}
		else if (foldExtendedConst(body)) {
			return;
		}

		unknown = true;
		type = ConstantInstruction.UNKNOWN;
		if (wellFormed) {
			Msg.warn(this, "Unparsed constant expression (" + body.size() +
				" instructions) - initializer will be shown as raw bytes");
		}
		else {
			Msg.warn(this, "Unknown opcode in constant expression - initializer will be shown as " +
				"raw bytes");
		}
	}

	/** Fill in type/value for a single-instruction expression; false if it is not understood. */
	private boolean parseSingleInstruction(Inst inst) throws IOException {
		switch (inst.op) {
			case 0x23: /* global.get */
				type = ConstantInstruction.GLOBAL_GET;
				value = toLebInfo(inst.imm, false);
				return true;
			case 0x41: /* i32.const */
				type = ConstantInstruction.I32_CONST;
				value = toLebInfo(inst.imm, true);
				return true;
			case 0x42: /* i64.const */
				type = ConstantInstruction.I64_CONST;
				value = toLebInfo(inst.imm, true);
				return true;
			case 0x43: /* f32.const */
				type = ConstantInstruction.F32_CONST;
				value = inst.imm;
				return true;
			case 0x44: /* f64.const */
				type = ConstantInstruction.F64_CONST;
				value = inst.imm;
				return true;
			case 0xD0: { /* ref.null <heaptype> */
				if (inst.imm.length == 1 && inst.imm[0] == (byte) 0x6F) {
					type = ConstantInstruction.REF_NULL_EXTERNREF;
				}
				else if (inst.imm.length == 1 && inst.imm[0] == (byte) 0x70) {
					type = ConstantInstruction.REF_NULL_FUNCREF;
				}
				else {
					unknown = true;
					type = ConstantInstruction.UNKNOWN;
				}
				value = null;
				return true;
			}
			case 0xD2: /* ref.func */
				type = ConstantInstruction.REF_FUNC;
				value = toLebInfo(inst.imm, false);
				return true;
			case 0xFD: { /* v128.const */
				BinaryReader r = new BinaryReader(new ByteArrayProvider(inst.imm), true);
				opcode2 = r.readNext(LEB128Info::unsigned);
				if (opcode2.asUInt32() != 0x0C) {
					return false;
				}
				type = ConstantInstruction.V128_CONST;
				value = r.readNextByteArray(16);
				return true;
			}
			default:
				return false;
		}
	}

	/**
	 * Fold a chain of `i32.const`/`i64.const` values joined by the extended-const operators. The
	 * result is exposed as a normal const instruction so globals get the right initial bytes.
	 */
	private boolean foldExtendedConst(List<Inst> body) {
		List<Long> stack = new ArrayList<>();
		boolean saw64 = false;

		for (Inst inst : body) {
			try {
				switch (inst.op) {
					case 0x41: /* i32.const */
						stack.add(decodeSleb(inst.imm));
						break;
					case 0x42: /* i64.const */
						stack.add(decodeSleb(inst.imm));
						saw64 = true;
						break;
					case 0x6A: case 0x6B: case 0x6C: /* i32 add/sub/mul */
					case 0x7C: case 0x7D: case 0x7E: /* i64 add/sub/mul */
					{
						if (stack.size() < 2) {
							return false;
						}
						long b = stack.remove(stack.size() - 1);
						long a = stack.remove(stack.size() - 1);
						boolean wide = inst.op >= 0x7C;
						if (wide != saw64) {
							return false;
						}
						long result;
						switch (inst.op) {
							case 0x6A: case 0x7C:
								result = a + b;
								break;
							case 0x6B: case 0x7D:
								result = a - b;
								break;
							default:
								result = a * b;
								break;
						}
						if (!wide) {
							result = (int) result; /* wrap to 32 bits */
						}
						stack.add(result);
						break;
					}
					default:
						return false;
				}
			}
			catch (IOException e) {
				return false;
			}
		}

		if (stack.size() != 1) {
			return false;
		}

		boolean is64 = saw64;
		long result = stack.get(0);
		try {
			type = is64 ? ConstantInstruction.I64_CONST : ConstantInstruction.I32_CONST;
			/* synthesize the LEB encoding of the folded value (signed, like the source consts) */
			value = toLebInfo(encodeSleb(result), true);
			folded = true;
			unknown = false;
			Msg.trace(this, "Folded extended-const initializer to " + result);
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private static LEB128Info toLebInfo(byte[] encoded, boolean signed) throws IOException {
		BinaryReader r = new BinaryReader(new ByteArrayProvider(encoded), true);
		return signed ? r.readNext(LEB128Info::signed) : r.readNext(LEB128Info::unsigned);
	}

	private static byte[] encodeSleb(long value) {
		List<Byte> out = new ArrayList<>();
		long v = value;
		while (true) {
			int b = (int) (v & 0x7F);
			v >>= 7;
			if ((v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0)) {
				out.add((byte) b);
				break;
			}
			out.add((byte) (b | 0x80));
		}
		byte[] result = new byte[out.size()];
		for (int i = 0; i < out.size(); i++) {
			result[i] = out.get(i);
		}
		return result;
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

	/** Returns true if the value came from folding an extended-const arithmetic chain. */
	public boolean isFolded() {
		return folded;
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
			if (folded) {
				/* the original byte sequence is an expression, not a single instruction */
				if (rawBytes.length > 1) {
					builder.addArray(BYTE, rawBytes.length - 1, "extended_const_expr");
				}
			}
			else {
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
				case UNKNOWN:
				default:
					// For unknown, just show the raw bytes as an array
					if (rawBytes.length > 1) {
						builder.addArray(BYTE, rawBytes.length - 1, "remaining_bytes");
					}
					break;
				}
			}
			// Add end byte if present
			if (rawBytes.length > 0 && rawBytes[rawBytes.length - 1] == 0x0B) {
				builder.add(BYTE, "end_opcode");
			}
		}
		return builder.toStructure();
	}
}
