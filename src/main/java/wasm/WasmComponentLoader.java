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
package wasm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import wasm.format.WasmConstants;

/**
 * Loader for WebAssembly component-model binaries.
 * <p>
 * A component binary is discriminated from a core module by its 8-byte preamble
 * ({@code \0asm} + version + layer): core modules use version {@code 0x01} / layer {@code 0x00},
 * components use version {@code 0x0d} (pre-standard) / layer {@code 0x01}.
 * <p>
 * Component sections have the same framing as core-module sections
 * ({@code id:u8} followed by {@code size:u32 LEB128} and the payload); the only difference is the
 * section-id space. Section id {@code 1} is a {@code core:module} section whose payload is a
 * <em>complete</em> core module binary (including its own {@code \0asm} + version-1 preamble).
 * <p>
 * This loader locates the embedded core modules, reports how many it found, and then loads the
 * <em>first</em> one as a real program by handing the corresponding sub-range of the file to the
 * existing {@link WasmLoader} (through a {@link ByteProviderWrapper}). The resulting program
 * therefore contains the nested module's memory/table/function blocks and is analyzed exactly like
 * a standalone core module.
 * <p>
 * Payloads are always skipped using the declared section size, so a nested module's own sections
 * (whose id {@code 1} is the nested type section) are never mistaken for component sections.
 * <p>
 * Not supported (yet): nested components (section id 4), component-level index spaces, canonical
 * definitions, cross-module instantiation, and loading any module other than the first one found.
 */
public class WasmComponentLoader extends AbstractLibrarySupportLoader {

	public final static String WEBASSEMBLY = "WebAssembly";

	/** Size of the component preamble: magic(4) + version(2) + layer(2). */
	private static final long COMPONENT_HEADER_SIZE = 8;
	/** Component version (bytes 0x0d 0x00) and layer (bytes 0x01 0x00) - pre-standard. */
	private static final int COMPONENT_VERSION = 0x0d;
	private static final int COMPONENT_LAYER = 0x01;
	/** Component section id whose payload is a complete core module (core:module). */
	private static final int CORE_MODULE_SECTION_ID = 1;
	/** Size of a core-module preamble: magic(4) + version(4). */
	private static final long CORE_HEADER_SIZE = 8;
	/** Language / compiler spec used for the extracted core module. */
	private static final String WASM_LANGUAGE = "Wasm:LE:32:default";

	/** One embedded core module located inside the component. */
	private static final class CoreModule {
		/** 0-based index among the core-module sections, in file order. */
		final int index;
		/** 0-based index among all component sections, in file order. */
		final int sectionIndex;
		/** File offset of the module's first byte (its own {@code \0asm} magic). */
		final long offset;
		/** Module length in bytes, from the enclosing section's declared size. */
		final long size;

		CoreModule(int index, int sectionIndex, long offset, long size) {
			this.index = index;
			this.sectionIndex = sectionIndex;
			this.offset = offset;
			this.size = size;
		}
	}

	/** Thrown when a section header or payload runs past the end of the file. */
	private static final class TruncatedComponentException extends IOException {
		TruncatedComponentException(String message) {
			super(message);
		}
	}

	@Override
	public String getName() {
		return WEBASSEMBLY;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!isComponentBinary(provider)) {
			return Collections.emptyList();
		}

		List<CoreModule> modules = findCoreModules(provider);
		if (modules.isEmpty()) {
			Msg.info(this, "WasmComponentLoader: component header detected but no core module "
				+ "sections (section id 1) found in the binary; no load spec offered.");
			return Collections.emptyList();
		}

		Msg.info(this, "WasmComponentLoader: component detected (" + describeHeader(provider) + "); "
			+ "found " + modules.size() + " core module section(s).");

		/*
		 * Only one LoadSpec is offered even when the component contains several modules: this loader
		 * always loads the first module, so offering one entry per module would create duplicate,
		 * indistinguishable import options.
		 */
		List<LoadSpec> loadSpecs = new ArrayList<>();
		loadSpecs.add(new LoadSpec(this, WasmLoader.CODE_BASE,
			new LanguageCompilerSpecPair(WASM_LANGUAGE, "default"), true));
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		settings.monitor().setMessage("Wasm component: locating embedded core module");

		ByteProvider provider = settings.provider();
		List<CoreModule> modules;
		try {
			modules = findCoreModules(provider);
		}
		catch (Exception e) {
			Msg.error(this, "WasmComponentLoader: failed to parse component sections", e);
			return;
		}

		if (modules.isEmpty()) {
			Msg.info(this, "WasmComponentLoader: no core module sections found; nothing to load.");
			return;
		}

		CoreModule module = modules.get(0);
		Msg.info(this, "WasmComponentLoader: loading core module index " + module.index + " of "
			+ modules.size() + " (component section " + module.sectionIndex + ", file offset 0x"
			+ Long.toHexString(module.offset) + ", size " + module.size + " bytes) through "
			+ WasmLoader.class.getSimpleName() + ".");

		/*
		 * Hand the extracted module to the core-module loader. ByteProviderWrapper maps the
		 * sub-range [offset, offset+size) onto offset 0, so WasmLoader sees a self-contained core
		 * module: it creates the ".module" block from these bytes and the analyzers
		 * (WasmAnalysis) re-read that block, so the nested module's functions are disassembled.
		 */
		ByteProvider moduleProvider = new ByteProviderWrapper(provider, module.offset, module.size);
		ImporterSettings moduleSettings = new ImporterSettings(moduleProvider, settings.importName(),
			settings.project(), settings.projectRootPath(), settings.mirrorFsLayout(),
			settings.loadSpec(), settings.options(), settings.consumer(), settings.log(),
			settings.monitor());

		new WasmLoader().load(program, moduleSettings);
	}

	/**
	 * True if the file starts with a WebAssembly preamble that is <em>not</em> a core module
	 * (i.e. version != 1). The 8-byte header is magic(4) + version(2, LE) + layer(2, LE).
	 */
	private static boolean isComponentBinary(ByteProvider provider) throws IOException {
		if (provider.length() < COMPONENT_HEADER_SIZE) {
			return false;
		}
		byte[] magic = provider.readBytes(0, WasmConstants.WASM_MAGIC.length);
		if (!Arrays.equals(magic, WasmConstants.WASM_MAGIC)) {
			return false;
		}
		/*
		 * A core module is magic + version(4 bytes, LE) == 1, i.e. 01 00 00 00. Reinterpreting those
		 * 4 bytes as version(2)+layer(2) gives version 1, layer 0. Anything else with the magic is
		 * treated as a component-model candidate (version 0x0d / layer 0x01 today).
		 */
		long raw = (provider.readByte(4) & 0xFFL) | ((provider.readByte(5) & 0xFFL) << 8)
			| ((provider.readByte(6) & 0xFFL) << 16) | ((provider.readByte(7) & 0xFFL) << 24);
		long canonicalComponent = ((long) COMPONENT_VERSION) | (((long) COMPONENT_LAYER) << 16);
		return raw == canonicalComponent || raw != WasmConstants.WASM_VERSION;
	}

	private String describeHeader(ByteProvider provider) throws IOException {
		int version = (provider.readByte(4) & 0xFF) | ((provider.readByte(5) & 0xFF) << 8);
		int layer = (provider.readByte(6) & 0xFF) | ((provider.readByte(7) & 0xFF) << 8);
		return String.format("version=0x%04x, layer=0x%04x", version, layer);
	}

	/**
	 * Walk the component's sections and return the embedded core modules in file order.
	 * <p>
	 * Framing is {@code id:u8}, {@code size:u32 LEB128}, then {@code size} payload bytes. The
	 * payload is skipped using the declared size, so nothing inside a payload is ever re-scanned.
	 * A bare header (no sections) yields an empty list; a truncated file yields the modules found
	 * before the truncation and an informational message.
	 */
	private List<CoreModule> findCoreModules(ByteProvider provider) throws IOException {
		List<CoreModule> modules = new ArrayList<>();
		long length = provider.length();
		if (length < COMPONENT_HEADER_SIZE) {
			Msg.info(this, "WasmComponentLoader: file is too short for a component header ("
				+ length + " bytes).");
			return modules;
		}

		long pos = COMPONENT_HEADER_SIZE;
		int sectionIndex = 0;
		while (pos < length) {
			long sectionStart = pos;
			int sectionId = provider.readByte(pos) & 0xFF;
			pos++;

			long size;
			try {
				long[] leb = readUnsignedLeb128(provider, pos, length);
				size = leb[0];
				pos = leb[1];
			}
			catch (TruncatedComponentException e) {
				Msg.info(this, "WasmComponentLoader: truncated component: section " + sectionIndex
					+ " at file offset 0x" + Long.toHexString(sectionStart)
					+ " has no complete size field; stopped parsing.");
				break;
			}

			long payloadStart = pos;
			if (size < 0 || payloadStart + size > length) {
				Msg.info(this, "WasmComponentLoader: truncated component: section " + sectionIndex
					+ " (id " + sectionId + ") at file offset 0x" + Long.toHexString(sectionStart)
					+ " declares " + size + " payload byte(s) but only " + (length - payloadStart)
					+ " remain; stopped parsing.");
				break;
			}

			if (sectionId == CORE_MODULE_SECTION_ID) {
				if (isCoreModule(provider, payloadStart, size)) {
					modules.add(new CoreModule(modules.size(), sectionIndex, payloadStart, size));
				}
				else {
					Msg.info(this, "WasmComponentLoader: component section " + sectionIndex
						+ " (id 1) at file offset 0x" + Long.toHexString(sectionStart)
						+ " is not a core module (no \\0asm + version 1 preamble); skipped.");
				}
			}

			/* Skip the whole payload: this is what keeps nested section ids from being re-read. */
			pos = payloadStart + size;
			sectionIndex++;
		}
		return modules;
	}

	/** True if the payload at [offset, offset+size) is a complete core module (magic + version 1). */
	private static boolean isCoreModule(ByteProvider provider, long offset, long size)
			throws IOException {
		if (size < CORE_HEADER_SIZE) {
			return false;
		}
		byte[] magic = provider.readBytes(offset, WasmConstants.WASM_MAGIC.length);
		if (!Arrays.equals(magic, WasmConstants.WASM_MAGIC)) {
			return false;
		}
		long version = (provider.readByte(offset + 4) & 0xFFL)
			| ((provider.readByte(offset + 5) & 0xFFL) << 8)
			| ((provider.readByte(offset + 6) & 0xFFL) << 16)
			| ((provider.readByte(offset + 7) & 0xFFL) << 24);
		return version == WasmConstants.WASM_VERSION;
	}

	/**
	 * Read an unsigned LEB128 u32 at {@code pos}.
	 * @return {@code [value, indexAfterValue]}
	 */
	private static long[] readUnsignedLeb128(ByteProvider provider, long pos, long end)
			throws IOException {
		long result = 0;
		int shift = 0;
		long cur = pos;
		while (true) {
			if (cur >= end) {
				throw new TruncatedComponentException("unexpected end of file at 0x"
					+ Long.toHexString(cur));
			}
			int b = provider.readByte(cur) & 0xFF;
			cur++;
			if (shift < 32) {
				result |= (long) (b & 0x7F) << shift;
			}
			if ((b & 0x80) == 0) {
				break;
			}
			shift += 7;
			if (shift > 35) {
				throw new IOException("LEB128 value too long at 0x" + Long.toHexString(pos));
			}
		}
		return new long[] { result, cur };
	}
}
