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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf.DWARFImporter;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine.SourceFileAddr;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine.SourceFileInfo;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.util.Msg;
import ghidra.util.SourceFileUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;

/**
 * WebAssembly-aware wrapper around Ghidra's {@link DWARFAnalyzer}.
 * <p>
 * Type/signature import is delegated to the stock analyzer, but the DWARF
 * <i>function</i> importer stays disabled: its location expressions describe
 * wasm-native locals/frames and place variables at bogus addresses.
 * <p>
 * Source line information is imported by this class instead of by the base
 * analyzer, because it needs a wasm-specific address fixup (see
 * {@link #candidateFixups}). The line table of a wasm module stores code
 * addresses as offsets relative to the start of the code section's contents -
 * not as program addresses - so feeding them straight to
 * {@link DWARFProgram#getCodeAddress(long)} produces offsets like {@code 0x2}
 * (outside every memory block) or, when a fixup is guessed wrong, 33-bit values
 * that overflow the 32-bit {@code ram} space and make {@code getCodeAddress}
 * throw {@code AddressOutOfBoundsException}.
 */
public class WasmDWARFAnalyzer extends DWARFAnalyzer {

	/** Same cap Ghidra's own DWARFLineInfoSourceMapScript uses for a line's range. */
	private static final int MAX_ENTRY_LENGTH = 1000;

	/** Limit the number of identical debug/warning messages emitted. */
	private static final int MAX_MESSAGES = 25;

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();

		if (WasmLoader.WEBASSEMBLY.equals(format)
				&& DWARFSectionProviderFactory.createSectionProviderFor(program, TaskMonitor.DUMMY) != null) {
			return true;
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		/*
		 * Import DWARF data types (structs, typedefs, enums) but not functions.
		 * The DWARF function importer resolves variable/parameter locations via
		 * DWARF location expressions that reference wasm-native locals and frame
		 * bases; these do not translate to this plugin's ram/register layout, so
		 * it places variables at invalid addresses (ram:ffffffff) and corrupts
		 * decompiled bodies. Types alone are location-independent and safe, and
		 * give us the original struct layouts for the decompiler.
		 *
		 * Source line info is left disabled for the built-in pass and handled by
		 * importSourceLineInfo() below, which supplies the address fixup the wasm
		 * line table needs.
		 */
		try {
			Field f = DWARFAnalyzer.class.getDeclaredField("importOptions");
			f.setAccessible(true);
			DWARFImportOptions opts = (DWARFImportOptions) f.get(this);
			if (opts != null) {
				opts.setImportDataTypes(true);
				opts.setImportFuncs(false);
				opts.setOutputSourceLineInfo(false);
			}
		} catch (Exception e) {
			Msg.warn(this, "Could not constrain DWARF import options: " + e);
		}

		/*
		 * Re-running the analyzer on an already-imported program would duplicate
		 * source files / source map entries, so remember the state before the
		 * delegated call and only add line info for a fresh import.
		 */
		boolean alreadyImported = isAlreadyImported(program);
		boolean result = super.added(program, set, monitor, log);

		if (!alreadyImported) {
			try {
				importSourceLineInfo(program, monitor, log);
			}
			catch (CancelledException ce) {
				throw ce;
			}
			catch (Exception e) {
				Msg.error(this, "DWARF source line info import failed", e);
				log.appendMsg("DWARF source line info import failed: " + e);
			}
		}
		return result;
	}

	/**
	 * Reads the wasm DWARF line tables and populates the program's source map.
	 * <p>
	 * The addresses found in the line table are code-section-relative; the
	 * correct program address is obtained by adding a base-address fixup to
	 * every offset before it is turned into an {@link Address}. Which fixup is
	 * correct depends on how the producer encoded the addresses, so a small set
	 * of candidates is tried (see {@link #candidateFixups}) and the first one
	 * that yields at least one executable source entry wins.
	 *
	 * @param program program being analyzed
	 * @param monitor task monitor
	 * @param log import message log
	 * @throws Exception on unexpected failure
	 */
	private void importSourceLineInfo(Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		if (!program.hasExclusiveAccess()) {
			log.appendMsg("WASM DWARF: skipping source line info (program lacks exclusive access)");
			return;
		}

		DWARFSectionProvider dsp =
			DWARFSectionProviderFactory.createSectionProviderFor(program, monitor);
		if (dsp == null) {
			return;
		}

		DWARFImportOptions options = new DWARFImportOptions();
		try (DWARFProgram dprog = new DWARFProgram(program, options, dsp)) {
			dprog.init(monitor);

			List<SourceFileAddr> sourceInfo = new ArrayList<>();
			Map<SourceFileInfo, SourceFile> fileMap = new HashMap<>();
			Set<SourceFileInfo> badFiles = new HashSet<>();
			readSourceInfo(dprog, program, monitor, sourceInfo, fileMap, badFiles);

			if (sourceInfo.isEmpty()) {
				log.appendMsg("WASM DWARF: no source line information found");
				return;
			}

			int added = 0;
			for (long fixup : candidateFixups(program)) {
				dprog.setProgramBaseAddressFixup(fixup);
				added = applySourceInfo(dprog, program, monitor, sourceInfo, fileMap, badFiles);
				String message = "WASM DWARF: base-address fixup 0x%x produced %d source map %s"
						.formatted(fixup, added, added == 1 ? "entry" : "entries");
				Msg.info(this, message);
				log.appendMsg(message);
				if (added > 0) {
					break;
				}
			}
			if (added == 0) {
				Msg.warn(this, "WASM DWARF: no source line entries could be mapped to the program");
			}
		}
	}

	/**
	 * Registers every source file mentioned by the line tables and collects all
	 * line rows (address, file, line).
	 */
	private void readSourceInfo(DWARFProgram dprog, Program program, TaskMonitor monitor,
			List<SourceFileAddr> sourceInfo, Map<SourceFileInfo, SourceFile> fileMap,
			Set<SourceFileInfo> badFiles) throws Exception {
		SourceFileManager sourceManager = program.getSourceFileManager();
		List<DWARFCompilationUnit> compUnits = dprog.getCompilationUnits();
		monitor.initialize(compUnits.size(), "DWARF: reading wasm source information");
		for (DWARFCompilationUnit cu : compUnits) {
			monitor.checkCancelled();
			monitor.increment();
			try {
				DWARFLine line = cu.getLine();
				for (SourceFileInfo sfi : line.getAllSourceFileInfos()) {
					if (fileMap.containsKey(sfi) || badFiles.contains(sfi)) {
						continue;
					}
					try {
						String path = SourceFileUtils.normalizeDwarfPath(sfi.filePath(),
							DWARFImporter.DEFAULT_COMPILATION_DIR);
						SourceFileIdType type =
							sfi.md5() == null ? SourceFileIdType.NONE : SourceFileIdType.MD5;
						SourceFile sourceFile = new SourceFile(path, type, sfi.md5());
						sourceManager.addSourceFile(sourceFile);
						fileMap.put(sfi, sourceFile);
					}
					catch (IllegalArgumentException e) {
						badFiles.add(sfi);
					}
				}
				sourceInfo.addAll(line.getAllSourceFileAddrInfo(cu));
			}
			catch (java.io.IOException e) {
				Msg.debug(this, "DWARF: failed to read line info for CU %d: %s"
						.formatted(cu.getUnitNumber(), e));
			}
		}
	}

	/**
	 * Applies the collected line rows using the fixup currently set on
	 * {@code dprog}, skipping rows that do not map onto executable memory.
	 *
	 * @return number of source map entries actually created
	 */
	private int applySourceInfo(DWARFProgram dprog, Program program, TaskMonitor monitor,
			List<SourceFileAddr> sourceInfo, Map<SourceFileInfo, SourceFile> fileMap,
			Set<SourceFileInfo> badFiles) throws Exception {
		SourceFileManager sourceManager = program.getSourceFileManager();
		AddressSetView executeSet = program.getMemory().getExecuteSet();
		AddressSet warned = new AddressSet();

		List<SourceFileAddr> sorted = new ArrayList<>(sourceInfo);
		sorted.sort((a, b) -> Long.compareUnsigned(a.address(), b.address()));

		int errors = 0;
		int added = 0;
		int outOfRange = 0;
		int nonExec = 0;
		monitor.initialize(sorted.size(), "DWARF: applying wasm source map info");
		for (int i = 0; i < sorted.size(); i++) {
			monitor.checkCancelled();
			monitor.increment();
			SourceFileAddr sfa = sorted.get(i);
			if (sfa.isEndSequence() || sfa.fileName() == null) {
				continue;
			}
			SourceFileInfo sfi = new SourceFileInfo(sfa.fileName(), sfa.md5());
			if (badFiles.contains(sfi)) {
				continue;
			}

			Address addr;
			try {
				addr = dprog.getCodeAddress(sfa.address());
			}
			catch (RuntimeException e) {
				/*
				 * AddressOutOfBoundsException for garbage offsets (for example the
				 * unresolved 0xffffffff entries that wasm-ld leaves behind for
				 * garbage-collected core functions), or a 33-bit value that
				 * overflows the 32-bit ram space.
				 */
				outOfRange++;
				if (outOfRange <= MAX_MESSAGES) {
					Msg.debug(this, "DWARF: skipping out-of-range source address 0x%x: %s"
							.formatted(sfa.address(), e));
				}
				continue;
			}

			if (warned.contains(addr)) {
				continue;
			}
			if (!executeSet.contains(addr)) {
				nonExec++;
				if (nonExec <= MAX_MESSAGES) {
					Msg.debug(this, "DWARF: source entry for non-executable address %s (raw 0x%x)"
							.formatted(addr, sfa.address()));
				}
				warned.add(addr);
				continue;
			}

			long length = getLength(sorted, i);
			if (length < 0 || length > MAX_ENTRY_LENGTH) {
				length = 0;
			}

			SourceFile source = fileMap.get(sfi);
			if (source == null) {
				continue;
			}
			try {
				sourceManager.addSourceMapEntry(source, sfa.lineNum(), addr, length);
			}
			catch (Exception e) {
				if (errors++ < MAX_MESSAGES) {
					Msg.debug(this, "DWARF: source map entry rejected for %s: %s"
							.formatted(addr, e));
				}
				continue;
			}
			added++;
		}
		Msg.info(this, "WASM DWARF: fixup 0x%x: %d entries, %d out-of-range, %d non-executable, %d rejected"
				.formatted(dprog.getProgramBaseAddressFixup(), added, outOfRange, nonExec, errors));
		return added;
	}

	/**
	 * Length (in bytes) of the source line that starts at {@code all.get(i)},
	 * i.e. the distance to the next distinct address or the end of the sequence.
	 * Mirrors {@code DWARFLineInfoSourceMapScript.getLength}.
	 */
	private long getLength(List<SourceFileAddr> all, int i) {
		long start = all.get(i).address();
		for (int j = i + 1; j < all.size(); j++) {
			SourceFileAddr current = all.get(j);
			if (current.isEndSequence()) {
				return current.address() + 1 - start;
			}
			if (current.address() != start) {
				return current.address() - start;
			}
		}
		return -1;
	}

	/**
	 * Base-address fixups to try, in order.
	 * <p>
	 * For LLVM/rustc wasm modules the DWARF line table addresses are offsets
	 * from the start of the code section's contents, so the fixup must be
	 * {@code CODE_BASE + codeSectionContentOffset}. A producer that instead
	 * emitted module-file offsets needs only {@code CODE_BASE}; we keep that as
	 * a fallback.
	 */
	private long[] candidateFixups(Program program) {
		long contentOffset = getCodeSectionContentOffset(program);
		if (contentOffset > 0) {
			return new long[] { WasmLoader.CODE_BASE + contentOffset, WasmLoader.CODE_BASE };
		}
		return new long[] { WasmLoader.CODE_BASE };
	}

	/**
	 * File offset at which the code section's contents begin (i.e. the byte
	 * holding the function count). The wasm line table's address column is
	 * relative to this position.
	 */
	private long getCodeSectionContentOffset(Program program) {
		try {
			WasmModule module = WasmAnalysis.getState(program).getModule();
			WasmSection codeSection = module.getSection(WasmSectionId.SEC_CODE);
			if (codeSection != null) {
				return codeSection.getSectionOffset() + codeSection.getSectionSize()
						- codeSection.getContentSize();
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Could not determine wasm code-section offset: " + e);
		}
		return 0;
	}
}
