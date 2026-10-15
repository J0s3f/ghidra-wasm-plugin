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

import java.util.Map;
import java.util.TreeMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmNameFieldSubsection;
import wasm.format.sections.structures.WasmNameLabelSubsection;
import wasm.format.sections.structures.WasmNameSubsection.WasmNameSubsectionId;

/**
 * @@NAME: apply the names in the WebAssembly {@code .name} custom section.
 * <p>
 * Function, global and local names are applied by {@link wasm.WasmLoader} and
 * {@link WasmFunctionVariableNameAnalyzer} respectively. This analyzer covers the
 * remaining name classes:
 * <ul>
 * <li>table / memory / element / data names -> a Ghidra label at the corresponding
 * block or segment address,</li>
 * <li>label names (subsection 3) -> a real Ghidra label at the address the label branches
 * to (the loop's start, otherwise the construct's {@code end}); a label name that cannot
 * be resolved to an address (unknown function, out-of-range label index, or a function
 * whose pre-analysis failed) falls back to a plate comment on the containing function,</li>
 * <li>type names (4), field names (10) and tag names (11) -> a comment on the module
 * block, because Ghidra data types for wasm function/struct types are not materialised
 * in the program's data type manager,</li>
 * <li>the module name (0) -> a comment on the module block (the program name is not
 * changed so that probe/fixture logs stay stable).</li>
 * </ul>
 * Existing user-defined symbols are never overwritten.
 */
public class WasmNameApplyAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Wasm name section applier";
	private static final String DESCRIPTION =
		"Apply module/type/table/memory/elem/data/field/tag/label names from the '.name' section as Ghidra symbols and comments.";

	private static final String TAG = "[.name] ";

	public WasmNameApplyAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public boolean added(Program program, ghidra.program.model.address.AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmModule module = state.getModule();
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection == null) {
			return true;
		}

		AddressFactory addressFactory = program.getAddressFactory();

		try {
			applyModuleComment(program, nameSection);
		}
		catch (Exception e) {
			Msg.error(this, "Failed to apply module name comment", e);
		}

		applyMapNames(program, module, nameSection, WasmNameSubsectionId.NAME_TABLE, "table", monitor);
		applyMapNames(program, module, nameSection, WasmNameSubsectionId.NAME_MEMORY, "memory", monitor);
		applyElemNames(program, module, nameSection, monitor);
		applyDataNames(program, module, nameSection, monitor);
		applyTypeFieldTagComment(program, nameSection, addressFactory, monitor);
		applyLabelNames(program, state, nameSection, monitor);

		return true;
	}

	/**
	 * Module/type/field/tag names have no address of their own. The module name and the
	 * type/field/tag name tables are recorded as comments on the module block (the
	 * "module structure"), which is what the listing shows to a user.
	 */
	private void applyModuleComment(Program program, WasmNameSection nameSection) {
		String moduleName = nameSection.getModuleName();
		if (moduleName == null || moduleName.isEmpty()) {
			return;
		}
		Address moduleAddress = WasmLoader.getModuleAddress(program.getAddressFactory());
		if (program.getMemory().getBlock(moduleAddress) == null) {
			return;
		}
		appendPlateComment(program, moduleAddress, "WebAssembly module name: " + moduleName);
	}

	private void applyTypeFieldTagComment(Program program, WasmNameSection nameSection,
			AddressFactory addressFactory, TaskMonitor monitor) {
		StringBuilder sb = new StringBuilder();
		appendNameMap(sb, "type", nameSection.getNameMap(WasmNameSubsectionId.NAME_TYPE));

		WasmNameFieldSubsection fieldSubsection = nameSection.getFieldSubsection();
		if (fieldSubsection != null) {
			for (Map.Entry<Long, Map<Long, String>> entry : fieldSubsection.getFieldNameMap().entrySet()) {
				for (Map.Entry<Long, String> field : entry.getValue().entrySet()) {
					if (sb.length() > 0) {
						sb.append(", ");
					}
					sb.append("field_").append(entry.getKey()).append('_').append(field.getKey())
						.append('=').append(field.getValue());
				}
			}
		}

		appendNameMap(sb, "tag", nameSection.getNameMap(WasmNameSubsectionId.NAME_TAG));
		if (sb.length() == 0) {
			return;
		}

		Address moduleAddress = WasmLoader.getModuleAddress(addressFactory);
		if (program.getMemory().getBlock(moduleAddress) == null) {
			return;
		}
		appendPlateComment(program, moduleAddress, "WebAssembly " + sb);
	}

	private static void appendNameMap(StringBuilder sb, String kind, Map<Long, String> map) {
		if (map == null || map.isEmpty()) {
			return;
		}
		for (Map.Entry<Long, String> entry : new TreeMap<>(map).entrySet()) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(kind).append(entry.getKey()).append('=').append(entry.getValue());
		}
	}

	/** table/memory names -> a label at the block start. */
	private void applyMapNames(Program program, WasmModule module, WasmNameSection nameSection, WasmNameSubsectionId id,
			String kind, TaskMonitor monitor) {
		Map<Long, String> map = nameSection.getNameMap(id);
		if (map == null || map.isEmpty()) {
			return;
		}
		AddressFactory addressFactory = program.getAddressFactory();
		for (Map.Entry<Long, String> entry : map.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			long idx = entry.getKey();
			if (idx < 0 || idx > Integer.MAX_VALUE) {
				continue;
			}
			Address address = kind.equals("table")
					? WasmLoader.getTableAddress(addressFactory, (int) idx, 0)
					: WasmLoader.getMemoryAddress(addressFactory, module, (int) idx, 0);
			applyLabel(program, address, entry.getValue(), kind + idx);
		}
	}

	/** element names -> a label at the segment's offset inside its table block. */
	private void applyElemNames(Program program, WasmModule module, WasmNameSection nameSection,
			TaskMonitor monitor) {
		Map<Long, String> map = nameSection.getNameMap(WasmNameSubsectionId.NAME_ELEM);
		if (map == null || map.isEmpty()) {
			return;
		}
		java.util.List<WasmElementSegment> segments = module.getElementSegments();
		AddressFactory addressFactory = program.getAddressFactory();
		for (Map.Entry<Long, String> entry : map.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			long idx = entry.getKey();
			if (idx < 0 || idx >= segments.size()) {
				continue;
			}
			WasmElementSegment segment = segments.get((int) idx);
			Long offset = segment.getOffset();
			if (offset == null) {
				continue;
			}
			int tableidx = (int) segment.getTableIndex();
			applyLabel(program, WasmLoader.getTableAddress(addressFactory, tableidx, offset),
				entry.getValue(), "elem" + idx);
		}
	}

	/** data names -> a label at the segment's offset inside its memory block. */
	private void applyDataNames(Program program, WasmModule module, WasmNameSection nameSection,
			TaskMonitor monitor) {
		Map<Long, String> map = nameSection.getNameMap(WasmNameSubsectionId.NAME_DATA);
		if (map == null || map.isEmpty()) {
			return;
		}
		java.util.List<WasmDataSegment> segments = module.getDataSegments();
		AddressFactory addressFactory = program.getAddressFactory();
		for (Map.Entry<Long, String> entry : map.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			long idx = entry.getKey();
			if (idx < 0 || idx >= segments.size()) {
				continue;
			}
			WasmDataSegment segment = segments.get((int) idx);
			Long offset = segment.getMemoryOffset();
			if (offset == null) {
				continue;
			}
			int memidx = (int) segment.getIndex();
			applyLabel(program, WasmLoader.getMemoryAddress(addressFactory, module, memidx, offset),
				entry.getValue(), "data" + idx);
		}
	}

	/**
	 * Label names are an indirect map funcidx -> (labelidx -> name), where labelidx is the
	 * extended-name-section, function-wide index (the order the block/loop/if/try constructs
	 * appear in the body). The pre-analyzer records the address each label branches to
	 * ({@link WasmFunctionAnalysis#getLabelTargets()}), so each name becomes a real Ghidra
	 * label at that target address. A name whose index does not resolve (unknown function,
	 * label index past the last construct, or a function the pre-analyzer could not analyse)
	 * is kept as a plate comment instead, so nothing is silently dropped.
	 */
	private void applyLabelNames(Program program, WasmAnalysis state, WasmNameSection nameSection,
			TaskMonitor monitor) {
		WasmNameLabelSubsection labels = nameSection.getLabelSubsection();
		if (labels == null) {
			return;
		}
		Map<Long, Map<Long, String>> labelMap = labels.getLabelNameMap();
		if (labelMap.isEmpty()) {
			return;
		}
		java.util.List<WasmFuncSignature> functions = state.getFunctions();
		for (Map.Entry<Long, Map<Long, String>> entry : labelMap.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			long funcidx = entry.getKey();
			if (funcidx < 0 || funcidx >= functions.size()) {
				continue;
			}
			Address functionStart = functions.get((int) funcidx).getStartAddr();
			Function function = program.getFunctionManager().getFunctionAt(functionStart);
			if (function == null) {
				continue;
			}

			Map<Integer, Address> targets = labelTargets(state, functionStart);
			StringBuilder unresolved = new StringBuilder();
			for (Map.Entry<Long, String> label : new TreeMap<>(entry.getValue()).entrySet()) {
				long labelidx = label.getKey();
				Address target = (labelidx >= 0 && labelidx <= Integer.MAX_VALUE)
						? targets.get((int) labelidx)
						: null;
				/* Label names repeat across functions (e.g. $exit), so they live in the function's
				   namespace; anything that could not be applied is kept in the comment. */
				if (target != null && applyLabel(program, target, label.getValue(),
					"label_" + funcidx + "_" + labelidx, function)) {
					continue;
				}
				if (unresolved.length() > 0) {
					unresolved.append(' ');
				}
				unresolved.append('[').append(labelidx).append("]=").append(label.getValue());
			}
			if (unresolved.length() > 0) {
				appendPlateComment(program, function.getEntryPoint(),
					"WebAssembly label names (not applied): " + unresolved);
			}
		}
	}

	/**
	 * The label target addresses the pre-analyzer recorded for one function, or an empty map
	 * when the function could not be analysed (malformed body). Never throws.
	 */
	private Map<Integer, Address> labelTargets(WasmAnalysis state, Address functionStart) {
		try {
			WasmFunctionAnalysis funcAnalysis = state.getFunctionAnalysis(functionStart);
			if (funcAnalysis == null) {
				return java.util.Collections.emptyMap();
			}
			return funcAnalysis.getLabelTargets();
		}
		catch (Exception e) {
			Msg.warn(this, TAG + "could not resolve label targets for " + functionStart, e);
			return java.util.Collections.emptyMap();
		}
	}

	/** Create a label in the global namespace; see the namespace overload. */
	private void applyLabel(Program program, Address address, String name, String fallbackName) {
		applyLabel(program, address, name, fallbackName, program.getGlobalNamespace());
	}

	/**
	 * Create a label with an imported name in the given namespace, unless the address already
	 * carries a user-defined symbol (never overwrite user symbols) or the exact name is already
	 * present in that namespace. Returns whether the label now exists with this name.
	 */
	private boolean applyLabel(Program program, Address address, String name, String fallbackName,
			Namespace namespace) {
		if (address == null || name == null || name.isEmpty()) {
			return false;
		}
		if (program.getMemory().getBlock(address) == null) {
			return false;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		for (Symbol symbol : symbolTable.getSymbols(address)) {
			if (symbol.getSource() == SourceType.USER_DEFINED) {
				return false;
			}
		}

		String labelName = sanitize(name);
		if (labelName.isEmpty()) {
			return false;
		}
		for (Symbol existing : symbolTable.getSymbols(labelName, namespace)) {
			/* a re-run finds its own label: that is success, not a clash */
			return existing.getAddress().equals(address);
		}

		try {
			symbolTable.createLabel(address, labelName, namespace, SourceType.IMPORTED);
			return true;
		}
		catch (Exception e) {
			Msg.warn(this, TAG + "could not label " + fallbackName + " (" + name + ") at " + address, e);
			return false;
		}
	}

	private static String sanitize(String name) {
		String result = name.replace(" ", "\u00A0");
		result = SymbolUtilities.replaceInvalidChars(result, true);
		int maxLen = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - 16;
		if (result.length() > maxLen) {
			result = result.substring(0, maxLen);
		}
		return result;
	}

	/** Append to the existing plate comment at the address (never discard other comments). */
	private static void appendPlateComment(Program program, Address address, String text) {
		String current = program.getListing().getComment(CommentType.PLATE, address);
		/* One-time analyzers may be scheduled more than once; keep the comment idempotent. */
		if (current != null && current.contains(text)) {
			return;
		}
		String combined = (current == null || current.isEmpty()) ? text : current + "\n" + text;
		program.getListing().setComment(address, CommentType.PLATE, combined);
	}
}
