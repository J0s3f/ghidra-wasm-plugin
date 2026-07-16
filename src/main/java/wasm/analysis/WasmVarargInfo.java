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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 * Per-callsite information about a resolved variadic call (Emscripten ABI:
 * varargs are passed through a stack buffer whose pointer is the last real
 * parameter). Produced by WasmVarargAnalyzer, consumed by
 * InjectPayloadWasmCallPrologue, and persisted in a StringPropertyMap so it
 * survives across sessions.
 *
 * Encoding: "&lt;bufParamIndex&gt;;&lt;off&gt;:&lt;size&gt;,&lt;off&gt;:&lt;size&gt;,..."
 */
public class WasmVarargInfo {
	public static final String PROPERTY_NAME = "WasmVarargInfo";

	/** Index of the va-buffer pointer in the callee's real parameter list. */
	public final int bufParamIndex;
	/** Byte offset within the va buffer of each variadic argument. */
	public final int[] offsets;
	/** Size in bytes (4 or 8) of each variadic argument. */
	public final int[] sizes;

	public WasmVarargInfo(int bufParamIndex, int[] offsets, int[] sizes) {
		this.bufParamIndex = bufParamIndex;
		this.offsets = offsets;
		this.sizes = sizes;
	}

	public String encode() {
		StringBuilder sb = new StringBuilder();
		sb.append(bufParamIndex).append(';');
		for (int i = 0; i < offsets.length; i++) {
			if (i > 0)
				sb.append(',');
			sb.append(offsets[i]).append(':').append(sizes[i]);
		}
		return sb.toString();
	}

	public static WasmVarargInfo decode(String s) {
		try {
			int semi = s.indexOf(';');
			int bufIdx = Integer.parseInt(s.substring(0, semi));
			String rest = s.substring(semi + 1);
			List<int[]> slots = new ArrayList<>();
			if (!rest.isEmpty()) {
				for (String part : rest.split(",")) {
					int colon = part.indexOf(':');
					slots.add(new int[] { Integer.parseInt(part.substring(0, colon)),
							Integer.parseInt(part.substring(colon + 1)) });
				}
			}
			int[] offsets = new int[slots.size()];
			int[] sizes = new int[slots.size()];
			for (int i = 0; i < slots.size(); i++) {
				offsets[i] = slots.get(i)[0];
				sizes[i] = slots.get(i)[1];
			}
			return new WasmVarargInfo(bufIdx, offsets, sizes);
		} catch (Exception e) {
			return null;
		}
	}

	public static WasmVarargInfo get(Program program, Address callsite) {
		StringPropertyMap map = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY_NAME);
		if (map == null)
			return null;
		String s = map.getString(callsite);
		if (s == null)
			return null;
		return decode(s);
	}

	public static void put(Program program, Address callsite, WasmVarargInfo info) {
		StringPropertyMap map = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY_NAME);
		if (map == null) {
			try {
				map = program.getUsrPropertyManager().createStringPropertyMap(PROPERTY_NAME);
			} catch (DuplicateNameException e) {
				return;
			}
		}
		map.add(callsite, info.encode());
	}
}
