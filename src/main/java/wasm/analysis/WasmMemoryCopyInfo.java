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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.util.exception.DuplicateNameException;

/**
 * Records, per memory.copy callsite, the constant byte length of a copy whose
 * source is a read-only data-segment constant (a .rodata initializer). Produced
 * by WasmMemoryCopyAnalyzer, consumed by InjectPayloadWasmMemoryCopy, which
 * unrolls the copy so the decompiler folds the read-only source into inline
 * constant stores. Absent for dynamic copies (which stay a memcpy call).
 */
public class WasmMemoryCopyInfo {
	public static final String PROPERTY_NAME = "WasmMemoryCopyLen";
	public static void clear(Program program, Address callsite) {
		IntPropertyMap map = program.getUsrPropertyManager().getIntPropertyMap(PROPERTY_NAME);
		if (map != null) { map.remove(callsite); }
	}

	public static Integer getLength(Program program, Address callsite) {
		IntPropertyMap map = program.getUsrPropertyManager().getIntPropertyMap(PROPERTY_NAME);
		if (map == null || !map.hasProperty(callsite)) {
			return null;
		}
		try {
			return map.getInt(callsite);
		} catch (Exception e) {
			return null;
		}
	}

	public static void putLength(Program program, Address callsite, int length) {
		IntPropertyMap map = program.getUsrPropertyManager().getIntPropertyMap(PROPERTY_NAME);
		if (map == null) {
			try {
				map = program.getUsrPropertyManager().createIntPropertyMap(PROPERTY_NAME);
			} catch (DuplicateNameException e) {
				return;
			}
		}
		map.add(callsite, length);
	}
}
