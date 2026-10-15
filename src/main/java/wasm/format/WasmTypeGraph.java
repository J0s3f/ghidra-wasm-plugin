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
package wasm.format;

import java.util.*;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmEnums.ValType.TypeInfo;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmGCType;
import wasm.format.sections.structures.WasmGCType.Kind;
import wasm.format.sections.structures.WasmGCType.StorageType;

/** Defined-type equivalence, declared subtyping, nullability, and variance for Core 3.0. */
public final class WasmTypeGraph {
	private final WasmModule module;
	public WasmTypeGraph(WasmModule module) { this.module = module; }
	private WasmFuncType type(int index) { return module.getType(index); }
	private Kind kind(int index) { return type(index) instanceof WasmGCType gc ? gc.getKind() : Kind.FUNC; }
	private boolean isFinal(int index) { return !(type(index) instanceof WasmGCType gc) || !gc.hasSubtype() || gc.isSubtypeFinal(); }
	private long[] supers(int index) { return type(index) instanceof WasmGCType gc ? gc.getSupertypes() : new long[0]; }
	private static boolean reference(TypeInfo info) { return info.heapType != null || info.type.isReferenceType(); }
	private static long heap(TypeInfo info) { return info.heapType != null ? info.heapType : info.type.typeByte - 0x80L; }
	public static TypeInfo storage(StorageType field) {
		if (field.isRef()) { return TypeInfo.reference(field.code == 0x63 || field.code == 0x64 ? field.heapType : field.code - 0x80L, field.code != 0x64); }
		return TypeInfo.value(field.asValType());
	}

	public boolean isSubtype(TypeInfo actual, TypeInfo expected) {
		if (reference(actual) != reference(expected)) { return false; }
		if (!reference(actual)) { return actual.type == expected.type; }
		return (!actual.nullable || expected.nullable) && isHeapSubtype(heap(actual), heap(expected));
	}

	public boolean isHeapSubtype(long actual, long expected) {
		if (actual == expected) { return true; }
		if (actual < 0 && expected < 0) { return ValType.forHeapType(actual).isSubtypeOf(ValType.forHeapType(expected)); }
		if (actual < 0) {
			ValType bottom = ValType.forHeapType(actual);
			return bottom == ValType.none && (kind((int) expected) == Kind.STRUCT || kind((int) expected) == Kind.ARRAY)
				|| bottom == ValType.nofuncref && kind((int) expected) == Kind.FUNC;
		}
		if (expected < 0) { return module.resolveHeapType(actual).isSubtypeOf(ValType.forHeapType(expected)); }
		int from = Math.toIntExact(actual), to = Math.toIntExact(expected);
		var todo = new ArrayDeque<Integer>(); var visited = new HashSet<Integer>(); todo.add(from);
		while (!todo.isEmpty()) {
			int index = todo.removeFirst();
			if (!visited.add(index)) { continue; }
			if (equivalent(index, to)) { return true; }
			for (long parent : supers(index)) { if (parent >= 0 && parent < typeCount()) { todo.add((int) parent); } }
		}
		return false;
	}

	private int typeCount() { return module.getTypeSection() == null ? 0 : module.getTypeSection().getNumTypes(); }
	public boolean equivalent(int left, int right) { return equivalent(left, right, new HashSet<>()); }
	private boolean equivalent(int left, int right, Set<Long> visited) {
		if (left == right) { return true; }
		long key = ((long) left << 32) | (right & 0xffffffffL);
		if (!visited.add(key)) { return true; }
		var section = module.getTypeSection();
		int a = section.getGroupStart(left), b = section.getGroupStart(right), n = section.getGroupSize(left);
		if (n != section.getGroupSize(right) || left - a != right - b) { return false; }
		for (int i = 0; i < n; i++) {
			int x = a + i, y = b + i;
			if (kind(x) != kind(y) || isFinal(x) != isFinal(y)) { return false; }
			long[] xs = supers(x), ys = supers(y);
			if (xs.length != ys.length) { return false; }
			for (int j = 0; j < xs.length; j++) { if (!sameHeap(xs[j], ys[j], a, b, n, visited)) { return false; } }
			if (!sameComposite(x, y, a, b, n, visited)) { return false; }
		}
		return true;
	}
	private boolean sameHeap(long x, long y, int a, int b, int n, Set<Long> visited) {
		boolean localX = x >= a && x < a + n, localY = y >= b && y < b + n;
		if (localX || localY) { return localX && localY && x - a == y - b; }
		return x < 0 || y < 0 ? x == y : equivalent((int) x, (int) y, visited);
	}
	private boolean sameInfo(TypeInfo x, TypeInfo y, int a, int b, int n, Set<Long> visited) {
		if (reference(x) != reference(y)) { return false; }
		return reference(x) ? x.nullable == y.nullable && sameHeap(heap(x), heap(y), a, b, n, visited) : x.type == y.type;
	}
	private boolean sameStorage(StorageType x, StorageType y, int a, int b, int n, Set<Long> visited) {
		return x.isMutable() == y.isMutable() && (x.isPacked() || y.isPacked() ? x.code == y.code : sameInfo(storage(x), storage(y), a, b, n, visited));
	}
	private boolean sameComposite(int x, int y, int a, int b, int n, Set<Long> visited) {
		if (kind(x) == Kind.FUNC) {
			TypeInfo[][] xx = {type(x).getParamTypeInfo(), type(x).getReturnTypeInfo()}, yy = {type(y).getParamTypeInfo(), type(y).getReturnTypeInfo()};
			for (int k = 0; k < 2; k++) {
				if (xx[k].length != yy[k].length) { return false; }
				for (int j = 0; j < xx[k].length; j++) { if (!sameInfo(xx[k][j], yy[k][j], a, b, n, visited)) { return false; } }
			}
			return true;
		}
		var xx = (WasmGCType) type(x); var yy = (WasmGCType) type(y);
		if (kind(x) == Kind.ARRAY) { return sameStorage(xx.getElementStorage(), yy.getElementStorage(), a, b, n, visited); }
		if (kind(x) == Kind.CONT) { return sameHeap(xx.getContTypeIndex(), yy.getContTypeIndex(), a, b, n, visited); }
		if (xx.getFieldCount() != yy.getFieldCount()) { return false; }
		for (int j = 0; j < xx.getFieldCount(); j++) { if (!sameStorage(xx.getFieldStorage(j), yy.getFieldStorage(j), a, b, n, visited)) { return false; } }
		return true;
	}

	private boolean compatibleStorage(StorageType actual, StorageType expected) {
		if (actual.isMutable() != expected.isMutable()) { return false; }
		if (actual.isPacked() || expected.isPacked()) { return actual.code == expected.code; }
		return isSubtype(storage(actual), storage(expected)) && (!actual.isMutable() || isSubtype(storage(expected), storage(actual)));
	}
	private boolean compatibleComposite(int child, int parent) {
		if (kind(child) != kind(parent)) { return false; }
		if (kind(child) == Kind.FUNC) {
			var cp = type(child).getParamTypeInfo(); var pp = type(parent).getParamTypeInfo();
			var cr = type(child).getReturnTypeInfo(); var pr = type(parent).getReturnTypeInfo();
			if (cp.length != pp.length || cr.length != pr.length) { return false; }
			for (int j = 0; j < cp.length; j++) { if (!isSubtype(pp[j], cp[j])) { return false; } }
			for (int j = 0; j < cr.length; j++) { if (!isSubtype(cr[j], pr[j])) { return false; } }
			return true;
		}
		var c = (WasmGCType) type(child); var p = (WasmGCType) type(parent);
		if (kind(child) == Kind.ARRAY) { return compatibleStorage(c.getElementStorage(), p.getElementStorage()); }
		if (kind(child) != Kind.STRUCT) { return true; } // Draft continuation validation is separate.
		if (c.getFieldCount() < p.getFieldCount()) { return false; }
		for (int j = 0; j < p.getFieldCount(); j++) { if (!compatibleStorage(c.getFieldStorage(j), p.getFieldStorage(j))) { return false; } }
		return true;
	}

	/** Diagnostic validation preserves the repository's lenient import policy. */
	public List<String> diagnostics() {
		List<String> errors = new ArrayList<>();
		for (int child = 0; child < typeCount(); child++) {
			long[] parents = supers(child);
			if (parents.length > 1) { errors.add("Type " + child + " has multiple declared supertypes"); }
			for (long parent : parents) {
				if (parent < 0 || parent >= child) { errors.add("Type " + child + " has a non-prior supertype " + parent); continue; }
				if (isFinal((int) parent)) { errors.add("Type " + child + " extends final type " + parent); }
				try { if (!compatibleComposite(child, (int) parent)) { errors.add("Type " + child + " is incompatible with supertype " + parent); } }
				catch (RuntimeException e) { errors.add("Type " + child + " has invalid referenced storage: " + e.getMessage()); }
			}
		}
		return Collections.unmodifiableList(errors);
	}
}
