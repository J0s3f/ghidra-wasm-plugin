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

import java.io.IOException;

import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeComponentImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.util.exception.DuplicateNameException;

public class StructureBuilder {
	private class SBStructure extends StructureDataType {
		public SBStructure(CategoryPath path, String name, int length) {
			super(path, name, length);
		}

		/**
		 * Check that adding <code>dataType</code> to this structure would not create a
		 * circular dependency. Ghidra used to provide
		 * <code>CompositeDataTypeImpl.checkAncestry</code> for this purpose, but that
		 * method has been removed from newer Ghidra releases, so the equivalent logic is
		 * implemented here using only stable public API.
		 */
		private void checkAncestry(DataType dataType) {
			if (this.equals(dataType)) {
				throw new IllegalArgumentException("Data type " + getDisplayName() + " can't contain itself.");
			}
			if (containsDataType(dataType, this)) {
				throw new IllegalArgumentException(
					"Data type " + dataType.getDisplayName() + " has " + getDisplayName() + " within it.");
			}
		}

		/**
		 * Determine if <code>target</code> appears anywhere within the definition of
		 * <code>container</code> (equivalent to the former
		 * <code>DataTypeUtilities.isSecondPartOfFirst</code>).
		 */
		private boolean containsDataType(DataType container, DataType target) {
			if (container == null || container instanceof Pointer || target instanceof Pointer) {
				return false;
			}
			if (container.equals(target)) {
				return true;
			}
			if (container instanceof Array) {
				return containsDataType(((Array) container).getDataType(), target);
			}
			if (container instanceof TypeDef) {
				return containsDataType(((TypeDef) container).getDataType(), target);
			}
			if (container instanceof Composite) {
				for (DataTypeComponent component : ((Composite) container).getDefinedComponents()) {
					if (containsDataType(component.getDataType(), target)) {
						return true;
					}
				}
			}
			return false;
		}

		/**
		 * Add a component to this structure. This function does not repack the
		 * structure after adding, in order to avoid quadratic behaviour when adding a
		 * large number of structure elements. To ensure correct behaviour, the
		 * structure should be repacked after components have been added.
		 */
		@Override
		public DataTypeComponent add(DataType dataType, int length, String componentName, String comment) {
			dataType = validateDataType(dataType);

			dataType = dataType.clone(dataMgr);

			checkAncestry(dataType);

			DataTypeComponentImpl dtc;
			int offset = structLength;
			int ordinal = numComponents;

			int componentLength = getPreferredComponentLength(dataType, length);

			dtc = new DataTypeComponentImpl(dataType, this, componentLength, ordinal, offset,
					componentName, comment);
			dataType.addParent(this);
			components.add(dtc);

			int structureGrowth = dtc.getLength();
			if (!isPackingEnabled() && length > 0) {
				structureGrowth = length;
			}

			numComponents++;
			structLength += structureGrowth;
			return dtc;
		}
	}

	private SBStructure structure;

	public StructureBuilder(String name) {
		CategoryPath path = new CategoryPath(CategoryPath.ROOT, "Wasm");
		structure = new SBStructure(path, name, 0);
	}

	public Structure toStructure() {
		StructureDataType newStructure = new StructureDataType(structure.getCategoryPath(), structure.getName(), 0);
		newStructure.replaceWith(structure);
		return newStructure;
	}

	public void add(DataType dataType, int length, String name, String comment) {
		structure.add(dataType, length, name, comment);
	}

	public void add(DataType dataType, int length, String name) {
		add(dataType, length, name, null);
	}

	public void add(DataType dataType, String name, String comment) {
		structure.add(dataType, dataType.getLength(), name, comment);
	}

	public void add(DataType dataType, String name) {
		add(dataType, name, null);
	}

	public void addUnsignedLeb128(LEB128Info leb128, String name, String comment) {
		add(StructConverter.ULEB128, leb128.getLength(), name, comment);
	}

	public void addUnsignedLeb128(LEB128Info leb128, String name) {
		addUnsignedLeb128(leb128, name, null);
	}

	public void add(StructConverter converter, String name, String comment) throws DuplicateNameException, IOException {
		add(converter.toDataType(), name, comment);
	}

	public void add(StructConverter converter, String name) throws DuplicateNameException, IOException {
		add(converter.toDataType(), name, null);
	}

	public void addArray(DataType dataType, int numElements, String name, String comment) {
		if (numElements > 0)
			structure.add(new ArrayDataType(dataType, numElements, dataType.getLength()), name, comment);
	}

	public void addArray(DataType dataType, int numElements, String name) {
		addArray(dataType, numElements, name, null);
	}

	public void addString(int byteSize, String name, String comment) {
		if (byteSize > 0)
			structure.add(StructConverter.STRING, byteSize, name, comment);
	}

	public void addString(int byteSize, String name) {
		addString(byteSize, name, null);
	}
}
