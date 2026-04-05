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
package nd.bpun;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that detects dispatch/jump tables in ND-100 programs.
 *
 * Scans undefined data regions for runs of 3 or more consecutive words that
 * all point to valid instruction addresses. When found, creates a DISPATCH
 * label, defines words as WordDataType, and adds data references.
 */
public class ND100DispatchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 Dispatch Table Detector";
	private static final String DESCRIPTION =
		"Detects consecutive words pointing to code addresses as dispatch/jump tables.";

	private static final int MIN_TABLE_ENTRIES = 3;

	public ND100DispatchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DATA_ANALYSIS.after());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		String langId = program.getLanguageID().getIdAsString();
		return langId.startsWith("ND-100:");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		ReferenceManager refMgr = program.getReferenceManager();
		SymbolTable symTable = program.getSymbolTable();

		// Get the default address space (RAM) for instruction lookups
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		// Find undefined regions (no code or data defined)
		AddressSet undefined = new AddressSet();
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			monitor.checkCancelled();
			AddressRange range = rangeIter.next();
			// Only look at default address space (RAM)
			if (!range.getMinAddress().getAddressSpace().equals(defaultSpace)) {
				continue;
			}
			Address addr = range.getMinAddress();
			Address end = range.getMaxAddress();
			while (addr.compareTo(end) <= 0) {
				if (listing.getCodeUnitAt(addr) == null ||
						listing.isUndefined(addr, addr)) {
					undefined.add(addr);
				}
				try {
					addr = addr.add(2); // word-aligned (16-bit)
				} catch (Exception e) {
					break; // address overflow
				}
			}
		}

		// Scan undefined regions for dispatch tables
		AddressRangeIterator undefIter = undefined.getAddressRanges();
		while (undefIter.hasNext()) {
			monitor.checkCancelled();
			AddressRange range = undefIter.next();
			scanForDispatchTable(program, listing, memory, refMgr, symTable,
				defaultSpace, range, monitor);
		}

		return true;
	}

	private void scanForDispatchTable(Program program, Listing listing, Memory memory,
			ReferenceManager refMgr, SymbolTable symTable, AddressSpace defaultSpace,
			AddressRange range, TaskMonitor monitor) throws CancelledException {

		Address addr = range.getMinAddress();
		Address end = range.getMaxAddress();

		// Align to word boundary (ND-100 is 16-bit word addressed)
		long offset = addr.getOffset();
		if ((offset & 1) != 0) {
			try {
				addr = addr.add(1);
			} catch (Exception e) {
				return;
			}
		}

		// Track current run of valid code pointers
		Address runStart = null;
		int runLength = 0;

		while (addr.compareTo(end) < 0) {
			monitor.checkCancelled();

			boolean isCodePointer = false;
			try {
				short word = memory.getShort(addr);
				int target = Short.toUnsignedInt(word);
				Address targetAddr = defaultSpace.getAddress(target);

				// Check if target is a defined instruction
				if (listing.getInstructionAt(targetAddr) != null) {
					isCodePointer = true;
				}
			} catch (MemoryAccessException e) {
				// Not readable
			}

			if (isCodePointer) {
				if (runStart == null) {
					runStart = addr;
					runLength = 1;
				} else {
					runLength++;
				}
			} else {
				// End of run — check if it qualifies as a dispatch table
				if (runLength >= MIN_TABLE_ENTRIES) {
					defineDispatchTable(listing, memory, refMgr, symTable,
						defaultSpace, runStart, runLength);
				}
				runStart = null;
				runLength = 0;
			}

			try {
				addr = addr.add(2);
			} catch (Exception e) {
				break;
			}
		}

		// Check trailing run
		if (runLength >= MIN_TABLE_ENTRIES) {
			defineDispatchTable(listing, memory, refMgr, symTable,
				defaultSpace, runStart, runLength);
		}
	}

	private void defineDispatchTable(Listing listing, Memory memory,
			ReferenceManager refMgr, SymbolTable symTable, AddressSpace defaultSpace,
			Address tableStart, int entryCount) {

		// Create label: DISPATCH_xxxx
		String label = "DISPATCH_" + tableStart.toString().toUpperCase();
		try {
			symTable.createLabel(tableStart, label, SourceType.ANALYSIS);
		} catch (Exception e) {
			// Label may already exist
		}

		// Add plate comment
		listing.setComment(tableStart, CommentType.PLATE,
			"Dispatch table (" + entryCount + " entries)");

		// Define each entry as WordDataType and add data reference
		Address addr = tableStart;
		for (int i = 0; i < entryCount; i++) {
			try {
				// Define as word
				listing.clearCodeUnits(addr, addr.add(1), false);
				listing.createData(addr, WordDataType.dataType);

				// Read target and add reference
				short word = memory.getShort(addr);
				int target = Short.toUnsignedInt(word);
				Address targetAddr = defaultSpace.getAddress(target);
				refMgr.addMemoryReference(addr, targetAddr,
					RefType.DATA, SourceType.ANALYSIS, 0);
			} catch (Exception e) {
				// Best effort
			}

			try {
				addr = addr.add(2);
			} catch (Exception e) {
				break;
			}
		}
	}
}
