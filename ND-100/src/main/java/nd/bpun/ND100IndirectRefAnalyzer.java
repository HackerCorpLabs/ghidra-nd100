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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that resolves ND-100 indirect P-relative memory references.
 *
 * For instructions using addressing mode 2 (I without ,B or ,X), the pointer
 * address is P-relative and resolved at disassembly time. This analyzer reads
 * the word at that pointer address from loaded memory and adds a reference to
 * the final target address, plus an EOL comment showing the resolved target.
 *
 * For JMP/JPL indirect: defines the pointer as a code pointer and adds
 * COMPUTED_JUMP/COMPUTED_CALL references so the decompiler resolves the target.
 *
 * Also handles mode 6 (,X I *addr) where the pointer is P-relative but the
 * final address is X-indexed (target from pointer + X at runtime, but the
 * pointer dereference can still be resolved statically).
 */
public class ND100IndirectRefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 Indirect Reference Resolver";
	private static final String DESCRIPTION =
		"Resolves indirect P-relative references by reading pointer values from memory " +
		"and adding references to the final target addresses.";

	public ND100IndirectRefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// Run after basic reference analysis so we can find existing refs
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
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

		InstructionIterator instrIter = listing.getInstructions(set, true);

		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			// Check operand representation for "I *" which indicates
			// indirect P-relative addressing (mode 2: "I *addr" or mode 6: ",X I *addr")
			int numOps = instr.getNumOperands();
			boolean hasIndirectPRelative = false;
			for (int i = 0; i < numOps; i++) {
				String opRepr = instr.getDefaultOperandRepresentation(i);
				if (opRepr != null && opRepr.contains("I *")) {
					hasIndirectPRelative = true;
					break;
				}
			}

			if (!hasIndirectPRelative) {
				continue;
			}

			// Find the pointer address from existing references.
			// SLEIGH creates a reference to the P-relative pointer location.
			Address ptrAddr = null;
			Reference[] refs = instr.getReferencesFrom();
			for (int i = 0; i < refs.length; i++) {
				Address toAddr = refs[i].getToAddress();
				// The pointer address should be in RAM near the instruction
				if (toAddr.getAddressSpace().equals(instr.getAddress().getAddressSpace())) {
					ptrAddr = toAddr;
					break;
				}
			}

			if (ptrAddr == null) {
				continue;
			}

			// Read the 16-bit word at the pointer address (big-endian ND-100)
			try {
				short targetWord = memory.getShort(ptrAddr);
				int targetOffset = Short.toUnsignedInt(targetWord);

				// Create address in the same space as the instruction
				// Multiply by wordSize because ND-100 is word-addressed (wordsize=2)
				int wordSize = instr.getAddress().getAddressSpace().getAddressableUnitSize();
				Address targetAddr = instr.getAddress().getNewAddress((long) targetOffset * wordSize);

				// Check if target is in valid memory
				if (!memory.contains(targetAddr)) {
					continue;
				}

				// Determine reference type based on mnemonic
				String mnemonic = instr.getMnemonicString();
				RefType refType;
				if ("JMP".equals(mnemonic) || "JPL".equals(mnemonic)) {
					refType = RefType.COMPUTED_JUMP;
				} else {
					refType = RefType.INDIRECTION;
				}

				// Add a reference from the instruction to the resolved target
				boolean alreadyHasRef = false;
				for (int i = 0; i < refs.length; i++) {
					if (refs[i].getToAddress().equals(targetAddr)) {
						alreadyHasRef = true;
						break;
					}
				}

				if (!alreadyHasRef) {
					refMgr.addMemoryReference(
						instr.getAddress(), targetAddr,
						refType, SourceType.ANALYSIS, 0);
				}

				// Define the pointer location as a code pointer data type
				Data existingData = listing.getDefinedDataAt(ptrAddr);
				if (existingData == null) {
					try {
						listing.createData(ptrAddr, PointerDataType.dataType, 2);
					} catch (Exception e) {
						// May conflict with existing instruction — skip
					}
				}

				// Add EOL comment showing resolved indirect target
				String existingComment = instr.getComment(CommentType.EOL);
				String targetLabel = getLabel(symTable, targetAddr);
				String comment = "[" + ptrAddr + "] -> " + targetLabel;

				if (existingComment == null || !existingComment.contains("-> ")) {
					instr.setComment(CommentType.EOL, comment);
				}
			}
			catch (MemoryAccessException e) {
				// Pointer location not readable — skip
			}
		}

		return true;
	}

	private String getLabel(SymbolTable symTable, Address addr) {
		Symbol[] symbols = symTable.getSymbols(addr);
		if (symbols != null && symbols.length > 0) {
			return symbols[0].getName();
		}
		return addr.toString();
	}
}
