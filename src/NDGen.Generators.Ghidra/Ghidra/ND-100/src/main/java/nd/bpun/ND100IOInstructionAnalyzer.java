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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that annotates IOT and IOX instructions with the device register
 * name from io_space symbols created by ND100IOAnalyzer.
 *
 * Adds EOL comments like "; RTC1_READ_STATUS" to I/O instructions.
 */
public class ND100IOInstructionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 I/O Instruction Annotator";
	private static final String DESCRIPTION =
		"Annotates IOT/IOX instructions with device register names from io_space symbols.";

	public ND100IOInstructionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after().after());
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
		SymbolTable symTable = program.getSymbolTable();

		InstructionIterator instrIter = listing.getInstructions(set, true);

		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			String mnemonic = instr.getMnemonicString();
			if (!"IOT".equals(mnemonic) && !"IOX".equals(mnemonic)) {
				continue;
			}

			// Find reference to io_space from this instruction
			Reference[] refs = instr.getReferencesFrom();
			String ioLabel = null;

			for (int i = 0; i < refs.length; i++) {
				Address toAddr = refs[i].getToAddress();
				if ("io_space".equals(toAddr.getAddressSpace().getName())) {
					Symbol[] symbols = symTable.getSymbols(toAddr);
					if (symbols != null && symbols.length > 0) {
						ioLabel = symbols[0].getName();
					}
					break;
				}
			}

			if (ioLabel == null) {
				continue;
			}

			// Don't overwrite existing comments
			String existing = instr.getComment(CommentType.EOL);
			if (existing != null && existing.length() > 0) {
				continue;
			}

			instr.setComment(CommentType.EOL, ioLabel);
		}

		return true;
	}
}
