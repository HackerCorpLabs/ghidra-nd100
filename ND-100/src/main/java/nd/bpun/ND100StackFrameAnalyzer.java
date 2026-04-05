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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that annotates B-relative (stack frame) addressing with signed
 * decimal offsets and known frame slot names.
 *
 * ND-100 stack frames use the B register as frame pointer. Common offsets:
 *   B-128 = LINK (return address)
 *   B-127 = PREVB (previous B pointer)
 *   B-126 = STP (stack top pointer)
 *   B-125 = SMAX (stack max)
 *   B-123 = ERRCODE (error code)
 */
public class ND100StackFrameAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 Stack Frame Annotator";
	private static final String DESCRIPTION =
		"Annotates B-relative instructions with signed decimal offsets and known frame slot names.";

	// Known frame slot names indexed by signed offset
	private static final String[] FRAME_NAMES = new String[256];
	static {
		// Offsets are signed 8-bit: -128 to +127
		// Array index = offset & 0xFF (unsigned byte)
		FRAME_NAMES[(-128) & 0xFF] = "LINK";
		FRAME_NAMES[(-127) & 0xFF] = "PREVB";
		FRAME_NAMES[(-126) & 0xFF] = "STP";
		FRAME_NAMES[(-125) & 0xFF] = "SMAX";
		FRAME_NAMES[(-123) & 0xFF] = "ERRCODE";
	}

	public ND100StackFrameAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after());
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
		InstructionIterator instrIter = listing.getInstructions(set, true);

		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			int numOps = instr.getNumOperands();
			for (int i = 0; i < numOps; i++) {
				String opRepr = instr.getDefaultOperandRepresentation(i);
				if (opRepr == null) {
					continue;
				}

				// Look for ,B suffix indicating B-relative addressing
				// Formats: "0x1A,B" (mode 1), "I 0x1A,B" (mode 3),
				// "0x1A,B,X" (mode 5), "I 0x1A,B,X" (mode 7)
				int bIdx = opRepr.indexOf(",B");
				if (bIdx < 0) {
					continue;
				}

				// Extract the hex displacement before ,B
				String before = opRepr.substring(0, bIdx);

				// Strip "I " prefix for indirect modes (3, 7)
				if (before.startsWith("I ")) {
					before = before.substring(2);
				}

				// Parse hex value
				int displacement;
				try {
					if (before.startsWith("0x") || before.startsWith("0X")) {
						displacement = Integer.parseInt(before.substring(2), 16);
					} else {
						displacement = Integer.parseInt(before, 16);
					}
				} catch (NumberFormatException e) {
					continue;
				}

				// Convert to signed 8-bit
				int signed = displacement;
				if (signed > 127) {
					signed = signed - 256;
				}

				// Build comment
				StringBuilder comment = new StringBuilder();
				if (signed >= 0) {
					comment.append("B+");
					comment.append(signed);
				} else {
					comment.append("B");
					comment.append(signed);
				}

				// Check for known frame slot name
				String frameName = FRAME_NAMES[displacement & 0xFF];
				if (frameName != null) {
					comment.append(" (");
					comment.append(frameName);
					comment.append(")");
				}

				// Don't overwrite existing comments from other analyzers
				String existing = instr.getComment(CommentType.EOL);
				if (existing != null && existing.length() > 0) {
					instr.setComment(CommentType.EOL, existing + "  " + comment.toString());
				} else {
					instr.setComment(CommentType.EOL, comment.toString());
				}

				break; // Only annotate once per instruction
			}
		}

		return true;
	}
}
