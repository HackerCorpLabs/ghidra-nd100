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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * ND-100 TPE :TEST and :NEXT file format loader for Ghidra.
 *
 * TPE (Test Program Environment) files contain hardware diagnostic test programs
 * for the ND-100 minicomputer. The file format consists of a 136-word (272-byte)
 * header followed by executable code/data payload.
 *
 * File structure:
 * - Words 0x0000-0x0002: Magic/control flags (0x6C00 for :TEST, 0x9780 for :NEXT)
 * - Word 0x0003: Checksum
 * - Word 0x0004: Marker (0xFFFF)
 * - Words 0x0008: Unknown field
 * - Words 0x0019-0x0027: Dependency names (CR-separated, apostrophe-terminated)
 * - Words 0x0028-0x0030: PCR configuration data
 * - Words 0x0031-0x0070: Page table entries (physical page numbers, 0xFFFF=unmapped)
 * - Words 0x0088+: Code/data payload (loaded into test program virtual address space)
 *
 * The payload contains:
 * - TPE runtime library (words 0x0088-0x00C5, identical across all test files)
 * - Test-specific code and data (words 0x0100+)
 *
 * Reference: docs/test-file-format.md
 */
public class TPETestLoader extends AbstractProgramWrapperLoader {

	public static final String TPE_NAME = "ND-100 TPE Test Program (:TEST/:NEXT)";

	private static final int MAGIC_TEST = 0x6C00;
	private static final int MAGIC_NEXT = 0x9780;

	private static final int HEADER_WORDS = 136;
	private static final int HEADER_BYTES = HEADER_WORDS * 2;
	private static final int PAYLOAD_WORD_OFFSET = 0x0088;
	private static final int PAGE_UNMAPPED = 0xFFFF;

	/* Header field offsets (word offsets) */
	private static final int OFF_FLAGS = 0x0000;
	private static final int OFF_PID = 0x0001;
	private static final int OFF_PIE = 0x0002;
	private static final int OFF_CHECKSUM = 0x0003;
	private static final int OFF_MARKER = 0x0004;
	private static final int OFF_FIELD_08 = 0x0008;
	private static final int OFF_CONST_0E = 0x000E;
	private static final int OFF_PARAM_A = 0x0014;
	private static final int OFF_PARAM_B = 0x0015;
	private static final int OFF_DEPS_START = 0x0019;
	private static final int OFF_DEPS_END = 0x0029;
	private static final int OFF_RTLIB_CONST1 = 0x002A;
	private static final int OFF_RTLIB_CONST2 = 0x002B;
	private static final int OFF_RTLIB_CONST3 = 0x002D;
	private static final int OFF_RTLIB_CONST4 = 0x0030;
	private static final int OFF_PAGE_TABLE = 0x0031;
	private static final int OFF_PAGE_TABLE_END = 0x0070;
	private static final int PAGE_SIZE_WORDS = 1024;

	/* Payload-relative offsets */
	private static final int CMD_TABLE_OFFSET = 0x0078;    /* pointer to first command entry */
	private static final int CMD_ENTRY_WORDS = 5;          /* each entry: next, handler, name, help, flags */
	private static final int PROG_NAME_OFFSET = 0x0080;    /* ASCII program name */
	private static final int RADD_SL_DX = 0xCD67;          /* PLANC function prologue opcode */
	private static final int RUNTIME_ENTRY_VA = 0x6C00;    /* VA where payload+0x78 maps */

	/** Parsed TPE file header */
	private static class TpeHeader {
		int flags;
		int pid;
		int pie;
		int checksum;
		int marker;
		int field08;
		int const0e;
		int paramA;
		int paramB;
		int rtlibConst1;   /* word 0x2A — always 0x04CB */
		int rtlibConst2;   /* word 0x2B — always 0x67C2 */
		int rtlibConst3;   /* word 0x2D — always 0x040F */
		int rtlibConst4;   /* word 0x30 — always 0x040F */
		String dependencies;
		int mappedPages;
		int[] pageTable;
		int[][] cmdEntries; /* command table: each row is [next, handler, name, help, flags] */
		int cmdEntryCount;
		boolean isTest;    /* true = :TEST, false = :NEXT */
		String fileType;
		int payloadWords;
		int fileSizeWords;
		String progName;   /* test program name from payload offset 0x80 */
		int baseVA;        /* computed runtime base VA */
	}

	@Override
	public String getName() {
		return TPE_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!probeTPE(provider)) {
			return List.of();
		}
		LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("ND-100:BE:16:default", "default");
		return List.of(new LoadSpec(this, 0, lcs, true));
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		MessageLog log = settings.log();

		monitor.setMessage("Loading TPE test program...");

		byte[] fileData = provider.readBytes(0, provider.length());
		TpeHeader header = parseHeader(fileData, log);

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();
		Listing listing = program.getListing();

		int wordSize = space.getAddressableUnitSize();

		/* Runtime base address: payload word 0x78 always maps to VA 0x6C00
		 * (the start of the runtime entry point area in the ND-100 TPE
		 * virtual address space). So base = 0x6C00 - 0x78 = 0x6B88.
		 *
		 * The word AT payload+0x78 is a POINTER to the first command entry
		 * (like [VA 0x6C00] = first_entry_ptr in TPE-MON memory). */
		int payloadByteOffset = PAYLOAD_WORD_OFFSET * 2;
		int payloadByteLen = fileData.length - payloadByteOffset;
		if (payloadByteLen <= 0) {
			log.appendMsg("Error: no payload data in file");
			return;
		}

		byte[] payloadData = new byte[payloadByteLen];
		System.arraycopy(fileData, payloadByteOffset, payloadData, 0, payloadByteLen);

		int baseVA = RUNTIME_ENTRY_VA - CMD_TABLE_OFFSET;
		header.baseVA = baseVA;
		log.appendMsg(String.format("Runtime base VA: 0x%04X (VA 0x%04X = payload+0x%02X)",
				baseVA, RUNTIME_ENTRY_VA, CMD_TABLE_OFFSET));

		Address blockStart = space.getAddress((long) baseVA * wordSize);
		Address blockEnd = null;

		try (ByteArrayInputStream dataStream = new ByteArrayInputStream(payloadData)) {
			MemoryBlock block = memory.createInitializedBlock(
					"CODE", blockStart, dataStream, payloadByteLen, monitor, false);
			block.setComment(header.fileType + " test program code/data");
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
			blockEnd = block.getEnd();

			log.appendMsg(String.format("Loaded %d payload words at VA 0x%04X-0x%04X",
					header.payloadWords, baseVA, baseVA + header.payloadWords - 1));
		}
		catch (Exception e) {
			log.appendMsg("Failed to create code block: " + e.getMessage());
			return;
		}

		/* Load the 136-word header as a separate non-executable block at 0x0000.
		 * This lets the user browse the raw header with field labels. */
		try {
			byte[] headerData = new byte[HEADER_BYTES];
			System.arraycopy(fileData, 0, headerData, 0, HEADER_BYTES);
			ByteArrayInputStream headerStream = new ByteArrayInputStream(headerData);
			Address headerStart = space.getAddress(0);
			MemoryBlock headerBlock = memory.createInitializedBlock(
					"HEADER", headerStart, headerStream, HEADER_BYTES, monitor, false);
			headerBlock.setComment("TPE file header (136 words)");
			headerBlock.setRead(true);
			headerBlock.setWrite(false);
			headerBlock.setExecute(false);

			/* Label header fields */
			String[] headerLabels = {
				"hdr_flags", "hdr_pid", "hdr_pie", "hdr_checksum", "hdr_marker"
			};
			for (int i = 0; i < headerLabels.length; i++) {
				tryLabel(symbolTable, space, i, wordSize, headerLabels[i]);
			}
			tryLabel(symbolTable, space, 0x08, wordSize, "hdr_version");
			tryLabel(symbolTable, space, 0x0E, wordSize, "hdr_const_24DC");
			tryLabel(symbolTable, space, 0x14, wordSize, "hdr_paramA");
			tryLabel(symbolTable, space, 0x15, wordSize, "hdr_paramB");
			tryLabel(symbolTable, space, 0x19, wordSize, "hdr_dependencies");
			tryLabel(symbolTable, space, 0x31, wordSize, "hdr_page_table");

			/* Type header words */
			for (int w = 0; w < HEADER_WORDS; w++) {
				Address hAddr = space.getAddress((long) w * wordSize);
				try {
					listing.createData(hAddr, WordDataType.dataType);
				}
				catch (Exception ex) { /* ignore */ }
			}

			/* Add EOL comments on key header fields */
			setWordComment(listing, space, wordSize, 0x00,
					String.format("flags: 0x%04X %s%s", header.flags,
							(header.flags & 0x4000) != 0 ? "[PON] " : "",
							(header.flags & 0x2000) != 0 ? "[REX]" : ""));
			setWordComment(listing, space, wordSize, 0x03,
					String.format("checksum: 0x%04X", header.checksum));
			setWordComment(listing, space, wordSize, 0x04, "marker (always 0xFFFF)");
			setWordComment(listing, space, wordSize, 0x08,
					String.format("version: 0x%02X", header.field08));
			setWordComment(listing, space, wordSize, 0x0E, "constant (always 0x24DC)");
			setWordComment(listing, space, wordSize, 0x31, "page table start (64 entries)");
			setWordComment(listing, space, wordSize, 0x70, "page table end");

			log.appendMsg("Loaded 136-word header block at VA 0x0000");
		}
		catch (Exception e) {
			log.appendMsg("Could not create header block: " + e.getMessage());
		}

		/* Create CmdEntry struct data type */
		DataTypeManager dtm = program.getDataTypeManager();
		StructureDataType cmdEntryStruct = new StructureDataType(
				new CategoryPath("/TPE"), "CmdEntry", 0, dtm);
		cmdEntryStruct.add(WordDataType.dataType, "next_ptr", "Next command entry VA (0=last)");
		cmdEntryStruct.add(WordDataType.dataType, "handler", "Command handler function VA");
		cmdEntryStruct.add(WordDataType.dataType, "name_desc", "PLANC string descriptor for command name");
		cmdEntryStruct.add(WordDataType.dataType, "help_desc", "PLANC string descriptor for help text");
		cmdEntryStruct.add(WordDataType.dataType, "flags", "Command flags (0x0004=normal)");
		try {
			dtm.addDataType(cmdEntryStruct, null);
		}
		catch (Exception e) { /* ignore */ }

		/* Get reference manager and bookmark manager for later use */
		ReferenceManager refMgr = program.getReferenceManager();
		BookmarkManager bookmarkMgr = program.getBookmarkManager();

		/* Add comprehensive plate comment with ALL header info */
		StringBuilder meta = new StringBuilder();
		meta.append(String.format("=== TPE %s File: %s ===\n", header.fileType, provider.getName()));
		if (header.progName != null) {
			meta.append(String.format("Program name: %s\n", header.progName));
		}
		meta.append(String.format("Format: %s\n", header.isTest ? ":TEST (paged mode)" : ":NEXT (physical mode)"));
		meta.append("\n--- Header Fields ---\n");
		meta.append(String.format("w00-02  Flags:      0x%04X", header.flags));
		if ((header.flags & 0x4000) != 0) meta.append(" [PON]");
		if ((header.flags & 0x2000) != 0) meta.append(" [REX]");
		meta.append("\n");
		meta.append(String.format("w03     Checksum:   0x%04X\n", header.checksum));
		meta.append(String.format("w04     Marker:     0x%04X\n", header.marker));
		meta.append(String.format("w08     Field08:    0x%04X\n", header.field08));
		meta.append(String.format("w0E     Const0E:    0x%04X\n", header.const0e));
		meta.append(String.format("w14     ParamA:     0x%04X\n", header.paramA));
		meta.append(String.format("w15     ParamB:     0x%04X\n", header.paramB));
		meta.append(String.format("w2A     RtlibC1:    0x%04X\n", header.rtlibConst1));
		meta.append(String.format("w2B     RtlibC2:    0x%04X\n", header.rtlibConst2));
		meta.append(String.format("w2D     RtlibC3:    0x%04X\n", header.rtlibConst3));
		meta.append(String.format("w30     RtlibC4:    0x%04X\n", header.rtlibConst4));
		meta.append(String.format("Dependencies: %s\n", header.dependencies));

		meta.append("\n--- File Layout ---\n");
		meta.append(String.format("File size:     %d words (0x%04X)\n",
				header.fileSizeWords, header.fileSizeWords));
		meta.append(String.format("Header:        words 0x0000-0x0087 (%d words)\n", HEADER_WORDS));
		meta.append(String.format("Payload:       words 0x0088-0x%04X (%d words)\n",
				PAYLOAD_WORD_OFFSET + header.payloadWords - 1, header.payloadWords));
		meta.append(String.format("Load address:  VA 0x0000 (identity page mapping)\n"));

		meta.append("\n--- Page Table (VP -> PP) ---\n");
		meta.append(String.format("Mapped pages: %d\n", header.mappedPages));
		/* Show page table in compact form */
		StringBuilder ptLine = new StringBuilder();
		int lineCount = 0;
		for (int vp = 0; vp < header.pageTable.length; vp++) {
			int pp = header.pageTable[vp];
			if (pp == PAGE_UNMAPPED) continue;
			if (lineCount > 0 && lineCount % 8 == 0) {
				meta.append(ptLine).append("\n");
				ptLine.setLength(0);
			}
			if (ptLine.length() > 0) ptLine.append("  ");
			if (vp == pp) {
				ptLine.append(String.format("VP%02d=PP%02X", vp, pp));
			} else {
				ptLine.append(String.format("VP%02d->PP%02X", vp, pp));
			}
			lineCount++;
		}
		if (ptLine.length() > 0) {
			meta.append(ptLine).append("\n");
		}

		meta.append("\n--- Command Table (payload offset 0x78, 5-word linked list entries) ---\n");
		meta.append("Format: [next_ptr, handler, name_ptr, help_ptr, flags]\n");
		for (int i = 0; i < header.cmdEntryCount; i++) {
			int[] e = header.cmdEntries[i];
			meta.append(String.format("Cmd[%d]: next=0x%04X handler=0x%04X name=0x%04X help=0x%04X flags=0x%04X\n",
					i, e[0], e[1], e[2], e[3], e[4]));
		}

		meta.append("\n--- Payload Structure ---\n");
		meta.append("0x0000-0x0077: TPE runtime library (shared, 120 words)\n");
		meta.append("0x0078-0x007F: Entry point table (8 words)\n");
		meta.append("0x0080+:       Program name + test-specific code/data\n");

		/* Full header with named fields for all 136 words */
		meta.append("\n--- Full Header (all words, named where known) ---\n");
		for (int w = 0; w < HEADER_WORDS; w++) {
			int val = readWord(fileData, w);
			String label = getHeaderFieldName(w);
			if (label != null) {
				meta.append(String.format("w%04X: 0x%04X  %s\n", w, val, label));
			}
		}

		listing.setComment(blockStart, CodeUnit.PLATE_COMMENT, meta.toString());

		/* Label the TPE runtime library area (identical across all test files). */
		try {
			symbolTable.createLabel(blockStart, "TPE_RUNTIME_LIB", null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			/* ignore */
		}

		/* Label the command table start */
		int testCodeVA = baseVA + CMD_TABLE_OFFSET;
		Address testCodeAddr = space.getAddress((long) testCodeVA * wordSize);
		try {
			symbolTable.createLabel(testCodeAddr, "TEST_CODE_START", null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			/* ignore */
		}

		/* Add labels for mapped page boundaries */
		addPageLabels(header, symbolTable, space, wordSize);

		/* Try to find and label embedded test name string */
		String testName = findTestName(payloadData, testCodeVA * 2);
		if (testName != null) {
			listing.setComment(testCodeAddr, CodeUnit.EOL_COMMENT, "Test: " + testName);
		}

		/* Create labels for command table entries.
		 * Each entry has handler/name/help VA pointers. Handlers in the loaded
		 * range get disassembled; those outside are marked as external. */
		if (blockEnd != null) {
			AddressSet disassembleRange = new AddressSet(blockStart, blockEnd);

			/* Label the command table start */
			int cmdTableVA = baseVA + CMD_TABLE_OFFSET;
			Address cmdTableAddr = space.getAddress((long) cmdTableVA * wordSize);
			try {
				symbolTable.createLabel(cmdTableAddr, "CMD_TABLE", null, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) { /* ignore */ }

			/* Process each command entry. With the computed baseVA, the absolute
			 * VA pointers (handler, name, help) should resolve within the loaded
			 * payload: payloadOffset = absoluteVA - baseVA */
			int cmdHandlerCount = 0;
			for (int i = 0; i < header.cmdEntryCount; i++) {
				int[] entry = header.cmdEntries[i];
				int handlerVA = entry[1];
				int nameVA = entry[2];

				/* Read the command name string. The name_ptr points to a
				 * PLANC string descriptor: [text_ptr, ...]. Dereference
				 * the first word to get the actual text address. */
				String cmdName = null;
				int namePayloadOff = nameVA - header.baseVA;
				if (namePayloadOff > 0 && namePayloadOff + 1 < header.payloadWords) {
					/* Read text_ptr from the descriptor (word at byte offset) */
					int descByteOff = namePayloadOff * 2;
					if (descByteOff + 1 < payloadData.length) {
						int textVA = ((payloadData[descByteOff] & 0xFF) << 8) |
								(payloadData[descByteOff + 1] & 0xFF);
						int textPayloadOff = textVA - header.baseVA;
						if (textPayloadOff > 0 && textPayloadOff < header.payloadWords) {
							cmdName = readStringAt(payloadData, textPayloadOff * 2);
						}
					}
					Address nameAddr = space.getAddress((long) nameVA * wordSize);
					if (cmdName != null) {
						listing.setComment(nameAddr, CodeUnit.EOL_COMMENT, "CMD: " + cmdName);
					}
				}

				/* Label and disassemble handler if within loaded range */
				int handlerPayloadOff = handlerVA - header.baseVA;
				if (handlerVA > 0 && handlerPayloadOff > 0 && handlerPayloadOff < header.payloadWords) {
					Address handlerAddr = space.getAddress((long) handlerVA * wordSize);
					String handlerLabel;
					if (cmdName != null) {
						String clean = cmdName.split("[^A-Za-z0-9_-]")[0]
								.replace('-', '_').toLowerCase();
						handlerLabel = (clean.length() > 0) ? "cmd_" + clean :
								String.format("cmd_handler_%d", i);
					} else {
						handlerLabel = String.format("cmd_handler_%d", i);
					}

					try {
						symbolTable.createLabel(handlerAddr, handlerLabel,
								null, SourceType.IMPORTED);
					}
					catch (InvalidInputException e) { /* ignore */ }

					if (listing.getInstructionAt(handlerAddr) == null) {
						DisassembleCommand disCmd = new DisassembleCommand(
								handlerAddr, disassembleRange, true);
						disCmd.applyTo(program, monitor);
					}
					CreateFunctionCmd funcCmd = new CreateFunctionCmd(
							handlerLabel, handlerAddr, null, SourceType.ANALYSIS);
					funcCmd.applyTo(program, monitor);

					/* Mark as entry point */
					try { symbolTable.addExternalEntryPoint(handlerAddr); }
					catch (Exception e) { /* ignore */ }

					/* Bookmark the command handler */
					bookmarkMgr.setBookmark(handlerAddr, BookmarkType.ANALYSIS,
							"TPE Command", cmdName != null ? cmdName : handlerLabel);

					cmdHandlerCount++;
				}

				/* Apply CmdEntry struct and add cross-references */
				int entryVA = -1;
				if (i == 0) {
					entryVA = readPayloadWord(payloadData, CMD_TABLE_OFFSET);
				} else if (header.cmdEntries[i - 1][0] != 0) {
					entryVA = header.cmdEntries[i - 1][0];
				}
				if (entryVA > 0) {
					int ePayOff = entryVA - header.baseVA;
					if (ePayOff > 0 && ePayOff + CMD_ENTRY_WORDS <= header.payloadWords) {
						Address entryAddr = space.getAddress((long) entryVA * wordSize);
						/* Apply CmdEntry struct first */
						try {
							listing.clearCodeUnits(entryAddr,
									space.getAddress((long) (entryVA + CMD_ENTRY_WORDS - 1) * wordSize
											+ wordSize - 1), false);
							listing.createData(entryAddr, cmdEntryStruct);
						}
						catch (Exception e) { /* ignore — may conflict */ }

						/* THEN add cross-references (after struct is applied) */
						if (handlerVA > 0) {
							Address hField = space.getAddress((long) (entryVA + 1) * wordSize);
							Address hTarget = space.getAddress((long) handlerVA * wordSize);
							refMgr.addMemoryReference(hField, hTarget,
									RefType.DATA, SourceType.ANALYSIS, 0);
						}
						if (entry[0] > 0) {
							Address nTarget = space.getAddress((long) entry[0] * wordSize);
							refMgr.addMemoryReference(entryAddr, nTarget,
									RefType.DATA, SourceType.ANALYSIS, 0);
						}
						/* name_desc xref */
						if (nameVA > 0) {
							Address nField = space.getAddress((long) (entryVA + 2) * wordSize);
							Address nTarget = space.getAddress((long) nameVA * wordSize);
							refMgr.addMemoryReference(nField, nTarget,
									RefType.DATA, SourceType.ANALYSIS, 0);
						}
						/* help_desc xref */
						int helpVA = entry[3];
						if (helpVA > 0) {
							Address helpField = space.getAddress((long) (entryVA + 3) * wordSize);
							Address helpTarget = space.getAddress((long) helpVA * wordSize);
							refMgr.addMemoryReference(helpField, helpTarget,
									RefType.DATA, SourceType.ANALYSIS, 0);
						}
					}
				}
			}

			log.appendMsg(String.format("Parsed %d command table entries, %d handlers in file",
					header.cmdEntryCount, cmdHandlerCount));

			/* Scan for RADD SL,DX (0xCD67) function prologues — the reliable
			 * marker for PLANC function entry points. Disassemble from each one
			 * and create a function so Ghidra's analysis can propagate.
			 *
			 * Naming convention:
			 * - First RADD in file: <PROGNAME>_entry (test program entry dispatcher)
			 * - Subsequent: <PROGNAME>_func_XXXX (test-specific PLANC functions)
			 * PROGNAME is derived from the program name string at payload+0x80. */
			String prefix = "test";
			if (header.progName != null) {
				/* Extract first word of program name, lowercase, truncate */
				String raw = header.progName.split("[^A-Za-z0-9]")[0].toLowerCase();
				if (raw.length() > 12) raw = raw.substring(0, 12);
				if (raw.length() > 0) prefix = raw;
			}

			int funcCount = 0;
			boolean firstFunc = true;
			for (int i = 0; i < payloadByteLen - 1; i += 2) {
				int word = ((payloadData[i] & 0xFF) << 8) | (payloadData[i + 1] & 0xFF);
				if (word == RADD_SL_DX) {
					int wordAddr = baseVA + (i / 2);
					Address funcAddr = space.getAddress((long) wordAddr * wordSize);
					if (listing.getInstructionAt(funcAddr) == null) {
						DisassembleCommand disCmd = new DisassembleCommand(
								funcAddr, disassembleRange, true);
						disCmd.applyTo(program, monitor);
					}
					/* Create function with meaningful name */
					String funcName;
					if (firstFunc) {
						funcName = prefix + "_entry";
						firstFunc = false;
						/* Mark as program entry point */
						try {
							symbolTable.addExternalEntryPoint(funcAddr);
						}
						catch (Exception e) { /* ignore */ }
					} else {
						funcName = String.format("%s_func_%04x", prefix, wordAddr);
					}
					CreateFunctionCmd funcCmd = new CreateFunctionCmd(
							funcName, funcAddr, null, SourceType.ANALYSIS);
					funcCmd.applyTo(program, monitor);

					/* Bookmark each PLANC function */
					bookmarkMgr.setBookmark(funcAddr, BookmarkType.ANALYSIS,
							"PLANC Function", funcName);
					funcCount++;
				}
			}

			log.appendMsg(String.format("Found and created %d PLANC functions (RADD SL,DX), prefix='%s'",
					funcCount, prefix));
		}

		/* Bookmarks at key structural locations */
		bookmarkMgr.setBookmark(blockStart, BookmarkType.ANALYSIS,
				"TPE Structure", "Runtime library prefix (120 words, shared across all files)");
		bookmarkMgr.setBookmark(space.getAddress((long) RUNTIME_ENTRY_VA * wordSize),
				BookmarkType.ANALYSIS, "TPE Structure", "Command table pointer [VA 0x6C00]");
		if (header.progName != null) {
			Address nameAddr = space.getAddress((long) (baseVA + PROG_NAME_OFFSET) * wordSize);
			bookmarkMgr.setBookmark(nameAddr, BookmarkType.ANALYSIS,
					"TPE Structure", "Program name: " + header.progName);
		}

		/* ============================================================
		 * AUTO DATA TYPING — mark known data areas with proper types
		 * ============================================================ */
		monitor.setMessage("Applying data types...");
		int dataTyped = 0;

		/* 1. Shared runtime prefix (payload 0x00-0x77 = 120 words) — mark as word data */
		for (int w = 0; w < 0x78 && w < header.payloadWords; w++) {
			Address wAddr = space.getAddress((long) (baseVA + w) * wordSize);
			try {
				if (listing.getUndefinedDataAt(wAddr) != null) {
					listing.createData(wAddr, WordDataType.dataType);
					dataTyped++;
				}
			}
			catch (Exception e) { /* already defined or conflict */ }
		}

		/* Label known prefix fields */
		tryLabel(symbolTable, space, baseVA + 0x06, wordSize, "rtlib_ptr_0");
		tryLabel(symbolTable, space, baseVA + 0x07, wordSize, "rtlib_ptr_1");
		tryLabel(symbolTable, space, baseVA + 0x08, wordSize, "rtlib_ptr_2");
		tryLabel(symbolTable, space, baseVA + 0x09, wordSize, "rtlib_ptr_3");

		/* 2. Command table pointer at VA 0x6C00 (= payload+0x78) */
		Address cmdPtrAddr = space.getAddress((long) RUNTIME_ENTRY_VA * wordSize);
		tryLabel(symbolTable, space, RUNTIME_ENTRY_VA, wordSize, "cmd_table_ptr");
		try {
			if (listing.getUndefinedDataAt(cmdPtrAddr) != null) {
				listing.createData(cmdPtrAddr, WordDataType.dataType);
				listing.setComment(cmdPtrAddr, CodeUnit.EOL_COMMENT,
						String.format("-> 0x%04X (first command entry)",
								readPayloadWord(payloadData, CMD_TABLE_OFFSET)));
			}
		}
		catch (Exception e) { /* ignore */ }

		/* 3. Command table entries — mark each 5-word entry as words with field comments */
		for (int i = 0; i < header.cmdEntryCount; i++) {
			int[] entry = header.cmdEntries[i];
			/* Find this entry's VA by tracing from the first entry pointer */
			int entryVA = -1;
			if (i == 0) {
				entryVA = readPayloadWord(payloadData, CMD_TABLE_OFFSET);
			} else if (header.cmdEntries[i - 1][0] != 0) {
				entryVA = header.cmdEntries[i - 1][0]; /* prev entry's next_ptr */
			}
			if (entryVA <= 0) continue;

			int entryPayloadOff = entryVA - baseVA;
			if (entryPayloadOff < 0 || entryPayloadOff + CMD_ENTRY_WORDS > header.payloadWords) continue;

			String[] fieldNames = {"next_ptr", "handler", "name_desc", "help_desc", "flags"};
			for (int f = 0; f < CMD_ENTRY_WORDS; f++) {
				Address fAddr = space.getAddress((long) (entryVA + f) * wordSize);
				try {
					if (listing.getUndefinedDataAt(fAddr) != null) {
						listing.createData(fAddr, WordDataType.dataType);
						listing.setComment(fAddr, CodeUnit.EOL_COMMENT,
								String.format("cmd[%d].%s = 0x%04X", i, fieldNames[f], entry[f]));
						dataTyped++;
					}
				}
				catch (Exception e) { /* ignore */ }
			}
		}

		/* 4. PLANC string descriptors and text — for each command entry's name and help */
		int stringsFound = 0;
		for (int i = 0; i < header.cmdEntryCount; i++) {
			int[] entry = header.cmdEntries[i];
			/* Process name_ptr and help_ptr (entry fields 2 and 3) */
			for (int field = 2; field <= 3; field++) {
				int descVA = entry[field];
				int descPayloadOff = descVA - baseVA;
				if (descPayloadOff <= 0 || descPayloadOff + 3 > header.payloadWords) continue;

				/* PLANC string descriptor: [text_ptr, ?, ?] */
				int textVA = readPayloadWord(payloadData, descPayloadOff);
				int textPayloadOff = textVA - baseVA;

				/* Mark descriptor words */
				Address descAddr = space.getAddress((long) descVA * wordSize);
				try {
					if (listing.getUndefinedDataAt(descAddr) != null) {
						listing.createData(descAddr, WordDataType.dataType);
						listing.setComment(descAddr, CodeUnit.EOL_COMMENT,
								String.format("string descriptor -> text at 0x%04X", textVA));
						dataTyped++;
					}
				}
				catch (Exception e) { /* ignore */ }

				/* Create string at text address */
				if (textPayloadOff > 0 && textPayloadOff < header.payloadWords) {
					String text = readStringAt(payloadData, textPayloadOff * 2);
					if (text != null && text.length() > 0) {
						Address textAddr = space.getAddress((long) textVA * wordSize);
						try {
							if (listing.getUndefinedDataAt(textAddr) != null) {
								/* Create string data — length in bytes including terminator */
								int strByteLen = text.length() + 1; /* +1 for apostrophe */
								listing.createData(textAddr, StringDataType.dataType, strByteLen);
								String label = (field == 2) ? "cmd_name_" + i : "cmd_help_" + i;
								symbolTable.createLabel(textAddr, label, null, SourceType.IMPORTED);
								stringsFound++;
							}
						}
						catch (Exception e) { /* ignore — string might overlap code */ }
					}
				}
			}
		}

		/* 5. Program name and description strings (between payload+0x80 and first code) */
		int nameStartPayload = PROG_NAME_OFFSET;
		int firstCodePayload = header.payloadWords; /* default to end */
		/* Find first RADD to determine where code starts */
		for (int i = 0; i < payloadByteLen - 1; i += 2) {
			int word = ((payloadData[i] & 0xFF) << 8) | (payloadData[i + 1] & 0xFF);
			if (word == RADD_SL_DX) {
				firstCodePayload = i / 2;
				break;
			}
		}

		/* Scan for printable ASCII runs in the data area and create strings */
		int scanStart = nameStartPayload * 2;
		int scanEnd = Math.min(firstCodePayload * 2, payloadByteLen);
		int runStart = -1;
		for (int b = scanStart; b < scanEnd; b++) {
			int ch = payloadData[b] & 0xFF;
			boolean printable = (ch >= 0x20 && ch <= 0x7E) || ch == 0x0D || ch == 0x0A;
			if (printable) {
				if (runStart < 0) runStart = b;
			} else {
				if (runStart >= 0 && (b - runStart) >= 6) {
					/* Found a string run of at least 6 bytes */
					int strWordAddr = baseVA + (runStart / 2);
					Address strAddr = space.getAddress((long) strWordAddr * wordSize);
					int strLen = b - runStart;
					try {
						if (listing.getUndefinedDataAt(strAddr) != null) {
							listing.createData(strAddr, StringDataType.dataType, strLen);
							stringsFound++;
						}
					}
					catch (Exception e) { /* ignore */ }
				}
				runStart = -1;
			}
		}

		/* 6. Words between command entries and strings that aren't code — mark as word data */
		int cmdAreaStart = CMD_TABLE_OFFSET + 1; /* after the pointer word */
		int cmdAreaEnd = Math.min(firstCodePayload, header.payloadWords);
		for (int w = cmdAreaStart; w < cmdAreaEnd; w++) {
			Address wAddr = space.getAddress((long) (baseVA + w) * wordSize);
			try {
				if (listing.getUndefinedDataAt(wAddr) != null) {
					listing.createData(wAddr, WordDataType.dataType);
					dataTyped++;
				}
			}
			catch (Exception e) { /* ignore */ }
		}

		log.appendMsg(String.format("Auto-typed %d words and %d strings", dataTyped, stringsFound));

		/* ============================================================
		 * TPE-MON RUNTIME LIBRARY SYMBOLS
		 * ============================================================
		 * Test programs call TPE-MON runtime functions via indirect JPL
		 * through pointer tables. The pointer values (0x6900-0x69FF)
		 * are TPE-MON addresses that exist in memory at runtime but
		 * are NOT part of the test binary.
		 *
		 * The TPE-MON runtime at 0x6900+ is a jump table: each 2-word
		 * entry is JMP +1 (0xAA01) followed by the actual target addr.
		 * Test programs only reference the even addresses (0x6900,
		 * 0x6902, 0x6904, ...) which are the JMP instructions.
		 *
		 * We create an uninitialized memory block for the TPE-MON area
		 * and add labels so Ghidra shows meaningful names in the
		 * disassembly instead of raw addresses or DAT_ram_XXXX.
		 */
		monitor.setMessage("Adding TPE-MON runtime symbols...");
		int tpemonRtSymbols = 0;
		try {
			/* Create a small overlay block for the TPE-MON runtime jump table.
			 * Range 0x6900-0x69FF covers all known runtime entry points. */
			int rtStart = 0x6900;
			int rtEnd = 0x69FF;
			int rtByteLen = (rtEnd - rtStart + 1) * wordSize;
			Address rtBlockStart = space.getAddress((long) rtStart * wordSize);

			/* Only create if it doesn't already exist */
			if (memory.getBlock(rtBlockStart) == null) {
				MemoryBlock rtBlock = memory.createUninitializedBlock(
						"TPEMON_RT", rtBlockStart, rtByteLen, false);
				rtBlock.setComment("TPE-MON runtime library jump table (not part of test binary)");
				rtBlock.setRead(true);
				rtBlock.setWrite(false);
				rtBlock.setExecute(true);

				/* Known TPE-MON runtime entry points.
				 * Addresses are the jump table slots at even offsets in 0x6900-0x699x.
				 * Each maps to a JMP instruction in TPE-MON that redirects to the
				 * actual implementation. Names are derived from PLANC runtime analysis
				 * and cross-referencing with TPE-MON-100-B00.BPUN disassembly. */
				String[][] rtSymbols = {
					/* addr,  label,                    comment */
					{"6900", "tpemon_io_handler",       "I/O operation handler (→0x56EC)"},
					{"6902", "tpemon_csav",             "PLANC csav — create stack frame (→0x6650 rt_frame_next)"},
					{"6904", "tpemon_check_error",      "Check for I/O errors after operation (→0x6664 rt_stack_push)"},
					{"6906", "tpemon_error_display",    "Display error message (→0x6696)"},
					{"6908", "tpemon_io_dispatch",      "I/O dispatch by device type (→0x5676)"},
					{"690a", "tpemon_format_number",    "Format number for display (→0x55BD)"},
					{"690c", "tpemon_format_string",    "Format string for display (→0x564F)"},
					{"690e", "tpemon_show_description", "Show help text, wait for CR (→0x6631 rt_procedure_enter)"},
					{"6910", "tpemon_cret",             "PLANC cret — function return (→0x666A)"},
					{"6912", "tpemon_write_result",     "Write formatted result to terminal (→0x55D7)"},
					{"6914", "tpemon_error_report",     "Report error with code (→0x66D0)"},
					{"6916", "tpemon_error_leave",      "Error leave / cleanup (→0x66C7)"},
					{"6918", "tpemon_print_newline",    "Print newline sequence (→0x66E4)"},
					{"691a", "tpemon_terminal_ctrl",    "Terminal control operation (→0x5703)"},
					{"691c", "tpemon_string_output",    "String output to terminal (→0x6682)"},
					{"691e", "tpemon_string_format",    "String formatting (→0x66AB)"},
					{"6920", "tpemon_terminal_read",    "Read bytes from terminal (→0x5E73)"},
					{"6922", "tpemon_terminal_readln",  "Read line from terminal (→0x5EC7)"},
					{"6924", "tpemon_terminal_status",  "Check terminal status (→0x5EEC)"},
					{"6926", "tpemon_terminal_write",   "Write/send to terminal (→0x5F0A)"},
					{"6928", "tpemon_terminal_writeln", "Write line to terminal (→0x5F9B)"},
					{"692a", "tpemon_terminal_flush",   "Flush terminal output (→0x5FE7)"},
					{"692c", "tpemon_file_open",        "Open file operation (→0x594D)"},
					{"692e", "tpemon_terminal_send",    "Send raw bytes to terminal (→0x5963)"},
					{"6930", "tpemon_file_read",        "Read from file (→0x5CC4)"},
					{"6932", "tpemon_terminal_raw_send","Raw terminal send (→0x5CD1)"},
					{"6934", "tpemon_file_write",       "Write to file (→0x5D16)"},
					{"6936", "tpemon_file_close",       "Close file (→0x5D1B)"},
					{"6938", "tpemon_send_esc_prefix",  "Send escape sequence header (→0x5BAE)"},
					{"693a", "tpemon_channel_setup",    "Channel/device setup (→0x5D20)"},
					{"693c", "tpemon_channel_config",   "Channel configuration (→0x5D2E)"},
					{"693e", "tpemon_device_status",    "Device status query (→0x5DAA)"},
					{"6940", "tpemon_device_control",   "Device control operation (→0x5DF9)"},
					{"6942", "tpemon_read_single_char", "Read single character (→0x5E07)"},
					{"6944", "tpemon_device_reset",     "Device reset (→0x5E6B)"},
					{"6946", "tpemon_device_ident",     "Device identification (→0x5E6F)"},
					{"6948", "tpemon_iie_set_bits",     "Set IIE register bits (→0x0117)"},
					{"694a", "tpemon_iie_clear_bits",   "Clear IIE register bits (→0x011A)"},
					{"694c", "tpemon_iie_update",       "Update IIE register (→0x0125)"},
					{"694e", "tpemon_iie_mask",         "Mask IIE register (→0x0128)"},
					{"6950", "tpemon_file_ops_1",       "File operation 1 (→0x266C)"},
					{"6952", "tpemon_file_ops_2",       "File operation 2 (→0x268F)"},
					{"6954", "tpemon_file_ops_3",       "File operation 3 (→0x26C3)"},
					{"6956", "tpemon_file_ops_4",       "File operation 4 (→0x2791)"},
					{"6958", "tpemon_file_ops_5",       "File operation 5 (→0x2920)"},

					/* Additional runtime addresses used by test programs */
					{"6978", "tpemon_iox_setup",        "IOX opcode setup for executor"},
					{"697a", "tpemon_save_sts",         "Save STS register state"},
					{"697c", "tpemon_iox_timeout",      "IOX operation with timeout"},
					{"6992", "tpemon_validate_io",      "Validate I/O operation result"},
					{"69ae", "tpemon_allocate_memory",  "Allocate memory block (TPballocate)"},
				};

				for (int s = 0; s < rtSymbols.length; s++) {
					int symAddr = Integer.parseInt(rtSymbols[s][0], 16);
					String symLabel = rtSymbols[s][1];
					String symComment = rtSymbols[s][2];
					Address addr = space.getAddress((long) symAddr * wordSize);
					try {
						symbolTable.createLabel(addr, symLabel, null, SourceType.IMPORTED);
						listing.setComment(addr, CodeUnit.EOL_COMMENT, symComment);
						tpemonRtSymbols++;
					}
					catch (Exception e) { /* symbol might already exist */ }
				}

				log.appendMsg(String.format("Created TPE-MON runtime block (0x%04X-0x%04X) with %d symbols",
						rtStart, rtEnd, tpemonRtSymbols));
			}
		}
		catch (Exception e) {
			log.appendMsg("Note: Could not create TPE-MON runtime block: " + e.getMessage());
		}

		/* Also label the PLANC runtime implementations (0x6619-0x66FF) if not already in a block */
		try {
			int plancRtStart = 0x6619;
			int plancRtEnd = 0x66FF;
			int plancByteLen = (plancRtEnd - plancRtStart + 1) * wordSize;
			Address plancBlockStart = space.getAddress((long) plancRtStart * wordSize);

			if (memory.getBlock(plancBlockStart) == null) {
				MemoryBlock plancBlock = memory.createUninitializedBlock(
						"TPEMON_PLANC_RT", plancBlockStart, plancByteLen, false);
				plancBlock.setComment("PLANC runtime: csav, cret, cleav implementations");
				plancBlock.setRead(true);
				plancBlock.setWrite(false);
				plancBlock.setExecute(true);

				String[][] plancSymbols = {
					{"6631", "planc_init",  "PLANC INIT — rt_procedure_enter: create first/new stack frame"},
					{"6650", "planc_csav",  "PLANC csav — rt_frame_next: push stack frame (ENTR equivalent)"},
					{"6664", "planc_cleav", "PLANC cleav — rt_stack_push: error leave (ELEAV equivalent)"},
					{"666a", "planc_cret",  "PLANC cret — function return: restore B=PREVB, P=LINK (LEAVE equivalent)"},
				};

				for (int s = 0; s < plancSymbols.length; s++) {
					int symAddr = Integer.parseInt(plancSymbols[s][0], 16);
					Address addr = space.getAddress((long) symAddr * wordSize);
					try {
						symbolTable.createLabel(addr, plancSymbols[s][1], null, SourceType.IMPORTED);
						listing.setComment(addr, CodeUnit.EOL_COMMENT, plancSymbols[s][2]);
						tpemonRtSymbols++;
					}
					catch (Exception e) { /* ignore */ }
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Note: Could not create PLANC runtime block: " + e.getMessage());
		}

		log.appendMsg(String.format("Total TPE-MON runtime symbols added: %d", tpemonRtSymbols));

		monitor.setMessage("TPE loading complete");
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	/** Detect :TEST or :NEXT file by checking magic words */
	private boolean probeTPE(ByteProvider p) throws IOException {
		long len = p.length();
		if (len < HEADER_BYTES) return false;

		/* Read first 3 words (6 bytes) as big-endian */
		int w0 = readWordFromProvider(p, 0);
		int w1 = readWordFromProvider(p, 1);
		int w2 = readWordFromProvider(p, 2);

		/* All three words must be identical and match known magic */
		if (w0 != w1 || w1 != w2) return false;
		if (w0 != MAGIC_TEST && w0 != MAGIC_NEXT) return false;

		/* Verify marker word at offset 4 */
		int w4 = readWordFromProvider(p, 4);
		if (w4 != 0xFFFF) return false;

		return true;
	}

	/** Parse the 136-word header from file data */
	private TpeHeader parseHeader(byte[] fileData, MessageLog log) {
		TpeHeader h = new TpeHeader();

		h.flags = readWord(fileData, OFF_FLAGS);
		h.pid = readWord(fileData, OFF_PID);
		h.pie = readWord(fileData, OFF_PIE);
		h.checksum = readWord(fileData, OFF_CHECKSUM);
		h.marker = readWord(fileData, OFF_MARKER);
		h.field08 = readWord(fileData, OFF_FIELD_08);
		h.const0e = readWord(fileData, OFF_CONST_0E);
		h.paramA = readWord(fileData, OFF_PARAM_A);
		h.paramB = readWord(fileData, OFF_PARAM_B);

		h.isTest = (h.flags == MAGIC_TEST);
		h.fileType = h.isTest ? "TEST" : "NEXT";
		h.fileSizeWords = fileData.length / 2;
		h.payloadWords = h.fileSizeWords - HEADER_WORDS;

		/* Runtime library constants */
		h.rtlibConst1 = readWord(fileData, OFF_RTLIB_CONST1);
		h.rtlibConst2 = readWord(fileData, OFF_RTLIB_CONST2);
		h.rtlibConst3 = readWord(fileData, OFF_RTLIB_CONST3);
		h.rtlibConst4 = readWord(fileData, OFF_RTLIB_CONST4);

		/* Decode dependency string */
		h.dependencies = decodeDependencies(fileData);

		/* Parse page table */
		h.pageTable = new int[OFF_PAGE_TABLE_END - OFF_PAGE_TABLE + 1];
		h.mappedPages = 0;
		for (int i = 0; i < h.pageTable.length; i++) {
			h.pageTable[i] = readWord(fileData, OFF_PAGE_TABLE + i);
			if (h.pageTable[i] != PAGE_UNMAPPED) {
				h.mappedPages++;
			}
		}

		/* Command table: payload word 0x78 contains a POINTER to the first
		 * command entry (like [VA 0x6C00] in TPE-MON). Dereference it and
		 * follow the linked list of 5-word entries:
		 * [0] next_ptr, [1] handler, [2] name_ptr, [3] help_ptr, [4] flags */
		int baseVA = RUNTIME_ENTRY_VA - CMD_TABLE_OFFSET;
		int maxEntries = 20;
		int[][] tempEntries = new int[maxEntries][CMD_ENTRY_WORDS];
		int entryIdx = 0;

		/* Read the pointer at payload+0x78 = first entry VA */
		int firstEntryVA = readWord(fileData, PAYLOAD_WORD_OFFSET + CMD_TABLE_OFFSET);
		int entryPayloadOff = firstEntryVA - baseVA;

		while (entryIdx < maxEntries && entryPayloadOff > 0 &&
				entryPayloadOff + CMD_ENTRY_WORDS <= h.payloadWords) {
			int entryFileOff = PAYLOAD_WORD_OFFSET + entryPayloadOff;
			int[] entry = new int[CMD_ENTRY_WORDS];
			for (int f = 0; f < CMD_ENTRY_WORDS; f++) {
				entry[f] = readWord(fileData, entryFileOff + f);
			}
			tempEntries[entryIdx] = entry;
			entryIdx++;

			int nextPtr = entry[0];
			if (nextPtr == 0) break;

			entryPayloadOff = nextPtr - baseVA;
			if (entryPayloadOff <= 0 || entryPayloadOff >= h.payloadWords) break;
		}

		h.cmdEntries = new int[entryIdx][];
		for (int i = 0; i < entryIdx; i++) {
			h.cmdEntries[i] = tempEntries[i];
		}
		h.cmdEntryCount = entryIdx;

		/* Program name from payload offset 0x80 */
		h.progName = decodeProgName(fileData, PAYLOAD_WORD_OFFSET + PROG_NAME_OFFSET);

		log.appendMsg(String.format("TPE %s: %d payload words, %d mapped pages, deps: %s",
				h.fileType, h.payloadWords, h.mappedPages, h.dependencies));

		return h;
	}

	/** Decode program name from a word offset (ASCII, apostrophe-terminated).
	 * Skips leading NUL bytes (name is often preceded by 2-4 zero bytes). */
	private String decodeProgName(byte[] fileData, int wordOffset) {
		StringBuilder sb = new StringBuilder();
		int byteStart = wordOffset * 2;
		int maxLen = 64;
		boolean foundText = false;
		for (int i = 0; i < maxLen && (byteStart + i) < fileData.length; i++) {
			int b = fileData[byteStart + i] & 0xFF;
			if (b == 0x27) break;  /* apostrophe = SINTRAN string terminator */
			if (b == 0x00) {
				if (foundText) break;  /* NUL after text = end */
				continue;              /* skip leading NULs */
			}
			if (b >= 0x20 && b <= 0x7E) {
				sb.append((char) b);
				foundText = true;
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	/** Decode the dependency string from words 0x19-0x27 */
	private String decodeDependencies(byte[] fileData) {
		StringBuilder sb = new StringBuilder();
		int byteStart = OFF_DEPS_START * 2;
		int byteEnd = (OFF_DEPS_END + 1) * 2;

		for (int i = byteStart; i < byteEnd && i < fileData.length; i++) {
			int b = fileData[i] & 0xFF;
			if (b == 0x0A) break;        /* LF = end */
			if (b == 0x0D) {             /* CR = separator */
				sb.append(", ");
			} else if (b == 0x27) {
				/* apostrophe = SINTRAN string terminator, skip */
			} else if (b >= 0x20 && b <= 0x7E) {
				sb.append((char) b);
			}
		}
		return sb.toString();
	}

	/** Try to find the test program name from the test-specific code area */
	private String findTestName(byte[] payloadData, int searchByteOffset) {
		/* Look for a run of printable ASCII ending with apostrophe (0x27) */
		int maxSearch = Math.min(searchByteOffset + 200, payloadData.length);
		StringBuilder run = new StringBuilder();
		for (int i = searchByteOffset; i < maxSearch; i++) {
			int b = payloadData[i] & 0xFF;
			if (b >= 0x20 && b <= 0x7E) {
				run.append((char) b);
			} else {
				if (run.length() >= 10) {
					String s = run.toString();
					/* Remove trailing apostrophe if present */
					if (s.endsWith("'")) {
						s = s.substring(0, s.length() - 1);
					}
					return s;
				}
				run.setLength(0);
			}
		}
		return null;
	}

	/** Add labels at virtual page boundaries for mapped pages. */
	private void addPageLabels(TpeHeader header, SymbolTable symTable,
			AddressSpace space, int wordSize) {
		for (int vp = 0; vp < header.pageTable.length; vp++) {
			int pp = header.pageTable[vp];
			if (pp == PAGE_UNMAPPED) continue;

			int vpWordAddr = vp * PAGE_SIZE_WORDS;
			/* Check if this page falls within the loaded payload range */
			if (vpWordAddr < header.baseVA || vpWordAddr >= header.baseVA + header.payloadWords) continue;

			Address pageAddr = space.getAddress((long) vpWordAddr * wordSize);
			try {
				symTable.createLabel(pageAddr, String.format("VPAGE_%d_PP_%02X", vp, pp),
						null, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				/* ignore */
			}
		}
	}

	/** Return a human-readable label for a header word offset, or null to skip */
	private static String getHeaderFieldName(int wordOffset) {
		if (wordOffset >= OFF_PAGE_TABLE && wordOffset <= OFF_PAGE_TABLE_END) {
			return null; /* page table — shown separately */
		}
		if (wordOffset >= OFF_DEPS_START && wordOffset <= OFF_DEPS_END) {
			return null; /* dependency string — shown separately */
		}
		switch (wordOffset) {
			case 0x00: return "flags (magic)";
			case 0x01: return "flags (repeat)";
			case 0x02: return "flags (repeat)";
			case 0x03: return "checksum";
			case 0x04: return "marker (0xFFFF)";
			case 0x05: return "unknown_05";
			case 0x06: return "unknown_06";
			case 0x07: return "unknown_07";
			case 0x08: return "version/variant";
			case 0x09: return "unknown_09";
			case 0x0A: return "unknown_0A";
			case 0x0B: return "LRB reg block start (level 1 P)";
			case 0x0C: return "level 1 X";
			case 0x0D: return "level 1 T";
			case 0x0E: return "const_0E (always 0x24DC)";
			case 0x0F: return "unknown_0F";
			case 0x10: return "unknown_10";
			case 0x11: return "unknown_11";
			case 0x12: return "unknown_12";
			case 0x13: return "unknown_13";
			case 0x14: return "paramA";
			case 0x15: return "paramB";
			case 0x16: return "unknown_16";
			case 0x17: return "unknown_17";
			case 0x18: return "unknown_18";
			case 0x2A: return "rtlib const1 (always 0x04CB)";
			case 0x2B: return "rtlib const2 (always 0x67C2)";
			case 0x2C: return "unknown_2C";
			case 0x2D: return "rtlib const3 (always 0x040F)";
			case 0x2E: return "unknown_2E";
			case 0x2F: return "unknown_2F";
			case 0x30: return "rtlib const4 (always 0x040F)";
			default:
				/* Words 0x71-0x87 are remainder of LRB register blocks */
				if (wordOffset >= 0x71 && wordOffset <= 0x87) {
					int level = 1 + (wordOffset - 0x0B) / 8;
					int reg = (wordOffset - 0x0B) % 8;
					String[] regNames = {"P", "X", "T", "A", "D", "L", "STS", "B"};
					if (level <= 15 && reg < 8) {
						return String.format("LRB level %d %s", level, regNames[reg]);
					}
				}
				return String.format("unknown_%02X", wordOffset);
		}
	}

	/** Set an EOL comment on a word address */
	private static void setWordComment(Listing listing, AddressSpace space,
			int wordSize, int wordAddr, String comment) {
		try {
			Address addr = space.getAddress((long) wordAddr * wordSize);
			listing.setComment(addr, CodeUnit.EOL_COMMENT, comment);
		}
		catch (Exception e) { /* ignore */ }
	}

	/** Try to create a label, ignoring errors */
	private static void tryLabel(SymbolTable symTable, AddressSpace space,
			int wordAddr, int wordSize, String name) {
		try {
			symTable.createLabel(space.getAddress((long) wordAddr * wordSize),
					name, null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) { /* ignore */ }
	}

	/** Read a big-endian word from payloadData at a payload word offset */
	private static int readPayloadWord(byte[] payloadData, int payloadWordOffset) {
		int byteOff = payloadWordOffset * 2;
		if (byteOff + 1 >= payloadData.length) return 0;
		return ((payloadData[byteOff] & 0xFF) << 8) | (payloadData[byteOff + 1] & 0xFF);
	}

	/** Read an ASCII string from byte offset in payload data (apostrophe-terminated) */
	private static String readStringAt(byte[] data, int byteOffset) {
		StringBuilder sb = new StringBuilder();
		for (int i = byteOffset; i < data.length && i < byteOffset + 80; i++) {
			int b = data[i] & 0xFF;
			if (b == 0x27) break;  /* apostrophe = end */
			if (b == 0x00) break;
			if (b >= 0x20 && b <= 0x7E) {
				sb.append((char) b);
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	/** Read a big-endian 16-bit word from a byte array at a word offset */
	private static int readWord(byte[] data, int wordOffset) {
		int byteOff = wordOffset * 2;
		if (byteOff + 1 >= data.length) return 0;
		return ((data[byteOff] & 0xFF) << 8) | (data[byteOff + 1] & 0xFF);
	}

	/** Read a big-endian 16-bit word from a ByteProvider at a word offset */
	private static int readWordFromProvider(ByteProvider p, int wordOffset) throws IOException {
		long byteOff = (long) wordOffset * 2;
		int hi = p.readByte(byteOff) & 0xFF;
		int lo = p.readByte(byteOff + 1) & 0xFF;
		return (hi << 8) | lo;
	}
}
