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

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * ND-100 :PROG (SINTRAN III executable) file format loader for Ghidra.
 *
 * Layout (big-endian throughout):
 *   Offset 0x00000:  Header 1  (256-word / 512-byte header block)
 *   Offset 0x00200:  Bank 1 image — (Last1 - First1 + 1) words, loaded at First1
 *   Offset 0x20000:  Header 2  (optional, only present on 2-bank programs)
 *   Offset 0x20200:  Bank 2 image (optional) — loaded at First2 in the alternate page table
 *
 * Header layout (12 bytes, six 16-bit words):
 *   word 0:  Start address      (entry point)
 *   word 1:  Restart address
 *   word 2:  First address bank 1
 *   word 3:  Last  address bank 1
 *   word 4:  First address bank 2  (0xFFFF for 1-bank programs)
 *   word 5:  Last  address bank 2  (0x0000 for 1-bank programs)
 *
 * 2-bank programs always have a hole in the file between the end of bank 1 and
 * offset 0x20000, so the file size is not necessarily contiguous data.
 *
 * Bank 2 is loaded into a Ghidra overlay block named "BANK2" so that the same
 * 16-bit virtual address range can hold both segments (which is how the real
 * machine maps it: bank 2 is reached via the alternative page table after
 * MON ALTON).
 */
public class ProgLoader extends AbstractProgramWrapperLoader {

	public static final String PROG_NAME = "ND-100 :PROG (SINTRAN-III Executable)";

	private static final long HEADER1_OFFSET     = 0L;
	private static final long BANK1_DATA_OFFSET  = 512L;
	private static final long HEADER2_OFFSET     = 0x20000L;
	private static final long BANK2_DATA_OFFSET  = 0x20200L;
	private static final int  BANK2_EMPTY_FIRST  = 0xFFFF;
	private static final int  BANK2_EMPTY_LAST   = 0x0000;

	private static class ProgHeader {
		int start;
		int restart;
		int first1, last1;
		int first2, last2;

		boolean isOneBank() {
			return first2 == BANK2_EMPTY_FIRST && last2 == BANK2_EMPTY_LAST;
		}

		int bank1Words() { return (last1 - first1 + 1) & 0xFFFF; }
		int bank2Words() { return isOneBank() ? 0 : ((last2 - first2 + 1) & 0xFFFF); }
	}

	@Override
	public String getName() {
		return PROG_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!probeProg(provider)) {
			return List.of();
		}
		LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("ND-100:BE:16:default", "default");
		return List.of(new LoadSpec(this, 0, lcs, true));
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		TaskMonitor monitor   = settings.monitor();
		MessageLog log        = settings.log();

		monitor.setMessage("Loading PROG file...");

		ProgHeader h = readHeader(provider, HEADER1_OFFSET);

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symtab = program.getSymbolTable();
		Listing listing = program.getListing();

		// ND-100 is word-addressed; default-space wordSize is 2.
		int wordSize = space.getAddressableUnitSize();

		long bank1Bytes = (long) h.bank1Words() * 2L;
		Address bank1Start = space.getAddress((h.first1 & 0xFFFFL) * wordSize);
		Address bank1End   = null;

		if (h.bank1Words() > 0) {
			byte[] data = readBytes(provider, BANK1_DATA_OFFSET, bank1Bytes, "bank 1");
			try {
				MemoryBlock blk = memory.createInitializedBlock(
						"BANK1", bank1Start, new java.io.ByteArrayInputStream(data),
						data.length, monitor, false);
				blk.setComment(String.format("PROG bank 1: 0%06o..0%06o (%d words)",
						h.first1, h.last1, h.bank1Words()));
				blk.setRead(true);
				blk.setWrite(true);
				blk.setExecute(true);
				bank1End = blk.getEnd();
				log.appendMsg(String.format("Bank 1: %d words at 0%06o..0%06o (0x%04X..0x%04X)",
						h.bank1Words(), h.first1, h.last1, h.first1, h.last1));
			}
			catch (Exception e) {
				throw new IOException("Failed to create BANK1 memory block: " + e.getMessage(), e);
			}
		}
		else {
			log.appendMsg("Bank 1 is empty — unusual for a PROG file");
		}

		Address bank2Start = null;
		Address bank2End   = null;
		if (!h.isOneBank() && h.bank2Words() > 0) {
			long bank2Bytes = (long) h.bank2Words() * 2L;
			if (provider.length() < BANK2_DATA_OFFSET + bank2Bytes) {
				log.appendMsg(String.format(
						"Bank 2 truncated: file is %d bytes, need %d — skipping bank 2",
						provider.length(), BANK2_DATA_OFFSET + bank2Bytes));
			}
			else {
				byte[] data = readBytes(provider, BANK2_DATA_OFFSET, bank2Bytes, "bank 2");
				bank2Start = space.getAddress((h.first2 & 0xFFFFL) * wordSize);
				try {
					MemoryBlock blk = memory.createInitializedBlock(
							"BANK2", bank2Start, new java.io.ByteArrayInputStream(data),
							data.length, monitor, true /* overlay */);
					blk.setComment(String.format(
							"PROG bank 2 (alternate page table): 0%06o..0%06o (%d words)",
							h.first2, h.last2, h.bank2Words()));
					blk.setRead(true);
					blk.setWrite(true);
					blk.setExecute(true);
					bank2Start = blk.getStart();
					bank2End   = blk.getEnd();
					log.appendMsg(String.format("Bank 2 (overlay): %d words at 0%06o..0%06o",
							h.bank2Words(), h.first2, h.last2));
				}
				catch (Exception e) {
					log.appendMsg("Failed to create BANK2 overlay: " + e.getMessage());
					bank2Start = null;
					bank2End = null;
				}
			}
		}

		// Resolve the entry point first; both the labels and the plate
		// comment hang off it so the user lands on the metadata when they
		// navigate to the entry.
		Address entryAddr = space.getAddress((h.start & 0xFFFFL) * wordSize);

		// Build a filename-derived label so multiple PROG files in the same
		// project don't collide on a generic `START`.
		String progName = sanitizeName(provider.getName());

		// Plate comment with the full header summary at the entry point.
		StringBuilder meta = new StringBuilder();
		meta.append(String.format("PROG file: %s\n", provider.getName()));
		meta.append(String.format("Format: %s\n", h.isOneBank() ? "1-bank" : "2-bank"));
		meta.append(String.format("Start address:   0%06o (0x%04X)\n", h.start, h.start));
		meta.append(String.format("Restart address: 0%06o (0x%04X)\n", h.restart, h.restart));
		meta.append(String.format("Bank 1: 0%06o..0%06o (%d words)\n",
				h.first1, h.last1, h.bank1Words()));
		if (!h.isOneBank()) {
			meta.append(String.format("Bank 2: 0%06o..0%06o (%d words)",
					h.first2, h.last2, h.bank2Words()));
		}
		else {
			meta.append("Bank 2: (none)");
		}
		listing.setComment(entryAddr, CodeUnit.PLATE_COMMENT, meta.toString());

		symtab.addExternalEntryPoint(entryAddr);
		try {
			// Primary label: <basename> — distinctive in the symbol tree.
			symtab.createLabel(entryAddr, progName, null, SourceType.IMPORTED);
			// Secondary, generic label so cross-loader habits keep working.
			symtab.createLabel(entryAddr, "START", null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Warning: could not create entry label: " + e.getMessage());
		}
		log.appendMsg(String.format("Entry (%s): 0%06o (0x%04X)", progName, h.start, h.start));

		if (h.restart != h.start) {
			Address restartAddr = space.getAddress((h.restart & 0xFFFFL) * wordSize);
			symtab.addExternalEntryPoint(restartAddr);
			try {
				symtab.createLabel(restartAddr, progName + "_RESTART", null, SourceType.IMPORTED);
				symtab.createLabel(restartAddr, "RESTART", null, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg("Warning: could not create RESTART label: " + e.getMessage());
			}
			log.appendMsg(String.format("Restart: 0%06o (0x%04X)", h.restart, h.restart));
		}

		// Disassemble from the entry point through the bank-1 block. Bank-2 is
		// left to the user to disassemble manually since we don't know which
		// addresses there are reachable without running the program.
		if (bank1Start != null && bank1End != null) {
			AddressSet range = new AddressSet(bank1Start, bank1End);
			DisassembleCommand cmd = new DisassembleCommand(entryAddr, range, true);
			cmd.applyTo(program, monitor);
		}

		monitor.setMessage("PROG loading complete");
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	// -----------------------------------------------------------------------
	// Detection / parsing
	// -----------------------------------------------------------------------

	private boolean probeProg(ByteProvider p) throws IOException {
		long len = p.length();
		// Need at least the header + one word of payload.
		if (len < BANK1_DATA_OFFSET + 2L) {
			return false;
		}

		ProgHeader h = readHeader(p, HEADER1_OFFSET);

		// Bank 1 is mandatory and must have first <= last.
		if ((h.first1 & 0xFFFF) > (h.last1 & 0xFFFF)) return false;
		int bank1 = h.bank1Words();
		if (bank1 == 0) return false;

		long needBank1 = BANK1_DATA_OFFSET + (long) bank1 * 2L;
		if (len < needBank1) return false;

		if (h.isOneBank()) {
			// 1-bank file size is just bank1 + header, often padded to 512-byte
			// block boundary. We don't enforce padding strictly; some tools
			// (e.g. FTP from Norsk Data) trim trailing zeros.
			return true;
		}

		// 2-bank: bank 2 must also be valid and a Header 2 must fit at 0x20000.
		if ((h.first2 & 0xFFFF) > (h.last2 & 0xFFFF)) return false;
		if (len < HEADER2_OFFSET + 12L) return false;
		long needBank2 = BANK2_DATA_OFFSET + (long) h.bank2Words() * 2L;
		if (len < needBank2) return false;
		return true;
	}

	private ProgHeader readHeader(ByteProvider p, long off) throws IOException {
		ProgHeader h = new ProgHeader();
		h.start   = readWord(p, off + 0);
		h.restart = readWord(p, off + 2);
		h.first1  = readWord(p, off + 4);
		h.last1   = readWord(p, off + 6);
		h.first2  = readWord(p, off + 8);
		h.last2   = readWord(p, off + 10);
		return h;
	}

	private int readWord(ByteProvider p, long off) throws IOException {
		int hi = p.readByte(off) & 0xFF;
		int lo = p.readByte(off + 1) & 0xFF;
		return ((hi << 8) | lo) & 0xFFFF;
	}

	/**
	 * Turn a file name into a Ghidra-safe identifier: drop a trailing
	 * `.prog` extension (case-insensitive), drop a SINTRAN-style leading
	 * `:`, and replace any character outside [A-Za-z0-9_] with `_`.
	 * Falls back to "PROG" if the result would be empty or start with a
	 * digit.
	 */
	private static String sanitizeName(String fileName) {
		String s = fileName;
		int slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
		if (slash >= 0) s = s.substring(slash + 1);
		if (s.toLowerCase().endsWith(".prog")) s = s.substring(0, s.length() - 5);
		if (s.startsWith(":")) s = s.substring(1);
		s = s.replaceAll("[^A-Za-z0-9_]", "_");
		if (s.isEmpty() || !Character.isJavaIdentifierStart(s.charAt(0))) {
			s = "PROG_" + s;
		}
		return s;
	}

	private byte[] readBytes(ByteProvider p, long off, long count, String what) throws IOException {
		if (count <= 0 || count > Integer.MAX_VALUE) {
			throw new IOException("Invalid " + what + " size: " + count);
		}
		byte[] buf = new byte[(int) count];
		try (InputStream in = p.getInputStream(off)) {
			int read = 0;
			while (read < buf.length) {
				int n = in.read(buf, read, buf.length - read);
				if (n < 0) {
					throw new IOException(String.format(
							"Unexpected EOF reading %s at offset 0x%X (got %d of %d bytes)",
							what, off, read, buf.length));
				}
				read += n;
			}
		}
		return buf;
	}
}
