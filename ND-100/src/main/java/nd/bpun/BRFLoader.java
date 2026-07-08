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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 * ND-100 BRF (Binary Relocatable Format) loader for Ghidra.
 *
 * BRF is the relocatable object format produced by all ND language processors
 * (MAC, FORTRAN, COBOL, PLANC, BASIC, PASCAL, NPL, C) and consumed by the
 * ND Relocating Loader / Real Time Loader / BRF Editor.
 *
 * Primary sources:
 *   - ND-60.066.04 "ND Relocating Loader", chapter 2 (format) and chapter 3 (BRF Editor)
 *   - BRF-FILE-FORMAT.md (NDInsight repo) — spec validated byte-by-byte against
 *     real PLANC compiler output (all 348 unit checksums verify)
 *
 * Format summary (all facts below VERIFIED against real files unless noted):
 *   - Byte stream of groups: <control byte> [S-group] [P-groups...]
 *   - P-group = one 16-bit word, big-endian (MSB first)
 *   - S-group = symbol of 1-7 chars in six-bit code (ASCII - 040), right-justified,
 *     space(0)-padded, packed MSB-first; 4 bytes by default, 6 bytes after LONGF
 *   - A unit runs BEG (017) ... END (021) <checksum>; the checksum word is the
 *     two's complement (negation) of the 16-bit sum of everything from BEG
 *     through the END byte, i.e. the whole unit INCLUDING the checksum word
 *     sums to 0 (mod 2^16). Verified byte-by-byte against real ND BRF output
 *     (e.g. ADV-EXIT.BRF: sum-through-END 0x20EE + stored 0xDF12 = 0x0000)
 *   - LONGF (032) is per-unit: every BEG resets S-groups back to 4 bytes
 *   - Zero bytes (FEED) pad between units; a single EOF (023) byte ends the file
 *
 * This loader emulates the ND Relocating Loader: it loads every unit
 * consecutively from a base address (default 0), applies all relocations and
 * fix-ups, resolves ENTR/REF symbol linkage, and emits the resulting memory
 * image plus one Ghidra label per ENTR/MAIN symbol.
 *
 * Differences from the real loader (deliberate, for static analysis):
 *   - Library units (LIBR) are ALWAYS loaded, not conditionally — we want to
 *     see all code, not just what one particular main program pulls in.
 *   - Two-bank mode (PMO/DMO/LRP/LRD) is loaded into the single default space;
 *     a warning is logged if those control numbers occur.
 *
 * REF semantics (ND-60.066.04 only says the symbol "is referenced in CLC"; it
 * does not state whether CLC advances): empirically established against
 * encos-err-i-b01.brf that REF stores its reference-chain link word AT (CLC)
 * and advances CLC by one. With that rule all 567 AFR fix-up targets in the
 * file land inside the already-loaded part of their unit (the only 3 boundary
 * cases are forward fix-ups to exactly the next word, W2 == CLC); without it,
 * 98 fix-ups point past the end of the loaded area. When the symbol is later
 * defined (ENTR), the chain locations are patched with the symbol value —
 * this loader records the location and patches it directly at the end.
 *
 * COMMON blocks follow the 1-bank rule (ND-60.066.04 section 2.6): allocated
 * downward from the upper bound 0177777; the first ASF for a block fixes its
 * address and length.
 */
public class BRFLoader extends AbstractProgramWrapperLoader {

	public static final String BRF_NAME = "ND-100 BRF (Binary Relocatable Format)";

	// Control numbers (octal, per ND-60.066.04 section 2.9)
	private static final int C_FEED  = 000;  // neglect / padding
	private static final int C_LF    = 001;  // load word
	private static final int C_LR    = 002;  // load relocated (W1+PB)
	private static final int C_LC    = 003;  // load COMMON-relative (W1+CDB)
	private static final int C_AFF   = 004;  // fixup W1+(W2)->(W2)
	private static final int C_ARF   = 005;  // fixup W1+PB+(W2)->(W2)
	private static final int C_AFR   = 006;  // fixup W1+(W2+PB)->(W2+PB)
	private static final int C_ARR   = 007;  // fixup W1+PB+(W2+PB)->(W2+PB)
	private static final int C_SFL   = 010;  // set load address
	private static final int C_AFL   = 011;  // advance load address, fill zeros
	private static final int C_SRL   = 012;  // set relative load address (PB+W1)
	private static final int C_MAIN  = 014;  // symbolic start address
	private static final int C_LIBR  = 015;  // library entry point (conditional load)
	private static final int C_ENTR  = 016;  // symbol := CLC
	private static final int C_BEG   = 017;  // begin unit, PB := CLC
	private static final int C_REF   = 020;  // external reference at CLC (consumes 1 word — see class doc)
	private static final int C_END   = 021;  // end unit, W1 = checksum
	private static final int C_INHB  = 022;  // compilation errors occurred
	private static final int C_EOF   = 023;  // end of loading
	private static final int C_LNF   = 024;  // load N words fast
	private static final int C_RT    = 025;  // real-time priority
	private static final int C_ASF   = 026;  // allocate COMMON block
	private static final int C_ADS   = 027;  // add COMMON address to (CLC-1)
	private static final int C_ID30  = 030;  // "not used" per manual; observed as PLANC id stamp (count + ASCII words)
	private static final int C_LONGF = 032;  // 6-byte S-groups for the rest of this unit
	private static final int C_INL   = 034;  // W2 -> (W1+PB)
	private static final int C_DBL   = 035;  // 2 words -> (W1+PB..)
	private static final int C_RLL   = 036;  // 3 words -> (W1+PB..)
	private static final int C_CXL   = 037;  // 6 words -> (W1+PB..)
	private static final int C_INC   = 040;  // 1 word  -> (W4+ADR) in COMMON
	private static final int C_DBC   = 041;  // 2 words -> (W4+ADR..)
	private static final int C_RLC   = 042;  // 3 words -> (W4+ADR..)
	private static final int C_CXC   = 043;  // 6 words -> (W4+ADR..)
	private static final int C_BYL   = 044;  // byte load into (W1+PB)
	private static final int C_BYC   = 045;  // byte load into (W4+ADR) in COMMON
	private static final int C_NWL   = 046;  // line number (not in use)
	private static final int C_DBG   = 047;  // debug mode on/off
	private static final int C_PMO   = 050;  // program bank mode
	private static final int C_DMO   = 051;  // data bank mode
	private static final int C_LRP   = 052;  // LR with program-bank PB
	private static final int C_LRD   = 053;  // LR with data-bank PB
	private static final int C_DIC   = 054;  // dictionary table, terminated by 177777

	private static final int WORD_MASK   = 0xFFFF;
	private static final int MEM_WORDS   = 0x10000;   // full 16-bit word address space
	private static final int END_OF_LIST = 0177777;   // REF chain terminator / DIC terminator

	/** One defined or referenced symbol. */
	private static class BrfSymbol {
		String name;
		boolean defined;
		int value;          // address when defined
		int definedInUnit;  // 1-based unit number of the defining ENTR/ASF
		boolean isCommon;   // defined via ASF (value = block start, length below)
		int commonLength;
		List<Integer> refLocations = new ArrayList<>();  // word addresses awaiting the value
	}

	/** Per-unit info collected for annotation. */
	private static class UnitInfo {
		int number;              // 1-based, as the BRF Editor numbers them
		long fileOffset;         // offset of the BEG byte
		int pb;                  // program base (CLC at BEG)
		int endClc;              // CLC after the unit
		boolean longf;
		boolean checksumOk;
		int checksumStored;      // checksum P-group after END
		int checksumComputed;    // our running sum from BEG through END
		int rtPriority = -1;     // RT group value, -1 = none
		boolean inhibit;         // INHB seen: compilation errors
		List<String> libr = new ArrayList<>();
		List<String> entr = new ArrayList<>();
		String main;             // MAIN symbol, if any
		String idStamp;          // control-30 ASCII payload (PLANC id), if any
	}

	/** Result of interpreting the whole BRF stream. */
	private static class BrfImage {
		int[] words = new int[MEM_WORDS];
		boolean[] defined = new boolean[MEM_WORDS];
		Map<String, BrfSymbol> symbols = new LinkedHashMap<>();
		List<UnitInfo> units = new ArrayList<>();
		String mainSymbol;       // first MAIN seen
		int commonTop = 0177777; // 1-bank COMMON allocation grows downward from here
		boolean sawTwoBank;      // PMO/DMO encountered
		boolean sawEof;
		int checksumFailures;
	}

	@Override
	public String getName() {
		return BRF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!probeBrf(provider)) {
			return List.of();
		}
		LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("ND-100:BE:16:default", "default");
		return List.of(new LoadSpec(this, 0, lcs, true));
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
	// Detection
	// -----------------------------------------------------------------------

	/**
	 * A BRF file starts (after optional FEED zero padding) with BEG (017),
	 * and the first unit must parse group-by-group to END with a verifying
	 * checksum. Parsing a whole unit is cheap and makes false positives on
	 * arbitrary binaries essentially impossible.
	 */
	private boolean probeBrf(ByteProvider p) throws IOException {
		long len = p.length();
		if (len < 8) {
			return false;
		}
		byte[] head = p.readBytes(0, Math.min(len, 65536));
		int pos = 0;
		// Skip FEED padding, but don't accept a file that is mostly zeros:
		// require BEG within the first 4 KiB.
		while (pos < head.length && head[pos] == 0) {
			pos++;
			if (pos > 4096) {
				return false;
			}
		}
		if (pos >= head.length || (head[pos] & 0xFF) != C_BEG) {
			return false;
		}
		try {
			return checkReadUnit(head, pos) > 0;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Syntax-check one unit starting at the BEG byte at {@code pos}; verifies
	 * the END checksum. Returns the offset just past the checksum P-group, or
	 * -1 if the unit does not verify. Mirrors the loader's "check-read" of
	 * skipped library units.
	 */
	private int checkReadUnit(byte[] buf, int pos) throws IOException {
		boolean longf = false;
		int sum = 0;
		if ((buf[pos] & 0xFF) != C_BEG) {
			return -1;
		}
		sum += C_BEG;
		pos++;
		while (true) {
			if (pos >= buf.length) {
				return -1;
			}
			int c = buf[pos++] & 0xFF;
			sum = (sum + c) & WORD_MASK;
			int sBytes = longf ? 6 : 4;
			int nPGroups;
			boolean hasSym = false;
			switch (c) {
				case C_FEED: case C_INHB: case C_DBG:
				case C_PMO: case C_DMO:
					nPGroups = 0;
					break;
				case C_LONGF:
					longf = true;
					nPGroups = 0;
					break;
				case C_LF: case C_LR: case C_LC:
				case C_SFL: case C_AFL: case C_SRL:
				case C_RT: case C_NWL: case C_LRP: case C_LRD:
					nPGroups = 1;
					break;
				case C_AFF: case C_ARF: case C_AFR: case C_ARR:
				case C_INL: case C_BYL:
					nPGroups = 2;
					break;
				case C_DBL:
					nPGroups = 3;
					break;
				case C_RLL:
					nPGroups = 4;
					break;
				case C_CXL:
					nPGroups = 7;
					break;
				case C_MAIN: case C_LIBR: case C_ENTR: case C_REF:
					hasSym = true;
					nPGroups = 0;
					break;
				case C_ASF:
					hasSym = true;
					nPGroups = 1;
					break;
				case C_ADS:
					hasSym = true;
					nPGroups = 0;
					break;
				case C_INC:
					hasSym = true;
					nPGroups = 2;
					break;
				case C_DBC:
					hasSym = true;
					nPGroups = 3;
					break;
				case C_RLC:
					hasSym = true;
					nPGroups = 4;
					break;
				case C_CXC:
					hasSym = true;
					nPGroups = 7;
					break;
				case C_BYC:
					hasSym = true;
					nPGroups = 3;
					break;
				case C_LNF: case C_ID30: {
					// count word, then count payload words
					if (pos + 2 > buf.length) {
						return -1;
					}
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					if (pos + count * 2 > buf.length) {
						return -1;
					}
					for (int i = 0; i < count; i++) {
						sum = (sum + word(buf, pos)) & WORD_MASK;
						pos += 2;
					}
					continue;
				}
				case C_DIC: {
					// 5-word elements until a 177777 terminator word
					while (true) {
						if (pos + 2 > buf.length) {
							return -1;
						}
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (w == END_OF_LIST) {
							break;
						}
						// remaining 4 words of the element
						if (pos + 8 > buf.length) {
							return -1;
						}
						for (int i = 0; i < 4; i++) {
							sum = (sum + word(buf, pos)) & WORD_MASK;
							pos += 2;
						}
					}
					continue;
				}
				case C_END: {
					// checksum P-group: the whole unit (BEG..END byte plus this
					// checksum word) is a two's-complement sum that comes to 0.
					if (pos + 2 > buf.length) {
						return -1;
					}
					int stored = word(buf, pos);
					pos += 2;
					if (((sum + stored) & WORD_MASK) != 0) {
						return -1;
					}
					return pos;
				}
				default:
					return -1;   // 013, 031, 033 and >054 are illegal
			}
			if (hasSym) {
				if (pos + sBytes > buf.length) {
					return -1;
				}
				for (int i = 0; i < sBytes; i += 2) {
					sum = (sum + word(buf, pos + i)) & WORD_MASK;
				}
				pos += sBytes;
			}
			for (int i = 0; i < nPGroups; i++) {
				if (pos + 2 > buf.length) {
					return -1;
				}
				sum = (sum + word(buf, pos)) & WORD_MASK;
				pos += 2;
			}
		}
	}

	// -----------------------------------------------------------------------
	// Loading
	// -----------------------------------------------------------------------

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		TaskMonitor monitor   = settings.monitor();
		MessageLog log        = settings.log();

		monitor.setMessage("Loading BRF file...");

		byte[] file = provider.readBytes(0, provider.length());
		BrfImage img = interpret(file, log, monitor);

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symtab = program.getSymbolTable();
		Listing listing = program.getListing();

		// ND-100 is word-addressed; default-space wordSize is 2.
		int wordSize = space.getAddressableUnitSize();

		// Emit one memory block per contiguous run of defined words.
		Address firstBlockStart = null;
		Address lastBlockEnd = null;
		int run = 0;
		while (run < MEM_WORDS) {
			if (!img.defined[run]) {
				run++;
				continue;
			}
			int start = run;
			while (run < MEM_WORDS && img.defined[run]) {
				run++;
			}
			int nWords = run - start;
			byte[] data = new byte[nWords * 2];
			for (int i = 0; i < nWords; i++) {
				data[i * 2]     = (byte) ((img.words[start + i] >> 8) & 0xFF);
				data[i * 2 + 1] = (byte) (img.words[start + i] & 0xFF);
			}
			Address blockStart = space.getAddress((start & 0xFFFFL) * wordSize);
			String blockName = String.format("BRF_%06o", start);
			try {
				MemoryBlock blk = memory.createInitializedBlock(
						blockName, blockStart, new ByteArrayInputStream(data),
						data.length, monitor, false);
				blk.setComment(String.format("BRF image: 0%06o..0%06o (%d words)",
						start, run - 1, nWords));
				blk.setRead(true);
				blk.setWrite(true);
				blk.setExecute(true);
				if (firstBlockStart == null) {
					firstBlockStart = blockStart;
				}
				lastBlockEnd = blk.getEnd();
				log.appendMsg(String.format("Block %s: %d words at 0%06o..0%06o",
						blockName, nWords, start, run - 1));
			}
			catch (Exception e) {
				throw new IOException("Failed to create memory block " + blockName + ": " +
						e.getMessage(), e);
			}
		}
		if (firstBlockStart == null) {
			throw new IOException("BRF file produced no loaded words");
		}

		// Labels for all defined symbols (ENTR / MAIN / COMMON blocks).
		int nDefined = 0;
		int nUnresolved = 0;
		StringBuilder unresolved = new StringBuilder();
		for (BrfSymbol sym : img.symbols.values()) {
			if (sym.defined) {
				Address a = space.getAddress((sym.value & 0xFFFFL) * wordSize);
				try {
					symtab.createLabel(a, sanitizeLabel(sym.name), null, SourceType.IMPORTED);
					nDefined++;
				}
				catch (InvalidInputException e) {
					log.appendMsg("Warning: could not create label for symbol '" +
							sym.name + "': " + e.getMessage());
				}
				// Metadata comment at the definition site.
				String defc;
				if (sym.isCommon) {
					defc = String.format("BRF COMMON block %s: %d words at 0%06o (ASF in unit %d)",
							sym.name, sym.commonLength, sym.value, sym.definedInUnit);
				}
				else {
					defc = String.format("BRF ENTR %s = 0%06o (defined in unit %d, %d reference%s)",
							sym.name, sym.value, sym.definedInUnit,
							sym.refLocations.size(), sym.refLocations.size() == 1 ? "" : "s");
				}
				appendComment(listing, a, CodeUnit.PRE_COMMENT, defc);
			}
			else if (!sym.refLocations.isEmpty()) {
				nUnresolved++;
				if (unresolved.length() > 0) {
					unresolved.append(", ");
				}
				unresolved.append(sym.name);
			}
		}
		if (nUnresolved > 0) {
			log.appendMsg(String.format(
					"%d unresolved external symbols (reference words left as 0177777): %s",
					nUnresolved, unresolved));
		}

		// EOL comment on every REF word so external references are visible
		// exactly where the loader patched them.
		for (BrfSymbol sym : img.symbols.values()) {
			for (int i = 0; i < sym.refLocations.size(); i++) {
				int loc = sym.refLocations.get(i);
				Address a = space.getAddress((loc & 0xFFFFL) * wordSize);
				String rc = sym.defined
						? String.format("BRF REF %s -> 0%06o", sym.name, sym.value)
						: String.format("BRF REF %s (UNRESOLVED, left 0177777)", sym.name);
				appendComment(listing, a, CodeUnit.EOL_COMMENT, rc);
			}
		}

		// Per-unit annotation: plate comment with all unit metadata at the
		// unit's program base.
		for (UnitInfo u : img.units) {
			Address a = space.getAddress((u.pb & 0xFFFFL) * wordSize);
			StringBuilder c = new StringBuilder();
			c.append(String.format("=== BRF unit %d ===\n", u.number));
			c.append(String.format("File offset: 0x%X\n", u.fileOffset));
			c.append(String.format("Program base (PB): 0%06o, end CLC: 0%06o (%d words)\n",
					u.pb, u.endClc, (u.endClc - u.pb) & WORD_MASK));
			c.append(String.format("S-groups: %s\n", u.longf ? "6-byte (LONGF)" : "4-byte"));
			c.append(String.format("Checksum: stored 0%06o, computed sum 0%06o [%s]",
					u.checksumStored, u.checksumComputed, u.checksumOk ? "OK" : "MISMATCH"));
			if (u.rtPriority >= 0) {
				c.append(String.format("\nReal-time priority (RT): 0%o", u.rtPriority));
			}
			if (u.inhibit) {
				c.append("\nINHB: compiler reported errors in this unit");
			}
			if (u.main != null) {
				c.append("\nMAIN: ").append(u.main);
			}
			if (!u.libr.isEmpty()) {
				c.append("\nLIBR: ").append(String.join(", ", u.libr));
			}
			if (!u.entr.isEmpty()) {
				c.append("\nENTR: ").append(String.join(", ", u.entr));
			}
			if (u.idStamp != null) {
				c.append("\nID stamp (ctrl 30): ").append(u.idStamp);
			}
			// Units can share a PB (empty units); append rather than overwrite.
			appendComment(listing, a, CodeUnit.PLATE_COMMENT, c.toString());
		}

		// Entry point: value of the MAIN symbol if defined, else first block start.
		Address entryAddr = firstBlockStart;
		String entryDesc = "first loaded word (no MAIN symbol)";
		if (img.mainSymbol != null) {
			BrfSymbol ms = img.symbols.get(img.mainSymbol);
			if (ms != null && ms.defined) {
				entryAddr = space.getAddress((ms.value & 0xFFFFL) * wordSize);
				entryDesc = "MAIN " + img.mainSymbol;
			}
			else {
				entryDesc = "MAIN " + img.mainSymbol + " never defined; using first loaded word";
			}
		}
		symtab.addExternalEntryPoint(entryAddr);
		try {
			symtab.createLabel(entryAddr, "START", null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Warning: could not create START label: " + e.getMessage());
		}
		log.appendMsg("Entry point: " + entryAddr + " (" + entryDesc + ")");

		// File-level header plate comment at the entry with all file metadata.
		int nLongf = 0;
		int nLibrUnits = 0;
		for (UnitInfo u : img.units) {
			if (u.longf) {
				nLongf++;
			}
			if (!u.libr.isEmpty()) {
				nLibrUnits++;
			}
		}
		StringBuilder meta = new StringBuilder();
		meta.append("=== BRF file header ===\n");
		meta.append(String.format("File: %s (%d bytes)\n", provider.getName(), provider.length()));
		meta.append(String.format("Units: %d (%d LONGF / %d short S-group, %d library units)\n",
				img.units.size(), nLongf, img.units.size() - nLongf, nLibrUnits));
		meta.append(String.format("Symbols: %d defined, %d unresolved external\n",
				nDefined, nUnresolved));
		if (nUnresolved > 0) {
			meta.append("Unresolved: ").append(unresolved).append('\n');
		}
		meta.append(String.format("Entry: %s\n", entryDesc));
		if (img.mainSymbol != null) {
			meta.append(String.format("MAIN symbol: %s\n", img.mainSymbol));
		}
		if (img.commonTop != 0177777) {
			meta.append(String.format("COMMON allocated: 0%06o..0177777 (downward, 1-bank rule)\n",
					(img.commonTop + 1) & WORD_MASK));
		}
		meta.append(String.format("Checksums: %d of %d units OK\n",
				img.units.size() - img.checksumFailures, img.units.size()));
		if (img.checksumFailures > 0) {
			meta.append(String.format("WARNING: %d unit checksum failures\n", img.checksumFailures));
		}
		if (img.sawTwoBank) {
			meta.append("WARNING: two-bank (PMO/DMO) groups loaded into a single bank\n");
		}
		if (!img.sawEof) {
			meta.append("Note: no EOF (023) terminator found\n");
		}
		appendComment(listing, entryAddr, CodeUnit.PLATE_COMMENT, meta.toString());

		log.appendMsg(String.format("BRF: %d units, %d defined symbols, %d checksum failures",
				img.units.size(), nDefined, img.checksumFailures));

		// Disassemble from the entry point, following flow through all blocks.
		AddressSet range = new AddressSet(firstBlockStart, lastBlockEnd);
		DisassembleCommand cmd = new DisassembleCommand(entryAddr, range, true);
		cmd.applyTo(program, monitor);

		monitor.setMessage("BRF loading complete");
	}

	// -----------------------------------------------------------------------
	// BRF interpretation (emulated relocating loader)
	// -----------------------------------------------------------------------

	private BrfImage interpret(byte[] buf, MessageLog log, TaskMonitor monitor)
			throws CancelledException, IOException {

		BrfImage img = new BrfImage();
		int pos = 0;
		int clc = 0;             // current location counter (word address)
		int pb = 0;              // program base of current unit
		boolean longf = false;
		boolean inUnit = false;
		int sum = 0;             // running checksum of the current unit
		UnitInfo unit = null;

		while (pos < buf.length) {
			monitor.checkCancelled();
			int c = buf[pos] & 0xFF;

			if (!inUnit) {
				// Between units only FEED padding, BEG and EOF are meaningful.
				if (c == C_FEED) {
					pos++;
					continue;
				}
				if (c == C_EOF) {
					img.sawEof = true;
					pos++;
					long trailing = buf.length - pos;
					if (trailing > 0) {
						log.appendMsg(String.format(
								"%d bytes after EOF ignored (BRF Editor concatenations?)", trailing));
					}
					break;
				}
				if (c != C_BEG) {
					log.appendMsg(String.format(
							"Unexpected control byte 0%o outside a unit at offset 0x%X — stopping",
							c, pos));
					break;
				}
				// BEG: start a unit. LONGF resets here (verified against real files).
				inUnit = true;
				longf = false;
				sum = C_BEG;
				pb = clc;
				unit = new UnitInfo();
				unit.number = img.units.size() + 1;
				unit.fileOffset = pos;
				unit.pb = pb;
				img.units.add(unit);
				pos++;
				continue;
			}

			pos++;
			sum = (sum + c) & WORD_MASK;

			switch (c) {
				case C_FEED:
					break;

				case C_LONGF:
					longf = true;
					unit.longf = true;
					break;

				case C_LF: case C_LR: case C_LC: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					int v = w1;
					if (c == C_LR) {
						v = (w1 + pb) & WORD_MASK;
					}
					else if (c == C_LC) {
						// LC adds CDB — the manual defines CDB as "the COMMON data
						// base". Only 1 LC occurs in the validation samples. We use
						// the most recently ASF-allocated block start as CDB; if no
						// COMMON exists yet the word is stored unrelocated and logged.
						if (img.commonTop == 0177777) {
							log.appendMsg(String.format(
									"LC at 0%06o with no COMMON block allocated — stored unrelocated",
									clc));
						}
						else {
							v = (w1 + img.commonTop + 1) & WORD_MASK;
						}
					}
					store(img, clc, v);
					clc = (clc + 1) & WORD_MASK;
					break;
				}

				case C_AFF: case C_ARF: case C_AFR: case C_ARR: {
					int w1 = word(buf, pos);
					int w2 = word(buf, pos + 2);
					sum = (sum + w1 + w2) & WORD_MASK;
					pos += 4;
					int target = (c == C_AFR || c == C_ARR) ? (w2 + pb) & WORD_MASK : w2;
					int add    = (c == C_ARF || c == C_ARR) ? (w1 + pb) & WORD_MASK : w1;
					store(img, target, (img.words[target] + add) & WORD_MASK);
					break;
				}

				case C_SFL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					clc = w1;
					break;
				}

				case C_AFL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					// advance and fill zeros
					for (int i = 0; i < w1; i++) {
						store(img, (clc + i) & WORD_MASK, 0);
					}
					clc = (clc + w1) & WORD_MASK;
					break;
				}

				case C_SRL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					clc = (pb + w1) & WORD_MASK;
					break;
				}

				case C_MAIN: case C_LIBR: case C_ENTR: case C_REF: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					BrfSymbol sym = img.symbols.computeIfAbsent(name, k -> {
						BrfSymbol s = new BrfSymbol();
						s.name = k;
						return s;
					});
					if (c == C_MAIN) {
						unit.main = name;
						if (img.mainSymbol == null) {
							img.mainSymbol = name;
						}
					}
					else if (c == C_LIBR) {
						unit.libr.add(name);
					}
					else if (c == C_ENTR) {
						unit.entr.add(name);
						if (sym.defined) {
							log.appendMsg(String.format(
									"Symbol %s redefined in unit %d (old 0%06o, new 0%06o)",
									name, unit.number, sym.value, clc));
						}
						sym.defined = true;
						sym.value = clc;
						sym.definedInUnit = unit.number;
					}
					else { // C_REF — consumes one word at CLC (see class doc)
						sym.refLocations.add(clc);
						store(img, clc, END_OF_LIST);  // placeholder until resolved
						clc = (clc + 1) & WORD_MASK;
					}
					break;
				}

				case C_END: {
					int stored = word(buf, pos);
					pos += 2;
					unit.checksumStored = stored;
					unit.checksumComputed = sum;
					unit.checksumOk = ((sum + stored) & WORD_MASK) == 0;
					if (!unit.checksumOk) {
						img.checksumFailures++;
						log.appendMsg(String.format(
								"Unit %d checksum MISMATCH (sum=0%06o stored=0%06o)",
								unit.number, sum, stored));
					}
					unit.endClc = clc;
					inUnit = false;
					unit = null;
					break;
				}

				case C_INHB:
					unit.inhibit = true;
					log.appendMsg(String.format(
							"Unit %d flagged INHB: compilation errors occurred", unit.number));
					break;

				case C_EOF:
					// EOF inside a unit is a syntax error; be tolerant and stop.
					log.appendMsg(String.format(
							"EOF inside unit %d at offset 0x%X — stopping", unit.number, pos - 1));
					img.sawEof = true;
					pos = buf.length;
					break;

				case C_LNF: {
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					if (pos + count * 2 > buf.length) {
						throw new IOException(String.format(
								"LNF count %d overruns file at offset 0x%X", count, pos));
					}
					for (int i = 0; i < count; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						store(img, (clc + i) & WORD_MASK, w);
					}
					clc = (clc + count) & WORD_MASK;
					break;
				}

				case C_RT: case C_NWL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					if (c == C_RT) {
						unit.rtPriority = w1;
						log.appendMsg(String.format("Unit %d real-time priority: 0%o",
								unit.number, w1));
					}
					break;
				}

				case C_ASF: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					int len = word(buf, pos);
					sum = (sum + len) & WORD_MASK;
					pos += 2;
					BrfSymbol sym = img.symbols.computeIfAbsent(name, k -> {
						BrfSymbol s = new BrfSymbol();
						s.name = k;
						return s;
					});
					if (!sym.defined) {
						// 1-bank rule: allocate downward from the upper bound.
						img.commonTop -= len;
						sym.defined = true;
						sym.definedInUnit = unit.number;
						sym.isCommon = true;
						sym.value = (img.commonTop + 1) & WORD_MASK;
						sym.commonLength = len;
						log.appendMsg(String.format("COMMON %s: %d words at 0%06o",
								name, len, sym.value));
					}
					// Succeeding declarations cannot expand the block (section 2.6).
					break;
				}

				case C_ADS: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					BrfSymbol sym = img.symbols.get(name);
					int loc = (clc - 1) & WORD_MASK;
					if (sym != null && sym.defined) {
						store(img, loc, (img.words[loc] + sym.value) & WORD_MASK);
					}
					else {
						log.appendMsg(String.format(
								"ADS references undefined COMMON symbol %s at 0%06o", name, loc));
					}
					break;
				}

				case C_ID30: {
					// Undocumented ("not used" per manual) but observed in PLANC
					// output: framed like LNF, payload is ASCII (e.g. PLANC-1BANK-G00).
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					StringBuilder ascii = new StringBuilder();
					for (int i = 0; i < count; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						ascii.append(printable((w >> 8) & 0xFF));
						ascii.append(printable(w & 0xFF));
					}
					unit.idStamp = ascii.toString().trim();
					log.appendMsg(String.format("Unit %d id stamp (ctrl 30): %s",
							unit.number, unit.idStamp));
					break;
				}

				case C_INL: case C_BYL: {
					int w1 = word(buf, pos);
					int w2 = word(buf, pos + 2);
					sum = (sum + w1 + w2) & WORD_MASK;
					pos += 4;
					int target = (w1 + pb) & WORD_MASK;
					if (c == C_INL) {
						store(img, target, w2);
					}
					else {
						storeByte(img, target, w2);
					}
					break;
				}

				case C_DBL: case C_RLL: case C_CXL: {
					int n = (c == C_DBL) ? 2 : (c == C_RLL) ? 3 : 6;
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					int target = (w1 + pb) & WORD_MASK;
					for (int i = 0; i < n; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						store(img, (target + i) & WORD_MASK, w);
					}
					break;
				}

				case C_INC: case C_DBC: case C_RLC: case C_CXC: case C_BYC: {
					// S-group = COMMON block name (must be defined; value = ADR),
					// then W4 = offset, W5.. = data.
					int n = (c == C_INC || c == C_BYC) ? 1 : (c == C_DBC) ? 2 : (c == C_RLC) ? 3 : 6;
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					int w4 = word(buf, pos);
					sum = (sum + w4) & WORD_MASK;
					pos += 2;
					BrfSymbol sym = img.symbols.get(name);
					int adr = (sym != null && sym.defined) ? sym.value : -1;
					if (adr < 0) {
						log.appendMsg(String.format(
								"COMMON store references undefined block %s — data skipped", name));
					}
					for (int i = 0; i < n; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (adr >= 0) {
							int target = (w4 + adr + i) & WORD_MASK;
							if (c == C_BYC) {
								storeByte(img, target, w);
							}
							else {
								store(img, target, w);
							}
						}
					}
					break;
				}

				case C_DBG:
					break;

				case C_PMO: case C_DMO:
					// Two-bank loading not modeled: everything goes to one bank.
					if (!img.sawTwoBank) {
						log.appendMsg("Two-bank groups (PMO/DMO) present — " +
								"loading everything into a single bank");
					}
					img.sawTwoBank = true;
					break;

				case C_LRP: case C_LRD: {
					// Without separate banks, both relocate against the current PB.
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					store(img, clc, (w1 + pb) & WORD_MASK);
					clc = (clc + 1) & WORD_MASK;
					break;
				}

				case C_DIC: {
					// Library dictionary: 5-word elements (3-word name + 2-word
					// byte pointer) until 177777. Only used to speed up selective
					// loading — we load everything, so just log it.
					int entries = 0;
					while (true) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (w == END_OF_LIST) {
							break;
						}
						for (int i = 0; i < 4; i++) {
							sum = (sum + word(buf, pos)) & WORD_MASK;
							pos += 2;
						}
						entries++;
					}
					log.appendMsg(String.format("Unit %d: dictionary with %d entries (ignored)",
							unit.number, entries));
					break;
				}

				default:
					throw new IOException(String.format(
							"Illegal BRF control number 0%o at offset 0x%X (unit %d)",
							c, pos - 1, unit.number));
			}
		}

		if (inUnit) {
			log.appendMsg("File ended inside a unit (no END group)");
		}

		// Resolve REF chains: patch every reference word with the symbol value.
		for (BrfSymbol sym : img.symbols.values()) {
			if (sym.defined) {
				for (int i = 0; i < sym.refLocations.size(); i++) {
					int loc = sym.refLocations.get(i);
					store(img, loc, sym.value & WORD_MASK);
				}
			}
			// Undefined symbols keep 0177777 in their reference words, matching
			// the real loader's end-of-chain marker; they are reported by load().
		}

		return img;
	}

	/** Append to an existing comment instead of overwriting it. */
	private static void appendComment(Listing listing, Address a, int type, String text) {
		String prev = listing.getComment(type, a);
		listing.setComment(a, type, prev == null || prev.isEmpty() ? text : prev + "\n" + text);
	}

	private static void store(BrfImage img, int addr, int value) {
		img.words[addr & WORD_MASK] = value & WORD_MASK;
		img.defined[addr & WORD_MASK] = true;
	}

	/**
	 * BYL/BYC semantics: W bits 0-7 go to the target's bits 0-7 if W bit 15 = 0,
	 * to bits 8-15 if W bit 15 = 1.
	 */
	private static void storeByte(BrfImage img, int addr, int w) {
		int b = w & 0xFF;
		int old = img.words[addr & WORD_MASK];
		int v = ((w & 0x8000) != 0) ? (old & 0x00FF) | (b << 8)
									: (old & 0xFF00) | b;
		store(img, addr, v);
	}

	private static int word(byte[] buf, int pos) throws IOException {
		if (pos + 2 > buf.length) {
			throw new IOException("Unexpected end of BRF file at offset 0x" +
					Integer.toHexString(pos));
		}
		// P-groups are big-endian: MSB first (verified — checksums fail otherwise).
		return ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
	}

	/**
	 * Decode an S-group: symbol of 1-7 chars in six-bit code (char = ASCII - 040),
	 * right-justified, space(0)-padded on the left, packed MSB-first.
	 * 4 bytes = 32 bits = 5 chars (top 2 bits pad); 6 bytes = 48 bits = 8 chars.
	 */
	private static String decodeSymbol(byte[] buf, int pos, int sBytes) throws IOException {
		if (pos + sBytes > buf.length) {
			throw new IOException("Truncated S-group at offset 0x" + Integer.toHexString(pos));
		}
		long bits = 0;
		for (int i = 0; i < sBytes; i++) {
			bits = (bits << 8) | (buf[pos + i] & 0xFF);
		}
		int nChars = (sBytes == 6) ? 8 : 5;
		StringBuilder sb = new StringBuilder(nChars);
		for (int i = nChars - 1; i >= 0; i--) {
			int ch = (int) ((bits >> (i * 6)) & 0x3F);
			if (ch == 0) {
				// 0 = space padding; interior zeros also decode to space
				// (statement-number labels pad both ends)
				sb.append(' ');
			}
			else {
				sb.append((char) (ch + 040));
			}
		}
		String s = sb.toString().trim();
		return s.isEmpty() ? "BLANK" : s;
	}

	private static char printable(int b) {
		return (b >= 0x20 && b < 0x7F) ? (char) b : '.';
	}

	/**
	 * BRF symbols may contain characters Ghidra labels can't (e.g. space).
	 * Six-bit code covers ASCII 040-137, most of which is fine; replace
	 * anything outside [A-Za-z0-9_$*+-.:] with '_'.
	 */
	private static String sanitizeLabel(String name) {
		StringBuilder sb = new StringBuilder(name.length());
		for (int i = 0; i < name.length(); i++) {
			char ch = name.charAt(i);
			if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '$' ||
				ch == '*' || ch == '+' || ch == '-' || ch == '.' || ch == ':') {
				sb.append(ch);
			}
			else {
				sb.append('_');
			}
		}
		return sb.toString();
	}
}
