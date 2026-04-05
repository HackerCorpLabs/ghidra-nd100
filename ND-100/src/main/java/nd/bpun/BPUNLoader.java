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
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * ND-100 BPUN (Bootable Punched Tape) file format loader for Ghidra.
 *
 * BPUN format structure:
 * - Preamble: 7-bit ASCII bootstrap code with parity bits.
 *   Contains start/boot addresses as octal digit strings delimited by '/' and CR.
 *   Terminated by '!' delimiter.
 * - After '!': one data section as binary big-endian words:
 *   [address(2)] [count(2)] [data(count*2 bytes)] [checksum(2)] [action(2)]
 * - FloMon variant: if address==0 && count==0 && checksum==0, switches to FloMon format
 *   which reads a byte count then words in 00-hi-00-lo-00 format.
 *
 * Ported from nd100x emulator's LoadBPUNStream() implementation.
 */
public class BPUNLoader extends AbstractProgramWrapperLoader {

	public static final String BPUN_NAME = "ND-100 BPUN (Bootable Punched Tape)";

	private static final int LOAD_PREAMBLE = 0;
	private static final int LOAD_ADDRESS = 1;
	private static final int LOAD_COUNT = 2;
	private static final int LOAD_DATA = 3;
	private static final int LOAD_CHECKSUM = 4;
	private static final int LOAD_ACTION = 5;
	private static final int LOAD_FLOMON_COUNT = 6;
	private static final int LOAD_FLOMON_DATA = 7;

	private static class BpunFile {
		int start = 0;
		int boot = 0;
		int address = 0;
		int count = 0;
		int checksum = 0;
		int calculatedChecksum = 0;
		int action = 0;
		boolean isFloMon = false;
		byte[] data = null;
	}

	@Override
	public String getName() {
		return BPUN_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!probeBPUN(provider)) {
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

		monitor.setMessage("Loading BPUN binary...");

		BpunFile bpun = parseBpun(provider, log);

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbolTable = program.getSymbolTable();

		// ND-100 is word-addressed. Ghidra's address space uses wordsize=2,
		// so multiply word addresses by wordSize to get byte offsets.
		int wordSize = space.getAddressableUnitSize();

		Address blockStart = null;
		Address blockEnd = null;

		if (bpun.data != null && bpun.data.length > 0) {
			long byteAddr = (bpun.address & 0xffffL) * wordSize;
			blockStart = space.getAddress(byteAddr);
			String blockName = String.format("LOAD_%06o", bpun.address & 0xffff);

			try (ByteArrayInputStream dataStream = new ByteArrayInputStream(bpun.data)) {
				MemoryBlock block = memory.createInitializedBlock(
						blockName, blockStart, dataStream, bpun.data.length, monitor, false);
				block.setComment(bpun.isFloMon ? "BPUN FloMon section" : "BPUN load section");
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
				blockEnd = block.getEnd();

				log.appendMsg(String.format("Loaded %d words at 0%06o (0x%04X)",
						bpun.count, bpun.address, bpun.address));
			}
			catch (Exception e) {
				log.appendMsg(String.format("Failed to create memory block at 0%06o: %s",
						bpun.address, e.getMessage()));
			}
		}

		// Add BPUN metadata as plate comment at block start
		if (blockStart != null) {
			Listing listing = program.getListing();
			StringBuilder meta = new StringBuilder();
			meta.append(String.format("BPUN File: %s\n", provider.getName()));
			meta.append(String.format("Format: %s\n", bpun.isFloMon ? "FloMon" : "Standard"));
			meta.append(String.format("Load address: 0%06o (0x%04X)\n", bpun.address, bpun.address));
			meta.append(String.format("Word count: 0%06o (%d words)\n", bpun.count, bpun.count));
			meta.append(String.format("Start address: 0%06o (0x%04X)\n", bpun.start, bpun.start));
			meta.append(String.format("Boot address: 0%06o (0x%04X)\n", bpun.boot, bpun.boot));
			if (bpun.checksum != 0) {
				boolean ok = (bpun.calculatedChecksum == bpun.checksum);
				meta.append(String.format("Checksum: 0%06o %s\n", bpun.checksum, ok ? "[OK]" : "[MISMATCH]"));
			}
			meta.append(String.format("Action: 0%06o", bpun.action));
			listing.setComment(blockStart, CodeUnit.PLATE_COMMENT, meta.toString());
		}

		// Always create entry point — address 0 is valid on ND-100
		Address entryAddr = space.getAddress((bpun.start & 0xffffL) * wordSize);
		symbolTable.addExternalEntryPoint(entryAddr);
		try {
			symbolTable.createLabel(entryAddr, "START", null,
					ghidra.program.model.symbol.SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Warning: Could not create START label: " + e.getMessage());
		}
		log.appendMsg(String.format("Entry point (start): 0%06o (0x%04X)", bpun.start, bpun.start));

		if (bpun.boot != bpun.start) {
			Address bootAddr = space.getAddress((bpun.boot & 0xffffL) * wordSize);
			symbolTable.addExternalEntryPoint(bootAddr);
			try {
				symbolTable.createLabel(bootAddr, "BOOT", null,
						ghidra.program.model.symbol.SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg("Warning: Could not create BOOT label: " + e.getMessage());
			}
			log.appendMsg(String.format("Boot address: 0%06o (0x%04X)", bpun.boot, bpun.boot));
		}

		// Explicitly disassemble from entry point — follow flow through the entire loaded block
		if (blockStart != null && blockEnd != null) {
			AddressSet disassembleRange = new AddressSet(blockStart, blockEnd);
			DisassembleCommand disCmd = new DisassembleCommand(entryAddr, disassembleRange, true);
			disCmd.applyTo(program, monitor);
		}

		monitor.setMessage("BPUN loading complete");
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	private boolean probeBPUN(ByteProvider p) throws IOException {
		long len = p.length();
		if (len < 8) return false;

		// BPUN files start with a preamble: optional NUL padding, then ASCII text
		// with octal digits, '/', CR, LF, terminated by '!'. All bytes have parity
		// bit set (bit 7), so we strip to 7-bit.
		// Reject files that start with non-preamble binary data (e.g., TPE :TEST/:NEXT
		// files which start with 0x6C00 or 0x9780).
		int checkLen = (int) Math.min(len, 32);
		for (int i = 0; i < checkLen; i++) {
			int c = p.readByte(i) & 0x7F;
			if (c == 0) {
				// NUL padding — valid in BPUN preamble
			} else if (c >= '0' && c <= '9') {
				// Octal digit
			} else if (c == '/' || c == '!' || c == 0x0D || c == 0x0A || c == ' ') {
				// Valid preamble delimiters
			} else {
				// Non-preamble byte in first 32 bytes → not a BPUN file
				return false;
			}
		}

		// Find '!' delimiter (cap scan at 1 MiB)
		long cap = Math.min(len, 1_048_576L);
		long bang = -1;
		for (long i = 0; i < cap; i++) {
			if ((p.readByte(i) & 0x7f) == '!') { bang = i; break; }
		}
		if (bang < 0) return false;

		// Need at least Address(2) + Count(2) after '!'
		if (bang + 1 + 4 > len) return false;

		int count = ((p.readByte(bang + 3) & 0xff) << 8) | (p.readByte(bang + 4) & 0xff);

		// count==0 is valid for FloMon format
		if (count == 0) return true;
		if (count > 0x8000) return false;

		// Need Count*2 data bytes + Checksum(2); Action(2) is optional
		long need = (bang + 1) + 4L + (count * 2L) + 2L;
		return need <= len;
	}

	/**
	 * Parse BPUN file following the nd100x emulator's LoadBPUNStream() state machine.
	 *
	 * Preamble parsing (7-bit ASCII with parity stripped):
	 * - Digits '0'-'9' are accumulated into a string
	 * - '/' delimiter: accumulated number (parsed as octal) becomes the start address
	 * - CR (0x0D): accumulated number becomes lastValue
	 * - '!' delimiter: accumulated number becomes loadAddress, boot is computed,
	 *   then transitions to binary section reading
	 */
	private BpunFile parseBpun(ByteProvider provider, MessageLog log) throws IOException {
		BpunFile bpun = new BpunFile();

		long len = provider.length();
		long pos = 0;
		int loadState = LOAD_PREAMBLE;

		// Preamble state
		StringBuilder tmpString = new StringBuilder();
		int loadAddress = 0;
		int lastValue = 0;

		// Data state
		int dataCounter = 0;
		int dataOffset = 0;

		while (pos < len) {
			int b = provider.readByte(pos++) & 0xff;

			switch (loadState) {
				case LOAD_PREAMBLE: {
					char c = (char) (b & 0x7F); // Strip parity bit to 7-bit ASCII

					if (c == '!') {
						if (tmpString.length() > 0) {
							int tmp = parseOctal(tmpString.toString());
							if (tmp >= 0) {
								loadAddress = tmp & 0xFFFF;
							}
						}
						if (loadAddress == bpun.start) {
							bpun.boot = lastValue;
						}
						else {
							bpun.boot = loadAddress;
						}
						loadState = LOAD_ADDRESS;
						tmpString.setLength(0);

						log.appendMsg(String.format("Preamble: %d bytes", pos - 1));
						log.appendMsg(String.format("Start: 0%06o (0x%04X)", bpun.start, bpun.start));
						log.appendMsg(String.format("Boot: 0%06o (0x%04X)", bpun.boot, bpun.boot));
					}
					else if (c == '/') {
						if (tmpString.length() > 0) {
							int tmp = parseOctal(tmpString.toString());
							if (tmp >= 0) {
								int val = tmp & 0xFFFF;
								lastValue = val;
								bpun.start = val;
								if (loadAddress == 0) {
									loadAddress = val;
								}
							}
						}
						tmpString.setLength(0);
					}
					else if (c >= '0' && c <= '9') {
						tmpString.append(c);
					}
					else if (c == 0x0D) { // Carriage return
						if (tmpString.length() > 0) {
							int tmp = parseOctal(tmpString.toString());
							if (tmp >= 0) {
								lastValue = tmp & 0xFFFF;
							}
							tmpString.setLength(0);
						}
					}
					break;
				}

				case LOAD_ADDRESS: {
					if (pos >= len) throw new IOException("Unexpected end of file in address");
					int hi = b;
					int lo = provider.readByte(pos++) & 0xff;
					bpun.address = ((hi << 8) | lo) & 0xFFFF;
					loadState = LOAD_COUNT;
					break;
				}

				case LOAD_COUNT: {
					if (pos >= len) throw new IOException("Unexpected end of file in count");
					int hi = b;
					int lo = provider.readByte(pos++) & 0xff;
					bpun.count = ((hi << 8) | lo) & 0xFFFF;
					dataCounter = bpun.count * 2; // Count is in words, we read bytes
					bpun.data = new byte[dataCounter];
					dataOffset = 0;
					bpun.calculatedChecksum = 0;
					loadState = LOAD_DATA;

					log.appendMsg(String.format("Data section: address=0%06o count=0%06o (%d words)",
							bpun.address, bpun.count, bpun.count));
					break;
				}

				case LOAD_DATA: {
					if (dataCounter > 0) {
						dataCounter--;
						int hi = b;
						if (dataCounter > 0 && pos < len) {
							int lo = provider.readByte(pos++) & 0xff;
							dataCounter--;
							int word = ((hi << 8) | lo) & 0xFFFF;
							bpun.data[dataOffset++] = (byte) ((word >> 8) & 0xFF);
							bpun.data[dataOffset++] = (byte) (word & 0xFF);
							bpun.calculatedChecksum = (bpun.calculatedChecksum + word) & 0xFFFF;
						}
					}
					if (dataCounter == 0) {
						loadState = LOAD_CHECKSUM;
					}
					break;
				}

				case LOAD_CHECKSUM: {
					if (pos >= len) throw new IOException("Unexpected end of file in checksum");
					int hi = b;
					int lo = provider.readByte(pos++) & 0xff;
					bpun.checksum = ((hi << 8) | lo) & 0xFFFF;

					// FloMon detection: address==0 && count==0 && checksum==0
					if (bpun.address == 0 && bpun.count == 0 && bpun.checksum == 0) {
						bpun.isFloMon = true;
						loadState = LOAD_FLOMON_COUNT;
						log.appendMsg("FloMon format detected");
					}
					else {
						loadState = LOAD_ACTION;
						if (bpun.calculatedChecksum != bpun.checksum) {
							log.appendMsg(String.format("Checksum MISMATCH: calculated=0%06o, file=0%06o",
									bpun.calculatedChecksum, bpun.checksum));
						}
						else {
							log.appendMsg(String.format("Checksum: 0%06o [OK]", bpun.checksum));
						}
					}
					break;
				}

				case LOAD_ACTION: {
					if (pos >= len) {
						// Some BPUN files end after checksum with no action word
						bpun.action = 0;
						log.appendMsg("Action: (not present, defaulting to 0)");
						log.appendMsg("FloMon: 0");
						return bpun;
					}
					int hi = b;
					int lo = provider.readByte(pos++) & 0xff;
					bpun.action = ((hi << 8) | lo) & 0xFFFF;
					log.appendMsg(String.format("Action: 0%06o", bpun.action));
					log.appendMsg("FloMon: 0");
					return bpun;
				}

				case LOAD_FLOMON_COUNT: {
					// FloMon count is a single byte
					bpun.count = b & 0xFF;
					bpun.data = new byte[bpun.count * 2];
					dataOffset = 0;
					loadState = LOAD_FLOMON_DATA;
					log.appendMsg(String.format("FloMon: loading %d words at 0%06o",
							bpun.count, bpun.address));
					break;
				}

				case LOAD_FLOMON_DATA: {
					// FloMon word format per C code: 00 hi 00 lo 00
					// The outer loop already read the first 0x00 byte as 'b'
					int floWords = 0;
					while (floWords < bpun.count) {
						if (b != 0) {
							throw new IOException(String.format(
									"FloMon: expected 0x00, got 0x%02X at word %d", b, floWords));
						}
						if (pos + 3 >= len) throw new IOException("Unexpected end of FloMon data");

						int hi = provider.readByte(pos++) & 0xff;

						int chk1 = provider.readByte(pos++) & 0xff;
						if (chk1 != 0) {
							throw new IOException(String.format(
									"FloMon: expected 0x00, got 0x%02X at word %d", chk1, floWords));
						}

						int lo = provider.readByte(pos++) & 0xff;

						int chk2 = provider.readByte(pos++) & 0xff;
						if (chk2 != 0) {
							throw new IOException(String.format(
									"FloMon: expected 0x00, got 0x%02X at word %d", chk2, floWords));
						}

						int word = ((hi << 8) | lo) & 0xFFFF;
						bpun.data[dataOffset++] = (byte) ((word >> 8) & 0xFF);
						bpun.data[dataOffset++] = (byte) (word & 0xFF);
						floWords++;

						if (floWords < bpun.count) {
							if (pos >= len) throw new IOException("Unexpected end of FloMon data");
							b = provider.readByte(pos++) & 0xff;
						}
					}
					log.appendMsg(String.format("FloMon: loaded %d words", floWords));
					log.appendMsg("FloMon: 1");
					return bpun;
				}
			}
		}

		// If we ran out of data while expecting the action word, that's OK —
		// some BPUN files (e.g., TPE-MON) end right after the checksum
		if (loadState == LOAD_ACTION) {
			bpun.action = 0;
			log.appendMsg("Action: (not present, defaulting to 0)");
			log.appendMsg("FloMon: 0");
			return bpun;
		}

		throw new IOException("Unexpected end of BPUN file");
	}

	private int parseOctal(String s) {
		try {
			return Integer.parseInt(s, 8);
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}
