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
// AUTO-GENERATED from specs/io-devices.json — DO NOT EDIT
package nd.bpun;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that annotates ND-100 I/O space addresses with device register
 * documentation including bit field descriptions.
 *
 * Runs automatically when an ND-100 program is analyzed. Adds plate comments
 * and labels to known I/O device registers with register names, directions,
 * and bit field layouts.
 */
public class ND100IOAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 I/O Device Registers";
	private static final String DESCRIPTION =
		"Annotates I/O space addresses with device register names and bit field documentation.";

	private static final String OPTION_DONE = "IO annotations applied";
	private SymbolTable symbolTable;

	public ND100IOAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
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

		// Check if we already annotated this program (stored in program options)
		Options progOptions = program.getOptions("Analyzers");
		if (progOptions.getBoolean(OPTION_DONE, false)) {
			return true;
		}

		AddressSpace ioSpace = program.getAddressFactory().getAddressSpace("io_space");
		if (ioSpace == null) {
			log.appendMsg(NAME, "io_space address space not found - skipping I/O annotations");
			return false;
		}

		Listing listing = program.getListing();
		symbolTable = program.getSymbolTable();
		int count = 0;

		// Real-Time Clock 1 (octal 010-013)
		count += annotateDevice(listing, ioSpace, 0x8, "RTC1", "Real-Time Clock", "1", "010-013", "13", "01", "rtc");

		// Real-Time Clock 2 (octal 014-017)
		count += annotateDevice(listing, ioSpace, 0xC, "RTC2", "Real-Time Clock", "2", "014-017", "13", "02", "rtc");

		// Real-Time Clock 3 (octal 020-023)
		count += annotateDevice(listing, ioSpace, 0x10, "RTC3", "Real-Time Clock", "3", "020-023", "13", "06", "rtc");

		// Terminal Console (Terminal 1) (octal 0300-0307)
		count += annotateDevice(listing, ioSpace, 0xC0, "CON", "Terminal", "Console (Terminal 1)", "0300-0307", "10/12", "01", "terminal");

		// Paper Tape Reader 1 (octal 0400-0403)
		count += annotateDevice(listing, ioSpace, 0x100, "PTR1", "Paper Tape Reader", "1", "0400-0403", "12", "02", "paper_tape");

		// Paper Tape Reader 2 (octal 0404-0407)
		count += annotateDevice(listing, ioSpace, 0x104, "PTR2", "Paper Tape Reader", "2", "0404-0407", "12", "022", "paper_tape");

		// Line Printer 3 (octal 0160-0163)
		count += annotateDevice(listing, ioSpace, 0x70, "LP3", "Line Printer", "3", "0160-0163", "10", "035", "line_printer");

		// Line Printer 4 (octal 0164-0167)
		count += annotateDevice(listing, ioSpace, 0x74, "LP4", "Line Printer", "4", "0164-0167", "10", "036", "line_printer");

		// Line Printer 5 (octal 0170-0173)
		count += annotateDevice(listing, ioSpace, 0x78, "LP5", "Line Printer", "5", "0170-0173", "10", "033", "line_printer");

		// Line Printer 6 (octal 0174-0177)
		count += annotateDevice(listing, ioSpace, 0x7C, "LP6", "Line Printer", "6", "0174-0177", "10", "032", "line_printer");

		// Line Printer 1 (octal 0430-0433)
		count += annotateDevice(listing, ioSpace, 0x118, "LP1", "Line Printer", "1", "0430-0433", "10", "03", "line_printer");

		// Line Printer 2 (octal 0434-0437)
		count += annotateDevice(listing, ioSpace, 0x11C, "LP2", "Line Printer", "2", "0434-0437", "10", "023", "line_printer");

		// SMD Disk Controller 3 (octal 0540-0547)
		count += annotateDevice(listing, ioSpace, 0x160, "SMD3", "SMD Disk Controller", "3", "0540-0547", "11", "023", "smd");

		// SMD Disk Controller 4 (octal 0550-0557)
		count += annotateDevice(listing, ioSpace, 0x168, "SMD4", "SMD Disk Controller", "4", "0550-0557", "11", "06", "smd");

		// ND-500 Interface 1 (octal 060-077)
		count += annotateDevice(listing, ioSpace, 0x30, "ND500_1", "ND-500 Interface", "1", "060-077", "12", "016", "nd500_interface");

		// ND-500 Interface 5 (octal 0560-0577)
		count += annotateDevice(listing, ioSpace, 0x170, "ND500_5", "ND-500 Interface", "5", "0560-0577", "12", "076", "nd500_interface");

		// ND-500 Interface 3 (octal 0660-0677)
		count += annotateDevice(listing, ioSpace, 0x1B0, "ND500_3", "ND-500 Interface", "3", "0660-0677", "12", "036", "nd500_interface");

		// ND-500 Interface 4 (octal 0760-0777)
		count += annotateDevice(listing, ioSpace, 0x1F0, "ND500_4", "ND-500 Interface", "4", "0760-0777", "12", "0114", "nd500_interface");

		// ND-500 Interface 2 (octal 01060-01077)
		count += annotateDevice(listing, ioSpace, 0x230, "ND500_2", "ND-500 Interface", "2", "01060-01077", "12", "0116", "nd500_interface");

		// SMD Disk Controller 1 (octal 01540-01547)
		count += annotateDevice(listing, ioSpace, 0x360, "SMD1", "SMD Disk Controller", "1", "01540-01547", "11", "017", "smd");

		// SMD Disk Controller 2 (octal 01550-01557)
		count += annotateDevice(listing, ioSpace, 0x368, "SMD2", "SMD Disk Controller", "2", "01550-01557", "11", "020", "smd");

		// Floppy DMA Controller 1 (octal 01560-01567)
		count += annotateDevice(listing, ioSpace, 0x370, "FLP1", "Floppy DMA Controller", "1", "01560-01567", "11", "021", "floppy_dma");

		// Floppy DMA Controller 2 (octal 01570-01577)
		count += annotateDevice(listing, ioSpace, 0x378, "FLP2", "Floppy DMA Controller", "2", "01570-01577", "11", "022", "floppy_dma");

		// HDLC/Megalink 1 (octal 01640-01657)
		count += annotateDevice(listing, ioSpace, 0x3A0, "HDLC1", "HDLC/Megalink", "1", "01640-01657", "12/13", "0150", "hdlc");

		// HDLC/Megalink 2 (octal 01660-01677)
		count += annotateDevice(listing, ioSpace, 0x3B0, "HDLC2", "HDLC/Megalink", "2", "01660-01677", "12/13", "0151", "hdlc");

		// HDLC/Megalink 3 (octal 01700-01717)
		count += annotateDevice(listing, ioSpace, 0x3C0, "HDLC3", "HDLC/Megalink", "3", "01700-01717", "12/13", "0152", "hdlc");

		// HDLC/Megalink 4 (octal 01720-01737)
		count += annotateDevice(listing, ioSpace, 0x3D0, "HDLC4", "HDLC/Megalink", "4", "01720-01737", "12/13", "0153", "hdlc");

		// HDLC/Megalink 5 (octal 01740-01757)
		count += annotateDevice(listing, ioSpace, 0x3E0, "HDLC5", "HDLC/Megalink", "5", "01740-01757", "12/13", "0154", "hdlc");

		// HDLC/Megalink 6 (octal 01760-01777)
		count += annotateDevice(listing, ioSpace, 0x3F0, "HDLC6", "HDLC/Megalink", "6", "01760-01777", "12/13", "0155", "hdlc");

		// Octobus Interface 1 (octal 100400-100407)
		count += annotateDevice(listing, ioSpace, 0x8100, "OCT1", "Octobus Interface", "1", "100400-100407", "13", "040/041", "octobus");

		// Octobus Interface 2 (octal 100410-100417)
		count += annotateDevice(listing, ioSpace, 0x8108, "OCT2", "Octobus Interface", "2", "100410-100417", "13", "042/043", "octobus");

		// Octobus Interface 3 (octal 100420-100427)
		count += annotateDevice(listing, ioSpace, 0x8110, "OCT3", "Octobus Interface", "3", "100420-100427", "13", "044/045", "octobus");

		// Octobus Interface 4 (octal 100430-100437)
		count += annotateDevice(listing, ioSpace, 0x8118, "OCT4", "Octobus Interface", "4", "100430-100437", "13", "046/047", "octobus");

		// Ethernet II Controller 1 (octal 140360-140363)
		count += annotateDevice(listing, ioSpace, 0xC0F0, "ETH1", "Ethernet II Controller", "1", "140360-140363", "12", "0140034", "ethernet");

		// Ethernet II Controller 2 (octal 140364-140367)
		count += annotateDevice(listing, ioSpace, 0xC0F4, "ETH2", "Ethernet II Controller", "2", "140364-140367", "12", "0140035", "ethernet");

		// SCSI Disc Controller 1 (octal 144300-144377)
		count += annotateDevice(listing, ioSpace, 0xC8C0, "SCSI1", "SCSI Disc Controller", "1", "144300-144377", "11", "0140440", "scsi");

		// SCSI Disc Controller 2 (octal 144400-144477)
		count += annotateDevice(listing, ioSpace, 0xC900, "SCSI2", "SCSI Disc Controller", "2", "144400-144477", "11", "0140441", "scsi");


		// SCSI controllers use extended 24-bit IOX addresses (octal 144300+)
		// outside the current io_space range (0x000-0x3FF)

		// Ethernet II controllers use extended 24-bit IOX addresses (octal 140360+)
		// outside the current io_space range (0x000-0x3FF)

		// Mark as done so we don't re-annotate on every analysis pass
		progOptions.setBoolean(OPTION_DONE, true);

		// Don't log success — Ghidra shows "warnings/errors" dialog for ANY log message
		return true;
	}

	private void setPlate(Listing listing, AddressSpace space, int offset, String label, String comment) {
		// io_space has wordsize=2, so byte address = word address * 2
		Address addr = space.getAddress((long) offset * 2);
		listing.setComment(addr, CommentType.PLATE, comment);
		try {
			// Clear any auto-analysis data (undefined2) so we can define as word
			listing.clearCodeUnits(addr, addr, false);
			listing.createData(addr, WordDataType.dataType);
		}
		catch (Exception e) {
			// Best effort — data type may conflict
		}
		try {
			symbolTable.createLabel(addr, label, SourceType.ANALYSIS);
		}
		catch (Exception e) {
			// Best effort — label may already exist
		}
	}

	// =========================================================================
	// Device register definitions - generated from specs/io-devices.json
	// =========================================================================

	private int annotateDevice(Listing listing, AddressSpace io, int base,
			String prefix, String deviceDesc, String unit, String octalRange,
			String level, String ident, String deviceType) {

		String hdr = deviceDesc + " " + unit + " (octal " + octalRange +
			", level " + level + ", ident " + ident + ")";

		switch (deviceType) {
			case "ethernet":
				setPlate(listing, io, base + 0, prefix + "_DATA_LO", hdr + "\n" +
					prefix + " Data Register Low\n" +
					"Direction: Read/Write\n" +
					"ND-100 data exchange with 68000 local memory (low word)\n");

				setPlate(listing, io, base + 1, prefix + "_DATA_HI", hdr + "\n" +
					prefix + " Data Register High\n" +
					"Direction: Read/Write\n" +
					"ND-100 data exchange with 68000 local memory (high word)\n");

				setPlate(listing, io, base + 2, prefix + "_ADDR", hdr + "\n" +
					prefix + " Address Register\n" +
					"Direction: Read/Write\n" +
					"68000 local memory address for bank window access\n");

				setPlate(listing, io, base + 3, prefix + "_CTRL", hdr + "\n" +
					prefix + " Control/Status Register\n" +
					"Direction: Read/Write\n" +
					"Internal 68000 CPU (10 MHz) with 512KB DRAM, LANCE Am7990 Ethernet, MFP MC68901\n" +
					"Bit  0: InterruptEnable — triggers IRQ 12 to ND-100\n" +
					"Bit  1: Reset 68000 CPU\n" +
					"Bit  2: Bank select\n" +
					"Bit  3: Ready\n");

				return 4;
			case "floppy_dma":
				setPlate(listing, io, base + 0, prefix + "_READ_DATA", hdr + "\n" +
					prefix + " Read Data Register\n" +
					"Direction: Read\n" +
					"Read data from floppy controller\n");

				setPlate(listing, io, base + 1, prefix + "_UNUSED1", hdr + "\n" +
					prefix + " (Not Used)\n" +
					"" +
					"This register is not used\n");

				setPlate(listing, io, base + 2, prefix + "_READ_STATUS1", hdr + "\n" +
					prefix + " Read Status Register 1\n" +
					"Direction: Read\n" +
					"Bit  0: (unused)\n" +
					"Bit  1: Interrupt Enabled\n" +
					"Bit  2: Device Active (controller busy)\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bit  4: Error OR (inclusive OR of errors)\n" +
					"Bit  5: Deleted Record / EOF marker\n" +
					"Bit  6: Internal retry (no error)\n" +
					"Bit  7: Hard Error (no memory contact)\n" +
					"Bits 8-14: Error code from controller\n" +
					"Bit 15: Dual Density controller\n");

				setPlate(listing, io, base + 3, prefix + "_LOAD_CONTROL", hdr + "\n" +
					prefix + " Load Control Word\n" +
					"Direction: Write\n" +
					"Bit  0: (unused)\n" +
					"Bit  1: Enable Interrupt\n" +
					"Bit  2: Activate Autoload\n" +
					"Bit  3: Test Mode\n" +
					"Bit  4: Device Clear\n" +
					"Bit  5: Enable Streamer\n" +
					"Bits 6-7: (unused)\n" +
					"Bit  8: Execute Command (from command block in memory)\n" +
					"Bits 9-13: Test Data (when test mode active)\n" +
					"Bits 14-15: (unused)\n");

				setPlate(listing, io, base + 4, prefix + "_READ_STATUS2", hdr + "\n" +
					prefix + " Read Status Register 2\n" +
					"Direction: Read\n" +
					"Bits 0-1: Bytes per Sector encoding\n" +
					"Bit  2: Double Sided diskette\n" +
					"Bit  3: Double Density format\n" +
					"Bits 4-15: (unused)\n");

				setPlate(listing, io, base + 5, prefix + "_LOAD_PTR_HI", hdr + "\n" +
					prefix + " Load Pointer High\n" +
					"Direction: Write\n" +
					"Load command block pointer high bits (23-16)\n");

				setPlate(listing, io, base + 6, prefix + "_UNUSED6", hdr + "\n" +
					prefix + " (Not Used)\n" +
					"" +
					"This register is not used\n");

				setPlate(listing, io, base + 7, prefix + "_LOAD_PTR_LO", hdr + "\n" +
					prefix + " Load Pointer Low / Load Data\n" +
					"Direction: Write\n" +
					"Load command block pointer low bits (15-0)\n");

				return 8;
			case "hdlc":
				setPlate(listing, io, base + 0, prefix + "_RX_DATA", hdr + "\n" +
					prefix + " Receiver Data Register (RxDR)\n" +
					"Direction: Read\n" +
					"Assembled byte from COM5025 receiver buffer\n");

				setPlate(listing, io, base + 1, prefix + "_PCR", hdr + "\n" +
					prefix + " Parameter Control Register (PCR)\n" +
					"Direction: Write\n" +
					"HDLC protocol definition (8 bits). Written to COM5025 Mode register during INITIALIZE.\n");

				setPlate(listing, io, base + 2, prefix + "_RX_STATUS", hdr + "\n" +
					prefix + " Receiver Status Register (RxSR)\n" +
					"Direction: Read\n" +
					"COM5025 receiver status (8 bits)\n");

				setPlate(listing, io, base + 3, prefix + "_SAR", hdr + "\n" +
					prefix + " Sync/Address Register (SAR)\n" +
					"Direction: Write\n" +
					"Station address (bit-oriented) or SYNC char (byte-oriented)\n");

				setPlate(listing, io, base + 4, prefix + "_CHL", hdr + "\n" +
					prefix + " Character Length Register (CHL)\n" +
					"Direction: Write\n" +
					"Usually 8 bits each (value 0x88)\n" +
					"Bits 0-2: Receiver character length\n" +
					"Bits 3-4: (unused)\n" +
					"Bits 5-7: Transmitter character length\n");

				setPlate(listing, io, base + 5, prefix + "_TX_DATA", hdr + "\n" +
					prefix + " Transmitter Data Register (TxDR)\n" +
					"Direction: Write\n" +
					"Byte to transmit via COM5025\n");

				setPlate(listing, io, base + 6, prefix + "_TX_STATUS", hdr + "\n" +
					prefix + " Transmitter Status Register (TxSR)\n" +
					"Direction: Read\n" +
					"COM5025 transmitter status (8 bits)\n");

				setPlate(listing, io, base + 7, prefix + "_TX_CTRL", hdr + "\n" +
					prefix + " Transmitter Control Word (TxCW)\n" +
					"Direction: Write\n" +
					"COM5025 transmitter control (same bits as TxSR)\n");

				setPlate(listing, io, base + 8, prefix + "_RRTS", hdr + "\n" +
					prefix + " Receiver Transfer Status (RRTS)\n" +
					"Direction: Read\n" +
					"High byte auto-cleared on read\n" +
					"Bit  0: DataAvailable — byte assembled in RX buffer\n" +
					"Bit  1: StatusAvailable — status ready in RxSR\n" +
					"Bit  2: ReceiverActive — frame in progress\n" +
					"Bit  3: SyncFlagReceived — FLAG detected\n" +
					"Bit  4: DMAModuleRequest — DMA needs attention (auto-clear)\n" +
					"Bit  5: SD — Signal Detector (modem)\n" +
					"Bit  6: DSR — Data Set Ready (modem)\n" +
					"Bit  7: RI — Ring Indicator (modem)\n" +
					"Bit  8: BlockEnd — DMA block complete (auto-clear)\n" +
					"Bit  9: FrameEnd — HDLC frame received (auto-clear)\n" +
					"Bit 10: ListEnd — descriptor list exhausted (auto-clear)\n" +
					"Bit 11: ListEmpty — NO RX BUFFERS! Disables receiver (auto-clear)\n" +
					"Bit 13: X21D — X.21 Data Indication Error\n" +
					"Bit 14: X21S — X.21 Call Setup/Clear Error\n" +
					"Bit 15: ReceiverOverrun — buffer overrun\n");

				setPlate(listing, io, base + 9, prefix + "_WRTC", hdr + "\n" +
					prefix + " Receiver Transfer Control (WRTC)\n" +
					"Direction: Write\n" +
					"Bit  0: DataAvailableIE — enable IRQ 13 on DataAvailable\n" +
					"Bit  1: StatusAvailableIE — enable IRQ 13 on StatusAvailable\n" +
					"Bit  2: EnableReceiver — turn on receiver\n" +
					"Bit  3: EnableReceiverDMA — route DataAvail to DMA\n" +
					"Bit  4: DMAModuleIE — enable IRQ 13 on DMA request\n" +
					"Bit  5: DeviceClear+Maintenance — clear + enter loopback\n" +
					"Bit  6: DTR — Data Terminal Ready\n" +
					"Bit  7: ModemStatusChangeIE — enable IRQ on modem change\n" +
					"Bit  8: BlockEndIE — enable IRQ on Block End\n" +
					"Bit  9: FrameEndIE — enable IRQ on Frame End\n" +
					"Bit 10: ListEndIE — enable IRQ on List End\n");

				setPlate(listing, io, base + 10, prefix + "_RTTS", hdr + "\n" +
					prefix + " Transmitter Transfer Status (RTTS)\n" +
					"Direction: Read\n" +
					"High byte auto-cleared on read\n" +
					"Bit  0: TxBufferEmpty — ready for new byte\n" +
					"Bit  1: TxUnderrun — buffer not loaded in time\n" +
					"Bit  2: TxActive — transmitter active\n" +
					"Bit  6: RFS — Ready For Sending / CTS (modem)\n" +
					"Bit  8: BlockEnd — DMA buffer sent (auto-clear)\n" +
					"Bit  9: FrameEnd — HDLC frame sent TEOM (auto-clear)\n" +
					"Bit 10: ListEnd — all descriptors done (auto-clear)\n" +
					"Bit 11: TxFinished — DMA done, auto-sets DMAReq (auto-clear)\n" +
					"Bit 15: Illegal — bad key/format in descriptor\n");

				setPlate(listing, io, base + 11, prefix + "_WTTC", hdr + "\n" +
					prefix + " Transmitter Transfer Control (WTTC)\n" +
					"Direction: Write\n" +
					"Bit  0: TxBufferEmptyIE — enable IRQ 12 on buffer empty\n" +
					"Bit  1: TxUnderrunIE — enable IRQ 12 on underrun\n" +
					"Bit  2: TxEnabled — enable transmitter output\n" +
					"Bit  3: EnableTxDMA — route buffer-empty to DMA\n" +
					"Bit  4: DMAModuleIE — enable IRQ 12 on DMA request\n" +
					"Bit  5: HalfDuplex — half-duplex mode\n" +
					"Bit  6: RTS — Request To Send\n" +
					"Bit  7: ModemStatusChangeIE — enable IRQ on RFS change\n" +
					"Bit  8: BlockEndIE — enable IRQ on Block End\n" +
					"Bit  9: FrameEndIE — enable IRQ on Frame End\n" +
					"Bit 10: ListEndIE — enable IRQ on List End\n");

				setPlate(listing, io, base + 12, prefix + "_DMA_ADDR_R", hdr + "\n" +
					prefix + " DMA Address Read\n" +
					"Direction: Read\n" +
					"Reads back last value written to DMA Address Write\n");

				setPlate(listing, io, base + 13, prefix + "_DMA_ADDR_W", hdr + "\n" +
					prefix + " DMA Address Write\n" +
					"Direction: Write\n" +
					"16 LSBs of buffer/descriptor list address\n");

				setPlate(listing, io, base + 14, prefix + "_DMA_CMD_R", hdr + "\n" +
					prefix + " DMA Command Read\n" +
					"Direction: Read\n" +
					"Read DMA command status (shifted left 8 bits)\n");

				setPlate(listing, io, base + 15, prefix + "_DMA_CMD_W", hdr + "\n" +
					prefix + " DMA Command Write\n" +
					"Direction: Write\n" +
					"Bits 0-3: Bank bits for 18-bit DMA addressing\n" +
					"Bits 8-10: Command: 0=CLEAR 1=INIT 2=RX_START 3=RX_CONT 4=TX_START 5=DUMP_DATA 6=DUMP_REGS 7=LOAD_REGS\n");

				return 16;
			case "line_printer":
				setPlate(listing, io, base + 0, prefix + "_READ_DATA", hdr + "\n" +
					prefix + " Read Data\n" +
					"Direction: Read\n" +
					"Read back data in buffer (only valid in test mode, bit 3 in control)\n");

				setPlate(listing, io, base + 1, prefix + "_WRITE_DATA", hdr + "\n" +
					prefix + " Write Data\n" +
					"Direction: Write\n" +
					"Write character to buffer register\n" +
					"Codes 0-037 (octal) are illegal except:\n" +
					"  011: HT (horizontal tab)\n" +
					"  012: LF (line feed)\n" +
					"  014: FF (form feed)\n" +
					"  015: CR (carriage return)\n" +
					"  020-033: VFU channels (020=FF via channel 1)\n");

				setPlate(listing, io, base + 2, prefix + "_READ_STATUS", hdr + "\n" +
					prefix + " Read Status\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt enabled on ready\n" +
					"Bit  1: Interrupt enabled on error\n" +
					"Bit  2: (unused)\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bit  4: Error (bit 5 or 6 set)\n" +
					"Bit  5: Line printer not ready\n" +
					"Bit  6: Out of paper\n" +
					"Bit  7: Compressed pitch\n" +
					"Bit  8: LP9 (format/control code mode)\n" +
					"Bit  9: Inhibit (illegal character in buffer)\n" +
					"Bit 10: (unused)\n" +
					"Bits 11-12: Band detect (00=128ch, 01=96ch, 10=64ch, 11=48ch)\n" +
					"Bits 13-15: (unused)\n");

				setPlate(listing, io, base + 3, prefix + "_WRITE_CONTROL", hdr + "\n" +
					prefix + " Write Control\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt on ready for transfer\n" +
					"Bit  1: Enable interrupt on error\n" +
					"Bit  2: Activate (print character in buffer)\n" +
					"Bit  3: Test mode\n" +
					"Bit  4: Device and interface clear\n" +
					"Bits 5-15: (unused)\n");

				return 4;
			case "nd500_interface":
				setPlate(listing, io, base + 0, prefix + "_READ_MAR", hdr + "\n" +
					prefix + " Read MAR x2\n" +
					"Direction: Read\n" +
					"Read Memory Address Register bits 0-15 (doubled)\n");

				setPlate(listing, io, base + 1, prefix + "_LOAD_MAR", hdr + "\n" +
					prefix + " Load MAR x2\n" +
					"Direction: Write\n" +
					"Load Memory Address Register bits 0-15 (doubled)\n");

				setPlate(listing, io, base + 2, prefix + "_READ_STATUS", hdr + "\n" +
					prefix + " Read Status\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt enabled\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: ND-500 busy\n" +
					"Bit  3: ND-500 finished\n" +
					"Bit  4: Error\n" +
					"Bit  5: Interface locked (ND-500 running)\n" +
					"Bit  6: DMA error\n" +
					"Bit  7: ND-500 power fault\n" +
					"Bit  8: ND-500 power off\n" +
					"Bit  9: ND-500 micro clock stopped\n" +
					"Bits 10-14: ND-500 stop reason\n" +
					"Bit 15: CONTROL register bit 15\n");

				setPlate(listing, io, base + 3, prefix + "_LOAD_STATUS", hdr + "\n" +
					prefix + " Load Status (test mode only)\n" +
					"Direction: Write\n" +
					"Load status register for testing (only in Not Locked + Test mode)\n");

				setPlate(listing, io, base + 4, prefix + "_READ_CONTROL", hdr + "\n" +
					prefix + " Read Control\n" +
					"Direction: Read\n" +
					"Read back the control register (only in Locked Test or Not Locked Test mode)\n");

				setPlate(listing, io, base + 5, prefix + "_LOAD_CONTROL", hdr + "\n" +
					prefix + " Load Control\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt from ND-500\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: Activate ND-500 operation (locks communication)\n" +
					"Bit  3: Test mode\n" +
					"Bit  4: ND-500 programmed clear\n" +
					"Bit  5: Disable TAG-IN decoding when locked\n" +
					"Bit  6: DMA error\n" +
					"Bit  7: Command chaining\n" +
					"Bits 8-14: ND-500 operation code\n" +
					"Bit 15: (unused)\n");

				setPlate(listing, io, base + 6, prefix + "_MASTER_CLEAR", hdr + "\n" +
					prefix + " Master Clear / Read Data (test)\n" +
					"Direction: Write/Read\n" +
					"Normal: Master clear of interface\n" +
					"Test: Read data register\n");

				setPlate(listing, io, base + 7, prefix + "_TERMINATE", hdr + "\n" +
					prefix + " Terminate / Load Data (test)\n" +
					"Direction: Write\n" +
					"Normal: Terminate current operation\n" +
					"Test: Load data register\n");

				setPlate(listing, io, base + 8, prefix + "_READ_TAG_IN", hdr + "\n" +
					prefix + " Read TAG-IN / Read Upper Limit (test)\n" +
					"Direction: Read\n" +
					"Normal: Read TAG-IN (message from ND-500)\n" +
					"Test: Read upper memory limit register\n");

				setPlate(listing, io, base + 9, prefix + "_WRITE_TAG_OUT", hdr + "\n" +
					prefix + " Write TAG-OUT / Load Upper Limit (test)\n" +
					"Direction: Write\n" +
					"Normal: Write TAG-OUT (command to ND-500)\n" +
					"Test: Load upper memory limit register\n");

				setPlate(listing, io, base + 10, prefix + "_READ_LOWER_LIM", hdr + "\n" +
					prefix + " Read Lower Limit (test only)\n" +
					"Direction: Read\n" +
					"Read lower memory limit register (test mode only)\n");

				setPlate(listing, io, base + 11, prefix + "_WRITE_DATAX", hdr + "\n" +
					prefix + " Write DATAX / Load Lower Limit (test)\n" +
					"Direction: Write\n" +
					"Normal: Write DATAX\n" +
					"Test: Load lower memory limit register\n");

				setPlate(listing, io, base + 12, prefix + "_READ_LOCKED1", hdr + "\n" +
					prefix + " Read Locked (test only)\n" +
					"Direction: Read\n" +
					"Read interface locked status\n");

				setPlate(listing, io, base + 13, prefix + "_WRITE_DATA", hdr + "\n" +
					prefix + " Write Data\n" +
					"Direction: Write\n" +
					"Write data to ND-500\n");

				setPlate(listing, io, base + 14, prefix + "_READ_LOCKED2", hdr + "\n" +
					prefix + " Read Locked\n" +
					"Direction: Read\n" +
					"Read interface locked status\n");

				setPlate(listing, io, base + 15, prefix + "_RETURN_GATE", hdr + "\n" +
					prefix + " Return Gate (RETG5)\n" +
					"Direction: Write\n" +
					"Microclock control\n" +
					"Bit  1: Stop microclock (halts ND-500 CPU)\n");

				return 16;
			case "octobus":
				setPlate(listing, io, base + 0, prefix + "_IN_READ_DATA", hdr + "\n" +
					prefix + " Input Read Data\n" +
					"Direction: Read\n" +
					"Read received data from 16-word FIFO\n");

				setPlate(listing, io, base + 1, prefix + "_IN_WRITE_DATA", hdr + "\n" +
					prefix + " Input Write Data\n" +
					"Direction: Write\n" +
					"Write data to input controller\n");

				setPlate(listing, io, base + 2, prefix + "_IN_READ_STATUS", hdr + "\n" +
					prefix + " Input Read Status\n" +
					"Direction: Read\n" +
					"Bit  0: InterruptEnable\n" +
					"Bit  1: FifoNotFull\n" +
					"Bit  2: RequestOn\n" +
					"Bit  3: ReadyForTransfer\n" +
					"Bit  4: Error\n" +
					"Bit  5: RetryCounter0\n" +
					"Bit  6: NotPresent — interface not installed\n" +
					"Bit  7: Busy\n" +
					"Bit  8: ParityError\n");

				setPlate(listing, io, base + 3, prefix + "_IN_WRITE_CTRL", hdr + "\n" +
					prefix + " Input Write Control\n" +
					"Direction: Write\n" +
					"Bit  0: InterruptEnable\n" +
					"Bit  2: TransmitEnable\n" +
					"Bit  3: ReceiveEnable\n" +
					"Bit  4: MasterClear (CMMACLE) — reset SAMSON\n" +
					"Bit  5: ContinueACCP — resume ACCP processor\n" +
					"Bit  6: Reset interface\n" +
					"Bit  7: TestMode\n");

				setPlate(listing, io, base + 4, prefix + "_OUT_READ_DATA", hdr + "\n" +
					prefix + " Output Read Data\n" +
					"Direction: Read\n" +
					"Read data from output controller\n");

				setPlate(listing, io, base + 5, prefix + "_OUT_WRITE_CMD", hdr + "\n" +
					prefix + " Output Write Command\n" +
					"Direction: Write\n" +
					"CMMACLE (master clear) or CMACONT (continue ACCP)\n");

				setPlate(listing, io, base + 6, prefix + "_OUT_READ_STATUS", hdr + "\n" +
					prefix + " Output Read Status\n" +
					"Direction: Read\n" +
					"Bit  0: InterruptEnable\n" +
					"Bit  2: RequestOn\n" +
					"Bit  3: ReadyForTransfer — data ready flag\n" +
					"Bit  4: Error\n" +
					"Bit  5: RetryCounter0\n" +
					"Bit  6: NotPresent — interface not installed\n" +
					"Bit  7: Busy\n" +
					"Bit  8: ParityError\n" +
					"Bit 15: Master flag\n");

				setPlate(listing, io, base + 7, prefix + "_OUT_WRITE_CTRL", hdr + "\n" +
					prefix + " Output Write Control\n" +
					"Direction: Write\n" +
					"Same control bits as Input Write Control\n");

				return 8;
			case "paper_tape":
				setPlate(listing, io, base + 0, prefix + "_READ_DATA", hdr + "\n" +
					prefix + " Read Data\n" +
					"Direction: Read\n" +
					"Read data byte from tape\n");

				setPlate(listing, io, base + 1, prefix + "_WRITE_DATA", hdr + "\n" +
					prefix + " Write Data Buffer\n" +
					"Direction: Write\n");

				setPlate(listing, io, base + 2, prefix + "_READ_STATUS", hdr + "\n" +
					prefix + " Read Status\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt Enabled\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: Read Active\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bits 4-15: (unused)\n");

				setPlate(listing, io, base + 3, prefix + "_WRITE_CONTROL", hdr + "\n" +
					prefix + " Write Control\n" +
					"Direction: Write\n" +
					"Bit  0: Interrupt Enable\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: Activate\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bit  4: Device Clear\n" +
					"Bits 5-15: (unused)\n");

				return 4;
			case "rtc":
				setPlate(listing, io, base + 0, prefix + "_READ_DATA", hdr + "\n" +
					prefix + " Read Data Register\n" +
					"Direction: Read\n" +
					"Bits 0-15: Returns 0\n");

				setPlate(listing, io, base + 1, prefix + "_CLEAR_COUNTER", hdr + "\n" +
					prefix + " Clear Counter\n" +
					"Direction: Write\n" +
					"Clear real-time clock counter.\n" +
					"Next clock pulse occurs exactly 20 ms later.\n" +
					"Repeated execution prevents counter increment.\n");

				setPlate(listing, io, base + 2, prefix + "_READ_STATUS", hdr + "\n" +
					prefix + " Read Status Register\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt Enabled - clock will interrupt on next pulse\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: External Hold Pulse received\n" +
					"Bit  3: Ready for Transfer - clock pulse occurred\n" +
					"Bits 4-15: (unused)\n");

				setPlate(listing, io, base + 3, prefix + "_WRITE_CONTROL", hdr + "\n" +
					prefix + " Write Control Register\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt on Ready for Transfer\n" +
					"Bit  1: Return address on opcom segment (RETSG)\n" +
					"Bits 2-9: (unused)\n" +
					"Bits 10-11: Frequency select (0=Stop, 1=100us, 2=10us, 3=1us)\n" +
					"Bit 12: External Hold Enable (1=enable, 0=disable)\n" +
					"Bit 13: Clear Ready for Transfer flag\n" +
					"Bit 14: Clear External Hold signal\n" +
					"Bit 15: Restart clock (preset to N-1)\n");

				return 4;
			case "scsi":
				setPlate(listing, io, base + 0, prefix + "_RLMAR", hdr + "\n" +
					prefix + " Memory Address Register LSB\n" +
					"Direction: Read\n" +
					"Read MAR bits 0-15\n");

				setPlate(listing, io, base + 1, prefix + "_WLMAR", hdr + "\n" +
					prefix + " Memory Address Register LSB\n" +
					"Direction: Write\n" +
					"Write MAR bits 0-15\n");

				setPlate(listing, io, base + 2, prefix + "_REDAT", hdr + "\n" +
					prefix + " Read Data\n" +
					"Direction: Read\n" +
					"Read 16-bit data (IOX mode only)\n");

				setPlate(listing, io, base + 3, prefix + "_WRDAT", hdr + "\n" +
					prefix + " Write Data\n" +
					"Direction: Write\n" +
					"Write 16-bit data (IOX mode only)\n");

				setPlate(listing, io, base + 4, prefix + "_RSTAU", hdr + "\n" +
					prefix + " Read Status Register\n" +
					"Direction: Read\n" +
					"Bit  0: InterruptEnabled\n" +
					"Bit  2: Interrupt set for ND-100\n" +
					"Bit  4: Reset Active\n" +
					"Bit  5: Halt\n");

				setPlate(listing, io, base + 5, prefix + "_WCONT", hdr + "\n" +
					prefix + " Write Control Register\n" +
					"Direction: Write\n" +
					"Bit  0: InterruptEnable — IRQ level 11 when ready\n" +
					"Bit  1: Active — start operation (set after command)\n" +
					"Bit  2: TestMode — MAR incremented on IOX read\n" +
					"Bit  4: ResetOnSCSIBus — assert SCSI bus reset\n" +
					"Bit  5: DataRequestFromNCR5386\n" +
					"Bit  6: InterruptFromNCR5386\n" +
					"Bit  7: DMAEnable — enable DMA transfers\n" +
					"Bit  8: WriteNDMemory — enable write to ND-100 memory\n");

				setPlate(listing, io, base + 6, prefix + "_RHMAR", hdr + "\n" +
					prefix + " Memory Address Register MSB\n" +
					"Direction: Read\n" +
					"Read MAR bits 16-23 (24-bit addressing)\n");

				setPlate(listing, io, base + 7, prefix + "_WHMAR", hdr + "\n" +
					prefix + " Memory Address Register MSB\n" +
					"Direction: Write\n" +
					"Write MAR bits 16-23\n");

				return 8;
			case "smd":
				setPlate(listing, io, base + 0, prefix + "_READ_MEM_ADDR", hdr + "\n" +
					prefix + " Read Core Address\n" +
					"Direction: Read\n" +
					"Read current memory (core) address register\n");

				setPlate(listing, io, base + 1, prefix + "_LOAD_MEM_ADDR", hdr + "\n" +
					prefix + " Load Core Address\n" +
					"Direction: Write\n" +
					"Load memory (core) address for DMA transfer\n");

				setPlate(listing, io, base + 2, prefix + "_READ_SEEK_COND", hdr + "\n" +
					prefix + " Read Seek Condition (CWR=0) / Read ECC Count (CWR=1)\n" +
					"Direction: Read\n" +
					"--- CWR bit 15 = 0: Seek Condition ---\n" +
					"--- CWR bit 15 = 1: ECC Count ---\n" +
					"Bits 0-7: Seek Complete status for units 0-7\n" +
					"Bits 8-10: Unit number from last control word\n" +
					"Bit 11: Seek Error for selected unit\n" +
					"Bit 12: SMD 15MHz (always 1 for ND632)\n" +
					"Bit 13: ECC error is correctable\n" +
					"Bit 14: ECC parity error (HW fault)\n" +
					"Bit 15: Last field read was address field\n");

				setPlate(listing, io, base + 3, prefix + "_LOAD_BLOCK_ADDR", hdr + "\n" +
					prefix + " Load Block Address I (CWR=0) / Load Block Address II (CWR=1)\n" +
					"Direction: Write\n" +
					"CWR=0: Load sector/track address\n" +
					"CWR=1: Load cylinder number (triggers seek when Active bit set)\n");

				setPlate(listing, io, base + 4, prefix + "_READ_STATUS", hdr + "\n" +
					prefix + " Read Status (CWR=0) / Read ECC Pattern (CWR=1)\n" +
					"Direction: Read\n" +
					"--- CWR bit 15 = 0: Status Register ---\n" +
					"Bit  0: Interrupt Enabled\n" +
					"Bit  1: Error Interrupt Enabled\n" +
					"Bit  2: Active (controller busy)\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bit  4: Hardware Error (inclusive OR)\n" +
					"Bit  5: Illegal Load\n" +
					"Bit  6: Timeout\n" +
					"Bit  7: Hardware Error 2 (disk fault)\n" +
					"Bit  8: Address Mismatch\n" +
					"Bit  9: (reserved)\n" +
					"Bit 10: Comparer Error\n" +
					"Bits 11-12: (reserved)\n" +
					"Bit 13: Disk Unit Not Ready\n" +
					"Bit 14: On Cylinder\n" +
					"Bit 15: CWR bit (register multiplex)\n");

				setPlate(listing, io, base + 5, prefix + "_LOAD_CONTROL", hdr + "\n" +
					prefix + " Load Control Word\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt on Not Active\n" +
					"Bit  1: Enable interrupt on Errors\n" +
					"Bit  2: Active (start operation, triggers seek)\n" +
					"Bit  3: Test Mode\n" +
					"Bit  4: Device Clear\n" +
					"Bits 5-6: Core address bits 16-17\n" +
					"Bits 7-9: Unit Select (max 4 units)\n" +
					"Bit 10: Marginal Recovery Cycle\n" +
					"Bits 11-14: Operation Code: 0=Read 1=Write 2=ReadParity 3=Compare 4=Seek 5=Format 6=SeekComplete 7=ReturnToZero 8=RunECC 9=SelectRelease\n" +
					"Bit 15: CWR bit (register multiplex)\n");

				setPlate(listing, io, base + 6, prefix + "_READ_BLOCK_ADDR", hdr + "\n" +
					prefix + " Read Block Address I (CWR=0) / Read Block Address II (CWR=1)\n" +
					"Direction: Read\n" +
					"CWR=0: Read sector/track address\n" +
					"CWR=1: Read cylinder number\n");

				setPlate(listing, io, base + 7, prefix + "_LOAD_WORD_COUNT", hdr + "\n" +
					prefix + " Load Word Count (CWR=0) / Load ECC Control (CWR=1)\n" +
					"Direction: Write\n" +
					"CWR=0: Set number of words for DMA transfer\n" +
					"CWR=1: Load ECC control register\n");

				return 8;
			case "terminal":
				setPlate(listing, io, base + 0, prefix + "_READ_INPUT", hdr + "\n" +
					prefix + " Read Input Data\n" +
					"Direction: Read\n" +
					"Read input data character from terminal\n");

				setPlate(listing, io, base + 1, prefix + "_WRITE_NOP", hdr + "\n" +
					prefix + " Write (No Operation)\n" +
					"Direction: Write\n" +
					"No operation\n");

				setPlate(listing, io, base + 2, prefix + "_READ_INPUT_STATUS", hdr + "\n" +
					prefix + " Read Input Status\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt Enabled - data available gives interrupt\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: Device Activated\n" +
					"Bit  3: Ready for Transfer - data available\n" +
					"Bit  4: Error OR - inclusive OR of bits 5-7\n" +
					"Bit  5: Framing Error\n" +
					"Bit  6: Parity Error\n" +
					"Bit  7: Overrun\n" +
					"Bits 8-10: (unused)\n" +
					"Bit 11: Carrier Missing\n" +
					"Bits 12-15: (unused)\n");

				setPlate(listing, io, base + 3, prefix + "_WRITE_INPUT_CTRL", hdr + "\n" +
					prefix + " Write Input Control\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt on data available\n" +
					"Bit  1: (unused)\n" +
					"Bit  2: Activate Device\n" +
					"Bit  3: Test Mode\n" +
					"Bit  4: Device Clear\n" +
					"Bits 5-10: (unused)\n" +
					"Bits 11-12: Character Length (0=8, 1=7, 2=6, 3=5)\n" +
					"Bit 13: Stop Bits (0=2 bits, 1=1 bit)\n" +
					"Bit 14: Parity (0=none, 1=even parity)\n" +
					"Bit 15: (unused)\n");

				setPlate(listing, io, base + 4, prefix + "_READ_ZERO", hdr + "\n" +
					prefix + " Read (Returns 0)\n" +
					"Direction: Read\n" +
					"Returns 0 in A register, no other effect\n");

				setPlate(listing, io, base + 5, prefix + "_WRITE_DATA", hdr + "\n" +
					prefix + " Write Output Data\n" +
					"Direction: Write\n" +
					"Write data character to terminal output\n");

				setPlate(listing, io, base + 6, prefix + "_READ_OUTPUT_STATUS", hdr + "\n" +
					prefix + " Read Output Status\n" +
					"Direction: Read\n" +
					"Bit  0: Interrupt Enabled - ready gives interrupt\n" +
					"Bits 1-2: (unused)\n" +
					"Bit  3: Ready for Transfer\n" +
					"Bits 4-15: (unused)\n");

				setPlate(listing, io, base + 7, prefix + "_WRITE_OUTPUT_CTRL", hdr + "\n" +
					prefix + " Write Output Control\n" +
					"Direction: Write\n" +
					"Bit  0: Enable interrupt on ready for transfer\n" +
					"Bits 1-15: (unused)\n");

				return 8;
			default:
				return 0;
		}
	}

}
