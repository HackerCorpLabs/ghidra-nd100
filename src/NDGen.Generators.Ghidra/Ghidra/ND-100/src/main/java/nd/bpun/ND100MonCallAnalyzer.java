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
// AUTO-GENERATED from specs/mon-calls.json — DO NOT EDIT
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
 * Analyzer that annotates MON (monitor call) instructions with the system
 * call name and octal number from SINTRAN III documentation.
 *
 * Auto-generated from specs/mon-calls.json (231 monitor calls).
 */
public class ND100MonCallAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 MON Call Annotator";
	private static final String DESCRIPTION =
		"Annotates MON instructions with SINTRAN III monitor call names.";

		// MON call lookup table — auto-generated from specs/mon-calls.json
	// Index = decimal MON call number, value = "Name (octalB)"
	private static final String[] MON_NAMES = new String[333];
	static {
		MON_NAMES[0] = "ExitFromProgram / LEAVE (0B)"; // Terminates the program.
		MON_NAMES[1] = "InByte / INBT (1B)"; // Reads one byte from a character device, e.g. a terminal o...
		MON_NAMES[2] = "OutByte / OUTBT (2B)"; // Writes one byte to a character device, e.g. a terminal or...
		MON_NAMES[3] = "SetEcho / ECHOM (3B)"; // When you press a key on the terminal, a character is norm...
		MON_NAMES[4] = "SetBreak / BRKM (4B)"; // Sets the break characters for a terminal.
		MON_NAMES[5] = "ReadScratchFile / RDISK (5B)"; // Reads randomly from the scratch file.
		MON_NAMES[6] = "WriteScratchFile / WDISK (6B)"; // Writes randomly to the scratch file.
		MON_NAMES[7] = "ReadBlock / RPAGE (7B)"; // Reads randomly from a file.
		MON_NAMES[8] = "WriteBlock / WPAGE (10B)"; // Writes randomly to a file.
		MON_NAMES[9] = "GetBasicTime / TIME (11B)"; // **Time**  Gets the current internal time.
		MON_NAMES[10] = "SetCommandBuffer / SETCM (12B)"; // Transfers a string to the command buffer.
		MON_NAMES[11] = "ClearInBuffer / CIBUF (13B)"; // Clears a device input buffer.
		MON_NAMES[12] = "ClearOutBuffer / COBUF (14B)"; // Clears a device output buffer.
		MON_NAMES[14] = "GetTerminalType / MGTTY (16B)"; // Gets the terminal type.
		MON_NAMES[15] = "SetTerminalType / MSTTY (17B)"; // Sets the type of a terminal.
		MON_NAMES[17] = "InUpTo8Bytes / M8INB (21B)"; // See also In8Bytes, InByte, InString, In4x2Bytes, and Out8...
		MON_NAMES[18] = "OutUpTo8Bytes / M8OUT (22B)"; // Writes up to 8 characters to a device, e.g. a terminal or...
		MON_NAMES[19] = "In8Bytes / B8INB (23B)"; // Reads 8 bytes from a device.
		MON_NAMES[20] = "Out8Bytes / B8OUT (24B)"; // Writes 8 bytes to a character device, e.g. a terminal.
		MON_NAMES[22] = "GetLastByte / LASTC (26B)"; // Gets the last character typed on a terminal.
		MON_NAMES[23] = "GetRTDescr / RTDSC (27B)"; // Reads an RT description.
		MON_NAMES[24] = "GetOwnRTAddress / GETRT (30B)"; // Gets the address of the calling program's RT description.
		MON_NAMES[25] = "IOInstruction / EXIOX (31B)"; // Executes an IOX machine instruction.
		MON_NAMES[26] = "OutMessage / MSG (32B)"; // Writes a message to the user's terminal.
		MON_NAMES[27] = "AltPageTable / ALTON (33B)"; // Switches page table.
		MON_NAMES[28] = "NormalPageTable / ALTOFF (34B)"; // Sets the alternative page table equal to the normal page ...
		MON_NAMES[29] = "OutNumber / IOUT (35B)"; // Writes a number to the user's terminal.
		MON_NAMES[30] = "NoWaitSwitch / NOWT (36B)"; // Switches No Wait on and off.
		MON_NAMES[31] = "ReadADChannel / AIRDW (37B)"; // Reads an analog to digital channel.
		MON_NAMES[32] = "CloseSpoolingFile / SPCLO (40B)"; // Appends an opened file to a spooling queue.
		MON_NAMES[33] = "ReadObjectEntry / ROBJE (41B)"; // Gets information about an opened file.
		MON_NAMES[35] = "CloseFile / CLOSE (43B)"; // Closes one or more files.
		MON_NAMES[36] = "GetUserEntry / RUSER (44B)"; // Gets information about a user.
		MON_NAMES[40] = "OpenFile / OPEN (50B)"; // Opens a file.
		MON_NAMES[42] = "TerminalMode / TERMO (52B)"; // Selects various terminal functions.
		MON_NAMES[43] = "GetSegmentEntry / RSEGM (53B)"; // Gets information about a segment in the ND-100.
		MON_NAMES[44] = "DeleteFile / MDLFI (54B)"; // Deletes a file.
		MON_NAMES[45] = "GetSpoolingEntry / RSQPE (55B)"; // Gets the next spooling queue entry, that is, the next fil...
		MON_NAMES[46] = "SetUserParam / PASET (56B)"; // Sets information about a background program.
		MON_NAMES[47] = "GetUserParam / PAGEI (57B)"; // Gets information about why the last program terminated.
		MON_NAMES[48] = "N500M / ND500Function (60B)"; // ND-500 Monitor Function - The primary way ND-100 programs...
		MON_NAMES[49] = "MemoryAllocation / FIXC5 (61B)"; // Fixes or unfixes ND-100 segments to be used by the ND-500...
		MON_NAMES[50] = "GetBytesInFile / RMAX (62B)"; // Gets the number of bytes in a file.
		MON_NAMES[51] = "In4x2Bytes / B41NW (63B)"; // Reads 8 bytes from a word-oriented or character-oriented ...
		MON_NAMES[52] = "WarningMessage / ERMSG (64B)"; // Outputs a file system error message.
		MON_NAMES[53] = "ErrorMessage / QERMS (65B)"; // Displays a file system error message.
		MON_NAMES[54] = "InBufferSpace / ISIZE (66B)"; // Gets the current number of bytes in the input buffer.
		MON_NAMES[55] = "OutBufferSpace / OSIZE (67B)"; // Gets the number of free bytes in the output buffer (numbe...
		MON_NAMES[56] = "CallCommand / COMMND (70B)"; // Executes a SINTRAN III command from a program.
		MON_NAMES[57] = "DisableEscape / DESCF (71B)"; // The ESCAPE key on the terminal normally terminates a prog...
		MON_NAMES[58] = "EnableEscape / EESCF (72B)"; // Enables the ESCAPE key on the terminal.
		MON_NAMES[59] = "SetMaxBytes / SMAX (73B)"; // Sets the value of the maximum byte pointer in an opened f...
		MON_NAMES[60] = "SetStartByte / SETBT (74B)"; // Sets the next byte to be read or written in an opened mas...
		MON_NAMES[61] = "GetStartByte / REABT (75B)"; // Gets the number of the next byte to access in a file.
		MON_NAMES[62] = "SetBlockSize / SETBS (76B)"; // Sets the block size of an opened file.
		MON_NAMES[63] = "SetStartBlock / SETBL (77B)"; // Sets the next block to be read or written in an opened file.
		MON_NAMES[64] = "StartRTProgram / RT (100B)"; // Starts an RT program.
		MON_NAMES[65] = "DelayStart / SET (101B)"; // Starts an RT program after a specified time.
		MON_NAMES[66] = "StartupTime / ABSET (102B)"; // Starts an RT program at a specified time of the day.
		MON_NAMES[67] = "StartupInterval / INTV (103B)"; // Prepares an RT program for periodic execution.
		MON_NAMES[68] = "SuspendProgram / HOLD (104B)"; // Suspends the execution of your program for a given time.
		MON_NAMES[69] = "StopRTProgram / ABORT (105B)"; // Stops an RT program.
		MON_NAMES[70] = "StartOnInterrupt / CONCT (106B)"; // StartOnInterrupt connects an RT program to interrupts fro...
		MON_NAMES[71] = "NoInterruptStart / DSCNT (107B)"; // StartOnInterrupt connects an RT program to interrupts fro...
		MON_NAMES[72] = "SetRTPriority / PRIOR (110B)"; // Sets the priority of an RT program.
		MON_NAMES[73] = "SetClock / UPDAT (111B)"; // Gives new values to the computer's clock and calendar.
		MON_NAMES[74] = "AdjustClock / CLADJ (112B)"; // Sets the computer's clock (i.e. the current system time) ...
		MON_NAMES[75] = "GetCurrentTime / CLOCK (113B)"; // Gets the current system time and date.
		MON_NAMES[76] = "GetTimeUsed / TUSED (114B)"; // Gets the time you have used the CPU since you logged in.
		MON_NAMES[77] = "FixScattered / FIX (115B)"; // Place a segment in physical memory.
		MON_NAMES[78] = "UnfixSegment / UNFIX (116B)"; // Releases a fixed segment and removes it from the Page Ind...
		MON_NAMES[79] = "ReadFromFile / RFILE (117B)"; // Reads any number of bytes from a file.
		MON_NAMES[80] = "WriteToFile / WFILE (120B)"; // Writes any number of bytes to a file.
		MON_NAMES[81] = "AwaitFileTransfer / WAITF (121B)"; // Checks that a data transfer to or from a mass-storage fil...
		MON_NAMES[82] = "ReserveResource / RESRV (122B)"; // Reserves a device or file for your program only.
		MON_NAMES[83] = "ReleaseResource / RELES (123B)"; // Releases a reserved device or file.
		MON_NAMES[84] = "ForceReserve / PRSRV (124B)"; // Reserves a device for an RT program other than that which...
		MON_NAMES[85] = "ForceRelease / PRLRS (125B)"; // Releases a device reserved by an RT program other than th...
		MON_NAMES[86] = "ExactDelayStart / DSET (126B)"; // Sets an RT program to start after a given period.
		MON_NAMES[87] = "ExactStartup / DABST (127B)"; // Starts an RT program at a specific time.
		MON_NAMES[88] = "ExactInterval / DINTV (130B)"; // Prepares an RT program for periodic execution.
		MON_NAMES[89] = "DataTransfer / ABSTR (131B)"; // Transfers data between physical memory and a mass-storage...
		MON_NAMES[90] = "JumpToSegment / MCALL (132B)"; // Calls a routine on another segment in the ND-100.
		MON_NAMES[91] = "ExitFromSegment / MEXIT (133B)"; // Exchanges one or both current segments.
		MON_NAMES[92] = "ExitRTProgram / RTEXT (134B)"; // Terminates the calling RT or background program.
		MON_NAMES[93] = "WaitForRestart / RTWT (135B)"; // Sets the RT program in a waiting state.
		MON_NAMES[94] = "EnableRTStart / RTON (136B)"; // RTON RT programs cannot be started after DisableRTStart h...
		MON_NAMES[95] = "DisableRTStart / RTOFF (137B)"; // Disables start of RT programs.
		MON_NAMES[96] = "ReservationInfo / WHDEV (140B)"; // Checks that a device is not reserved.
		MON_NAMES[97] = "DeviceControl / IOSET (141B)"; // Sets control information for a character device, e.g. a t...
		MON_NAMES[98] = "ToErrorDevice / ERMON (142B)"; // Outputs a user-defined, real-time error.
		MON_NAMES[99] = "ExecutionInfo / RSIO (143B)"; // Gets information about the execution of the calling program.
		MON_NAMES[100] = "DeviceFunction / MAGTP (144B)"; // Performs various operations on floppy disks, magnetic tap...
		MON_NAMES[102] = "PrivInstruction / IPRIV (146B)"; // Executes a privileged machine instruction on the ND-100.
		MON_NAMES[103] = "CAMACFunction / CAMAC (147B)"; // Operates the CAMAC, i.e. executes the NAF register.
		MON_NAMES[104] = "CAMACGLRegister / GL (150B)"; // Read the CAMAC GL (Graded LAM - \"look at me\") register or...
		MON_NAMES[105] = "GetRTAddress / GRTDA (151B)"; // Gets the address of an RT description.
		MON_NAMES[106] = "GetRTName / GRTNA (152B)"; // Gets the name of an RT program.
		MON_NAMES[107] = "CAMACIOInstruction / IOXN (153B)"; // Executes a single IOX instruction for CAMAC.
		MON_NAMES[108] = "AssignCAMACLAM / ASSIG (154B)"; // Assigns a graded LAM in the CAMAC identification table to...
		MON_NAMES[109] = "GraphicFunction / GRAPH (155B)"; // Executes various functions on a graphic peripheral, such ...
		MON_NAMES[111] = "SegmentToPageTable / ENTSG (157B)"; // Enters a routine as a direct task or as a device driver, ...
		MON_NAMES[112] = "FixContiguous / FIXC (160B)"; // Places a segment in physical memory.
		MON_NAMES[113] = "InString / INSTR (161B)"; // Reads a string of characters from a peripheral device, e....
		MON_NAMES[114] = "OutString / OUTST (162B)"; // Writes a string of characters to a peripheral file, e.g.,...
		MON_NAMES[116] = "SaveSegment / WSEG (164B)"; // Saves a segment in the ND-100.
		MON_NAMES[117] = "GetInRegisters / DIW (165B)"; // Reads the device interface registers.
		MON_NAMES[119] = "AttachSegment / REENT (167B)"; // Attaches a reentrant segment to your two current segments.
		MON_NAMES[120] = "UserDef0 / US0 (170B)"; // User-defined monitor call.
		MON_NAMES[121] = "UserDef1 / US1 (171B)"; // User-defined monitor call.
		MON_NAMES[122] = "UserDef2 / US2 (172B)"; // User-defined monitor call.
		MON_NAMES[123] = "UserDef3 / US3 (173B)"; // User-defined monitor call.
		MON_NAMES[124] = "UserDef4 / US4 (174B)"; // User-defined monitor call.
		MON_NAMES[125] = "UserDef5 / US5 (175B)"; // User-defined monitor call.
		MON_NAMES[126] = "UserDef6 / US6 (176B)"; // User-defined monitor call.
		MON_NAMES[127] = "UserDef7 / US7 (177B)"; // User-defined monitor call.
		MON_NAMES[128] = "XMSGFunction / XMSG (200B)"; // Performs various data communication functions.
		MON_NAMES[129] = "HDLCfunction / MHDLC (201B)"; // Performs various HDLC functions.
		MON_NAMES[134] = "TerminationHandling / EDTRM (206B)"; // Switches termination handling on and off.
		MON_NAMES[135] = "GetErrorInfo / RERRP (207B)"; // Gets information about the last real-time error.
		MON_NAMES[138] = "ReentrantSegment / SREEN (212B)"; // Connects a reentrant segment to your two current segments.
		MON_NAMES[139] = "GetDirUserIndexes / MUIDI (213B)"; // Gets a directory index and a user index.
		MON_NAMES[140] = "GetUserName / GUSNA (214B)"; // Gets the name of a user.
		MON_NAMES[141] = "GetObjectEntry / DROBJ (215B)"; // Gets information about a file.
		MON_NAMES[142] = "SetObjectEntry / DWOBJ (216B)"; // Changes the description of a file.
		MON_NAMES[143] = "GetAllFileIndexes / GUIOI (217B)"; // Gets the directory index, the user index, and the object ...
		MON_NAMES[144] = "DirectOpen / DOPEN (220B)"; // Opens a file.
		MON_NAMES[145] = "CreateFile / CRALF (221B)"; // Creates a file.
		MON_NAMES[146] = "GetAddressArea / GBSIZ (222B)"; // Gets the size of your address area.
		MON_NAMES[151] = "SetEscLocalChars / MSDAE (227B)"; // You can terminate most programs with the ESCAPE key.
		MON_NAMES[152] = "GetEscLocalChars / MGDAE (230B)"; // Gets ESCAPE and LOCAL characters.
		MON_NAMES[153] = "ExpandFile / EXPFI (231B)"; // Expands the file size.
		MON_NAMES[154] = "RenameFile / MRNFI (232B)"; // See also @RENAME-FILE.
		MON_NAMES[155] = "SetTemporaryFile / STEFI (233B)"; // Defines a file to store information temporarily.
		MON_NAMES[156] = "SetPeripheralName / SPEFI (234B)"; // Defines a peripheral file, e.g. a printer.
		MON_NAMES[157] = "ScratchOpen / SCROP (235B)"; // Opens a file as a scratch file.
		MON_NAMES[158] = "SetPermanentOpen / SPERD (236B)"; // Sets a file permanently open.
		MON_NAMES[159] = "SetFileAccess / SFACC (237B)"; // Sets the access protection for a file.
		MON_NAMES[160] = "AppendSpooling / APSPE (240B)"; // Prints a file.
		MON_NAMES[161] = "NewUser / SUSCN (241B)"; // Switches the user name you are logged in under.
		MON_NAMES[162] = "OldUser / RUSCN (242B)"; // Switches back to the user name you were logged in under b...
		MON_NAMES[163] = "GetDirNameIndex / FDINA (243B)"; // Gets directory index and name index.
		MON_NAMES[164] = "GetDirEntry / GDIEN (244B)"; // Gets information about a directory.
		MON_NAMES[165] = "GetNameEntry / GNAEN (245B)"; // Gets information about devices, e.g. disks and floppy disks.
		MON_NAMES[166] = "ReserveDir / REDIR (246B)"; // Reserves a directory for special use.
		MON_NAMES[167] = "ReleaseDir / RLDIR (247B)"; // Releases a directory.
		MON_NAMES[168] = "GetDefaultDir / FDFDI (250B)"; // Gets the user’s default directory.
		MON_NAMES[169] = "CopyPage / COPAG (251B)"; // Copies file pages between two opened files.
		MON_NAMES[170] = "BackupClose / BCLOS (252B)"; // Closes a file.
		MON_NAMES[171] = "NewFileVersion / CRALN (253B)"; // Creates new versions of a file.
		MON_NAMES[172] = "GetErrorDevice / GERDV (254B)"; // Gets the logical device number of the error device.
		MON_NAMES[173] = "PIOCFunction / PIOCM (255B)"; // PIOC is a programmable input and output processor primari...
		MON_NAMES[174] = "FullFileName / DEABF (256B)"; // Returns a complete file name from an abbreviated one.
		MON_NAMES[175] = "OpenFileInfo / FOPEN (257B)"; // Gets information about an open file.
		MON_NAMES[178] = "GetSystemInfo / CPUST (262B)"; // Gets various system information.
		MON_NAMES[179] = "GetDeviceType / GDEVT (263B)"; // Gets the device type, e.g. terminal, floppy disk, mass-st...
		MON_NAMES[183] = "TimeOut / TMOUT (267B)"; // Suspends the execution of your program for a given time.
		MON_NAMES[184] = "ReadDiskPage / RDPAG (270B)"; // Reads one or more directory pages.
		MON_NAMES[185] = "WriteDiskPage / WDPAG (271B)"; // Writes to one or more pages in a directory.
		MON_NAMES[186] = "DeletePage / DELPG (272B)"; // Deletes pages from a file.
		MON_NAMES[187] = "GetFileName / MGFIL (273B)"; // Gets the name of a file.
		MON_NAMES[188] = "GetFileIndexes / FOBJN (274B)"; // Gets the directory index, the user index, and the object ...
		MON_NAMES[189] = "SetTerminalName / STRFI (275B)"; // Defines the file name to be used for terminals.
		MON_NAMES[190] = "EnableLocal / ELOFU (276B)"; // You may log in on remote computers through the COSMOS dat...
		MON_NAMES[191] = "DisableLocal / DLOFU (277B)"; // You may log in on remote computers through the COSMOS dat...
		MON_NAMES[192] = "SetEscapeHandling / EUSEL (300B)"; // Enables user-defined escape handling.
		MON_NAMES[193] = "StopEscapeHandling / DUSEL (301B)"; // Disables user-defined escape handling.
		MON_NAMES[194] = "OnEscLocalFunction / ELON (302B)"; // Enables delayed escape and local functions for your termi...
		MON_NAMES[195] = "OffEscLocalFunction / ELOFF (303B)"; // Delays the escape and local functions for your terminal.
		MON_NAMES[198] = "GetTerminalMode / GTMOD (306B)"; // Gets the terminal mode.
		MON_NAMES[199] = "TerminalNoWait / TNOWAI (307B)"; // Switches No Wait on and off.
		MON_NAMES[200] = "In8AndFlag / TBIN8 (310B)"; // Reads 8 bytes from a device, e.g., a terminal.
		MON_NAMES[201] = "WriteDirEntry / WDIEN (311B)"; // Changes the information about a directory.
		MON_NAMES[202] = "CheckMonCall / MOINF (312B)"; // Some monitor calls are optional or only available in late...
		MON_NAMES[203] = "InBufferState / IBRISZ (313B)"; // Gets information about an input buffer.
		MON_NAMES[204] = "DefaultRemoteSystem / SRUSI (314B)"; // Sets default values for COSMOS remote file access.
		MON_NAMES[205] = "LAMUFunction / MLAMU (315B)"; // Performs various functions on the LAMU system.
		MON_NAMES[206] = "SetRemoteAccess / SRLMO (316B)"; // Switches remote file access on and off.
		MON_NAMES[207] = "ExecuteCommand / UECOM (317B)"; // Executes a SINTRAN III command.
		MON_NAMES[210] = "GetSegmentNo / GSGNO (322B)"; // Gets the number of a segment in the ND-100.
		MON_NAMES[211] = "SegmentOverlay / SPLRE (323B)"; // Used to build multisegment programs in the ND-100.
		MON_NAMES[212] = "OctobusFunction / OCTIO (324B)"; // Performs various functions on an old Octobus (earlier tha...
		MON_NAMES[213] = "BatchModeEcho / MBECH (325B)"; // Controls echo of input and output if the program is execu...
		MON_NAMES[214] = "LogInStart / MLOGI (326B)"; // Logs in a user on a terminal and starts a subsystem.
		MON_NAMES[215] = "FileSystemFunction / FSMTY (327B)"; // Multifunction monitor call to make sure that an uncontrol...
		MON_NAMES[216] = "TerminalStatus / TERST (330B)"; // Gets information about a terminal.
		MON_NAMES[218] = "TerminalLineInfo / TREPP (332B)"; // Gets information about a terminal line.
		MON_NAMES[219] = "DMAFunction / UDMA (333B)"; // Various DMA functions for Direct Memory Access operations.
		MON_NAMES[220] = "GetErrorMessage / GETXM (334B)"; // Gets a SINTRAN III error message text.
		MON_NAMES[221] = "TransferData / EXABS (335B)"; // Transfers data between physical memory and a mass-storage...
		MON_NAMES[222] = "Terminal / IOMTY (336B)"; // This I/O multifunction monitor call is used to change the...
		MON_NAMES[223] = "ChangeSegment / SPCHG (337B)"; // Changes the segment and the page table your program uses.
		MON_NAMES[224] = "ReadSystemRecord / RSREC (340B)"; // Used to read the system record into a buffer.
		MON_NAMES[225] = "SegmentFunction / SGMTY (341B)"; // This is a multifunction monitor call used to change the a...
		MON_NAMES[256] = "ErrorReturn / MACROE (400B)"; // Terminates the program and sets an error code.
		MON_NAMES[257] = "DisAssemble / DIASS (401B)"; // Disassembles one machine instruction on the ND-500.
		MON_NAMES[258] = "GetInputFlags / RFLAG (402B)"; // ND-100 and ND-500 programs may communicate through two 32...
		MON_NAMES[259] = "SetOutputFlags / WFLAG (403B)"; // ND-100 and ND-500 programs may communicate through two 32...
		MON_NAMES[260] = "FixIOArea / IOFIX (404B)"; // Fixes an address area in a domain in physical memory.
		MON_NAMES[261] = "SwitchUserBreak / USTRK (405B)"; // Switches user-defined escape handling on and off.
		MON_NAMES[262] = "AccessRTCommon / RWRTC (406B)"; // Reads from or writes to RT common from an ND-500 program.
		MON_NAMES[264] = "FixInMemory / FIXMEM (410B)"; // Fixes a logical segment (either whole or in part) of a us...
		MON_NAMES[265] = "MemoryUnfix / UNFIXM (411B)"; // Releases a fixed segment in your domain from physical mem...
		MON_NAMES[266] = "FileAsSegment / FSCNT (412B)"; // Connects a file as a segment to your domain.
		MON_NAMES[267] = "FileNotAsSegment / FSCDNT (413B)"; // Disconnects a file as a segment in your domain.
		MON_NAMES[268] = "BCNAFCAMAC / BCNAF (414B)"; // Special CAMAC function on the ND-500.
		MON_NAMES[269] = "BCNAF1CAMAC / BCNAF1 (415B)"; // Special CAMAC monitor call for the ND-500.
		MON_NAMES[270] = "SaveND500Segment / WSEGN (416B)"; // Writes all modified pages of a segment back to the disk.
		MON_NAMES[271] = "MaxPagesInMemory / MXPISG (417B)"; // Sets the maximum number of pages a segment may have in ph...
		MON_NAMES[272] = "GetUserRegisters / GRBLK (420B)"; // SwitchUserBreak allows you to save the registers when you...
		MON_NAMES[273] = "GetActiveSegment / GASGM (421B)"; // Gets the name of the segments in your domain.
		MON_NAMES[274] = "GetScratchSegment / GSWSP (422B)"; // Connects an empty data segment to the user's domain and r...
		MON_NAMES[275] = "CopyCapability / CAPCOP (423B)"; // Copies a capability for a segment.
		MON_NAMES[276] = "ClearCapability / CAPCLE (424B)"; // Clears a capability.
		MON_NAMES[277] = "SetProcessName / SPRNAM (425B)"; // Defines a new name for your process.
		MON_NAMES[278] = "GetProcessNo / GPRNAM (426B)"; // Gets the number of a process in the ND-500.
		MON_NAMES[279] = "GetOwnProcessInfo / GPRNME (427B)"; // Gets the name and number of your own process in the ND-500.
		MON_NAMES[280] = "TranslateAddress / ADR100 (430B)"; // Translates an ND-500 logical address to an ND-100 physica...
		MON_NAMES[281] = "AwaitTransfer / MWAITF (431B)"; // Checks that a data transfer to or from a mass-storage fil...
		MON_NAMES[285] = "ForceTrap / PRT (435B)"; // Forces a programmed trap to occur in another ND-500 process.
		MON_NAMES[286] = "SetND500Param / 5PASET (436B)"; // Sets information about an ND-500 program.
		MON_NAMES[287] = "GetND500Param / 5PAGET (437B)"; // Gets information about why the last ND-500 program termin...
		MON_NAMES[288] = "Attach500Segment / AT5SGM (440B)"; // Maps a logical ND-500 data segment onto shared ND-100/ND-...
		MON_NAMES[320] = "StartProcess / STARTP (500B)"; // Starts a process in the ND-500.
		MON_NAMES[321] = "StopProcess / STOPPR (501B)"; // Sets the current process in a wait state.
		MON_NAMES[322] = "SwitchProcess / SWITCHP (502B)"; // Sets the current process in a wait state.
		MON_NAMES[323] = "InputString / DVINST (503B)"; // Reads a string from a device, e.g. a terminal or an opene...
		MON_NAMES[324] = "OutputString / DVOUTS (504B)"; // Writes a string to a device, e.g. a terminal or an opened...
		MON_NAMES[325] = "GetTrapReason / GERRCOD (505B)"; // Gets the error code from the swapper process.
		MON_NAMES[327] = "SetProcessPriority / SPRIO (507B)"; // Sets the priority for a process in the ND-500.
		MON_NAMES[332] = "ND500TimeOut / 5TMOUT (514B)"; // Suspends the execution of an ND-500 program for a given t...
	}

	public ND100MonCallAnalyzer() {
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

			if (!"MON".equals(instr.getMnemonicString())) {
				continue;
			}

			// Get the displacement operand (MON call number)
			int numOps = instr.getNumOperands();
			if (numOps < 1) {
				continue;
			}

			// Parse the operand value — it's the 8-bit displacement
			String opRepr = instr.getDefaultOperandRepresentation(0);
			if (opRepr == null) {
				continue;
			}

			int callNum;
			try {
				if (opRepr.startsWith("0x") || opRepr.startsWith("0X")) {
					callNum = Integer.parseInt(opRepr.substring(2), 16);
				} else {
					callNum = Integer.parseInt(opRepr);
				}
			} catch (NumberFormatException e) {
				continue;
			}

			callNum = callNum & 0xFF;
			if (callNum < 0 || callNum >= MON_NAMES.length || MON_NAMES[callNum] == null) {
				continue;
			}

			// Don't overwrite existing comments
			String existing = instr.getComment(CommentType.EOL);
			if (existing != null && existing.length() > 0) {
				continue;
			}

			instr.setComment(CommentType.EOL, MON_NAMES[callNum]);
		}

		return true;
	}
}
