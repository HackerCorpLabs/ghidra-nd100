# ND-100 Ghidra Extension

A comprehensive Ghidra extension providing complete support for the Norsk Data ND-100 16-bit minicomputer architecture.

## Overview

This extension adds full ND-100 processor support to Ghidra, including:

- **SLEIGH Language Specification** - Complete disassembly support for all 153 ND-100 instructions
- **BPUN File Format Loader** - Native support for Bootable Punched Tape files
- **Modern Ghidra API** - Uses latest loader patterns with `List<Loaded<Program>>` support

## Features

### ✅ Complete Instruction Set Support
- **153 Instructions** - Full ND-100 instruction coverage
- **All Addressing Modes** - Direct, indirect, indexed, and immediate addressing
- **System Instructions** - Privileged operations, I/O, and interrupt handling
- **Floating Point** - Hardware floating-point instruction support
- **Bit Manipulation** - Comprehensive bit-level operations

### ✅ BPUN File Format Support
- **Automatic Detection** - Files are automatically recognized as BPUN format
- **Multi-Section Loading** - Support for multiple load sections with checksums
- **Entry Point Detection** - Automatic identification of start and boot addresses
- **Memory Layout** - Proper memory block creation with appropriate permissions

### ✅ Professional Integration
- **Memory Blocks** - Creates properly named and configured memory segments
- **Symbol Creation** - Automatic START and BOOT label generation
- **Entry Points** - Registers entry points for analysis
- **Error Handling** - Comprehensive error reporting and recovery

## Installation

### Via Ghidra Extension Manager (Recommended)
1. Open Ghidra
2. Go to **File → Install Extensions...**
3. Click the **+** button in the top right
4. Select the `ghidra_12.0.4_PUBLIC_YYYYMMDD_ND-100.zip` file
5. Click **OK**
6. Restart Ghidra when prompted

### Manual Installation
1. Extract the ZIP file to your Ghidra extensions directory:
   - **User Extensions**: `{ghidra user settings}/Extensions/`
   - **System Extensions**: `<GHIDRA_INSTALL_DIR>/Ghidra/Extensions/`
2. Restart Ghidra

## Usage

### Loading BPUN Files
1. Create a new project or open existing project
2. Import a BPUN file via **File → Import File...**
3. The BPUN loader will automatically detect and process the file
4. Select the **ND-100:BE:16:default** language if prompted

### Analyzing ND-100 Code
1. After loading, the disassembly will show ND-100 assembly code
2. Entry points (START/BOOT) are automatically marked
3. Use Ghidra's standard analysis features for deeper investigation

### Language Selection
When importing non-BPUN ND-100 binaries:
- **Processor**: ND-100
- **Endianness**: Big Endian
- **Size**: 16-bit
- **Variant**: default
- **Language ID**: `ND-100:BE:16:default`

## BPUN File Format

The BPUN (Bootable Punched Tape) format is a specialized format used by ND-100 systems:

### Structure
```
[Preamble]          # Optional bootstrap code and addresses
!                   # Delimiter character
[Load Section 1]    # Address(2) + Count(2) + Data + Checksum(2) + Action(2)
[Load Section 2]    # Additional sections...
...
```

### Features Supported
- **Multiple Load Sections** - Files can contain multiple memory segments
- **Checksum Validation** - Automatic verification of data integrity
- **Address Parsing** - Octal start/boot addresses from preamble
- **Action Codes** - Support for different section types and actions

## Technical Details

### Processor Specifications
- **Architecture**: 16-bit big-endian
- **Address Space**: 64KB (0x0000 - 0xFFFF)
- **Word Size**: 16 bits
- **Byte Order**: Big-endian (MSB first)

### Instruction Categories
- **Arithmetic**: ADD, SUB, MPY, DIV, floating-point operations
- **Logical**: AND, ORA, XOR, bit manipulation
- **Transfer**: Load/store operations with various addressing modes
- **Control**: Jumps, branches, subroutine calls
- **System**: I/O, interrupts, privileged operations
- **Special**: Shift, rotate, stack operations

### Memory Organization
- **Code Sections**: Executable memory blocks with appropriate permissions
- **Entry Points**: START and BOOT addresses marked as external entry points
- **Symbol Table**: Automatic label creation for known addresses

## Compatibility

- **Ghidra Version**: 11.2 or later
- **Java Version**: JDK 21 or later
- **Platform**: Windows, Linux, macOS

## Troubleshooting

### Extension Not Loading
- Verify Ghidra version compatibility (11.2+)
- Check that Java 21+ is installed
- Ensure extension.properties file is present in ZIP
- Try manual installation method

### BPUN Files Not Recognized
- Verify file contains '!' delimiter character
- Check that file has valid section headers after delimiter
- Ensure file is not corrupted or truncated

### Language Not Available
- Confirm extension is properly installed and enabled
- Restart Ghidra after installation
- Check Ghidra application log for errors

## Support and Documentation

### Related Documentation
- **ND-100 Architecture**: Norsk Data technical manuals
- **BPUN Format**: ND-100 system programming guides
- **Ghidra Extensions**: Official Ghidra documentation

### Source Code
This extension is generated from the NDGen project, which provides a comprehensive framework for ND-100 tool generation from YAML specifications.

## Version Information

- **Extension Version**: 1.0.0
- **Target Ghidra**: 12.0.4+
- **Language Version**: 1.0
- **Build Date**: Generated automatically

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

---

**Note**: This extension provides reverse engineering capabilities for educational and research purposes. Ensure compliance with applicable laws and regulations when analyzing software.