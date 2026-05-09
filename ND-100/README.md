# ND-100 Ghidra Extension

Ghidra processor module for the Norsk Data **ND-100** 16-bit minicomputer.

## Overview

This extension adds full ND-100 processor support to Ghidra, including:

- **SLEIGH language specification** — disassembly support for all 153 ND-100 instructions
- **Three file format loaders** — BPUN, TPE :TEST/:NEXT, and :PROG (SINTRAN III executable)
- **Analyzers** — I/O instruction labeling, MON call analysis, dispatch tables, indirect references, stack frames

## Features

### Instruction set

- 153 instructions covering core, floating-point, bit, byte, and decimal classes
- Direct, indirect, indexed, and immediate addressing modes
- Privileged operations, I/O, interrupt handling

### File format loaders

| Loader | Class | Format |
|---|---|---|
| `ND-100 BPUN (Bootable Punched Tape)` | `BPUNLoader` | Boot tapes — 7-bit ASCII preamble + binary load sections, terminated by `!` |
| `ND-100 TPE Test Program (:TEST/:NEXT)` | `TPETestLoader` | Hardware diagnostic test programs with TPE runtime at `0x0088-0x00C5` |
| `ND-100 :PROG (SINTRAN-III Executable)` | `ProgLoader` | Standard SINTRAN III executable: 256-word header at offset 0, optional second header/bank at `0x20000` |

All loaders auto-register the `ND-100:BE:16:default` language and create entry points for the relevant start/boot/restart addresses.

### Analyzers

- `ND100IOInstructionAnalyzer` — labels device I/O register references at IOX/IOXT instructions
- `ND100MonCallAnalyzer` — annotates SINTRAN MON system call invocations
- `ND100DispatchTableAnalyzer` — recovers dispatch table layouts from indirect jumps
- `ND100IndirectRefAnalyzer` — resolves indirect address references
- `ND100StackFrameAnalyzer` — reconstructs stack frame layouts
- `ND100IOAnalyzer` — broader I/O reference cleanup

## Installation

1. Open Ghidra and pick **File → Install Extensions…**
2. Click the **+** button (top right)
3. Select the `ghidra_<version>_PUBLIC_<date>_ND-100.zip` archive from this build
4. Restart Ghidra when prompted

To install manually, extract the zip into either:

- **User extensions:** `<ghidra user settings>/Extensions/`
- **System extensions:** `<GHIDRA_INSTALL_DIR>/Ghidra/Extensions/`

## Usage

### Importing a binary

1. **File → Import File…** in Ghidra (or drag-and-drop into the project view)
2. Ghidra auto-detects BPUN, TPE, and PROG files via their loader probes; you can also pick the loader manually
3. The `ND-100:BE:16:default` language is selected automatically
4. After import, entry points (`START`, `BOOT`, `RESTART`) are pre-labeled and disassembly is run from them

### File formats at a glance

#### BPUN

7-bit ASCII bootstrap preamble (octal digit strings, `/` and CR delimiters) followed by `!` and one or more binary load sections:

```
[address(2)] [count(2)] [data(count*2)] [checksum(2)] [action(2)]
```

Supports the FloMon variant (address=count=checksum=0 → switches to `00 hi 00 lo 00` byte format).

#### TPE :TEST / :NEXT

Hardware diagnostic test programs. The first 136 words are a header containing the program name, the entry list, and command table pointer at virtual address `0x6C00`. The first 120 words (`0x0000-0x0077`) are a TPE runtime library, identical across every test file.

#### :PROG (SINTRAN III)

```
0x00000  Header 1     (256 words / 512 bytes)
0x00200  Bank 1 image — (Last1 - First1 + 1) words, loaded at virtual First1
0x20000  Header 2     (256 words, optional — only for 2-bank programs)
0x20200  Bank 2 image — loaded at virtual First2 in the alternate page table
```

The 12-byte header is six big-endian 16-bit words: `Start`, `Restart`, `First1`, `Last1`, `First2`, `Last2`. A 1-bank program is signaled by `First2=0xFFFF, Last2=0x0000`. The loader creates `BANK1` in the default address space and `BANK2` as a Ghidra overlay (real hardware reaches it via the alternate page table after `MON ALTON`).

## Architecture

| | |
|---|---|
| Word size | 16 bits |
| Endianness | Big |
| Address space | 64K words (word-addressed; Ghidra default space wordSize=2) |
| Banks | 2 × 64Kw via normal/alternate page tables |
| Levels | 16 program levels (PIL-driven priorities) |

## Compatibility

- **Ghidra:** 11.2 or later (built against 12.0.4)
- **Java:** JDK 21 or later

## Troubleshooting

- **Extension not loading** — verify Ghidra version (11.2+) and Java 21+; check Ghidra application log
- **File not auto-detected** — pick the loader manually in the import dialog; verify the file isn't truncated
- **PROG file rejected** — the probe checks `First1 ≤ Last1` and that the file holds at least the declared bank-1 payload; corrupted or partial files won't be accepted
- **Wrong language picked** — explicitly select `ND-100:BE:16:default`

## See also

- **Source repo:** [HackerCorpLabs/ghidra-nd100](https://github.com/HackerCorpLabs/ghidra-nd100)
- **Instruction definitions:** [HackerCorpLabs/nd100-definitions](https://github.com/HackerCorpLabs/nd100-definitions) — YAML CPU spec consumed by the C# generator
- **Norsk Data manuals** for ND-100 architecture and SINTRAN III internals

## License

Apache License 2.0 — see `LICENSE` in the repository root.
