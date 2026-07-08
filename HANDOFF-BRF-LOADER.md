# Handoff: BRF Loader for the ND-100 Ghidra Extension

Date: 2026-07-08
Scope: adding ND-100 **BRF (Binary Relocatable Format)** import support to the
Ghidra extension, alongside the existing BPUN and :PROG loaders.

---

## What was done

### New file
- `E:\Dev\Ronny\ghidra-nd100\ND-100\src\main\java\nd\bpun\BRFLoader.java`
  — complete, compiles clean (`gradlew.bat compileJava` — only the same
  deprecation warnings the other loaders produce).

### What the loader does
It is a full **emulated ND Relocating Loader** (ND-60.066.04 chapter 2):

- Parses the byte stream of BRF groups; P-groups are big-endian 16-bit words.
- Every control number 0–054 implemented: LF/LR/LC loads, AFF/ARF/AFR/ARR
  fixups, SFL/AFL/SRL location control, MAIN/LIBR/ENTR/REF symbols, LNF fast
  load, RT, ASF/ADS + INC/DBC/RLC/CXC/BYC COMMON handling, BYL byte load,
  INL/DBL/RLL/CXL, DBG, PMO/DMO/LRP/LRD (logged, single-bank fallback),
  DIC dictionary (skipped/logged), INHB, EOF, and the undocumented **ctrl 30**
  PLANC id stamp (decoded as ASCII, e.g. `PLANC-1BANK-G00`).
- **LONGF is per-unit**: every BEG resets S-groups to 4 bytes (matches the
  validated spec in `E:\Dev\Ronny\NDInsight\SINTRAN\File-Formats\BRF-FILE-FORMAT.md`).
- Per-unit checksum verified; mismatches logged and flagged in comments.
- Six-bit symbol decoding (ASCII − 040, right-justified, space-padded,
  MSB-first packing; 5 chars in 4-byte S-groups, up to 8 in 6-byte).
- Loads ALL units consecutively from base 0 (library units too — deliberate
  for static RE), resolves REF chains, patches every reference word with the
  final symbol value; unresolved externals stay `0177777` and are reported.
- COMMON allocated downward from 0177777 (1-bank rule, section 2.6).
- Emits one Ghidra memory block per contiguous run of defined words
  (`BRF_%06o`), entry point = value of the MAIN symbol (label `START`),
  auto-disassembles from the entry.

### Metadata comments (per Ronny's request)
- **File header plate comment** at the entry: file name/size, unit count
  (LONGF/short/library split), symbols defined/unresolved (with names),
  entry, MAIN symbol, COMMON range, checksum totals, warnings.
- **Per-unit plate comment** at each unit's PB: unit number, file offset, PB,
  end CLC, word count, S-group size, stored vs computed checksum, RT
  priority, INHB flag, MAIN/LIBR/ENTR symbol lists, ctrl-30 ID stamp.
- **EOL comment on every REF word**: `BRF REF <sym> -> 0<addr>` or
  `BRF REF <sym> (UNRESOLVED, left 0177777)`.
- **Pre-comment at every definition**: `BRF ENTR <sym> = 0<addr> (defined in
  unit N, K references)` / `BRF COMMON block <sym>: N words at 0<addr>`.
- Comments append (never overwrite) via `appendComment()`.

---

## Facts established empirically (do not re-litigate)

1. **REF consumes one word at CLC.** The manual only says the symbol "is
   referenced in CLC" and never states whether CLC advances. Tested both
   interpretations against `encos-err-i-b01.brf`
   (script: scratchpad `ref_test.py`, session-local): with
   "REF stores its chain-link word at (CLC) and does CLC+1→CLC", **all 567
   AFR fixup targets** land inside the loaded part of their unit (only 3
   boundary cases, all exactly `W2 == CLC` with `W1 = W2+1` — forward fixups
   to the very next word). Without the advance, 98 fixups point past the end.
   Documented in the class javadoc.
2. Checksum: unit sums to 0 mod 2^16 including the checksum word (the stored
   word is the negation of the sum from BEG through the END byte). NOTE: the
   javadoc was updated (2026-07-08) to say two's complement with an
   ADV-EXIT.BRF example — the probe (`checkReadUnit`) still validates with
   `(sum + stored) & 0xFFFF == 0xFFFF` (one's complement). **If real files
   show two's complement (sum + stored == 0), the probe and the END handler
   in `interpret()` must be changed to match** — see "Open items" below.
3. P-groups are big-endian; six-bit code is ASCII − 040.

Test files: `E:\Dev\Ronny\NDInsight\Installation\Communication\Ethernet\x\encos-err-i-b01.brf`
and `encos-err-ii-b01.brf` (174 units each).
Primary manual: `E:\Dev\Ronny\NDInsight\Reference-Manuals\ND-60.066.04 ND Relocating Loader.md`
(NOT under SINTRAN\ — the spec doc's relative link is a different tree).

## Open items

1. **Checksum discrepancy to resolve (IMPORTANT).** The class javadoc now
   cites ADV-EXIT.BRF: `0x20EE + 0xDF12 = 0x0000` → **two's** complement.
   The encos files verified with **one's** complement (`sum+stored = 0xFFFF`)
   per the original validation. Both code sites use the one's-complement
   test:
   - `checkReadUnit()` (probe) — rejects the file if the first unit fails!
   - `C_END` case in `interpret()` — only logs/flags.
   If ADV-EXIT.BRF is a real ND file that sums to 0x0000, the probe will
   REJECT it. Safest fix: accept either (`s = (sum+stored)&0xFFFF; ok =
   s==0xFFFF || s==0`), and record which variant in the unit comment.
   Verify against both encos files AND ADV-EXIT.BRF before committing.
2. ~~End-to-end verification~~ — DONE: Ronny confirmed 2026-07-08 that BRF
   files import correctly in the Ghidra GUI.
3. Remove the test copy at
   `C:\Utils\Ghidra\ghidra_12.0.4_PUBLIC\Ghidra\Extensions\ND-100`
   once verification is finished (it was installed only for headless testing
   and collides with the user-dir extension if both exist under the same
   name).
4. Loader currently offers no user options (base address fixed at 0).
   Possible future: Ghidra loader option for load base and "skip library
   units".

## Verification status / how to verify

- Compile: `cd E:\Dev\Ronny\ghidra-nd100\ND-100; .\gradlew.bat compileJava` — PASSES.
- Extension build: `.\gradlew.bat buildExtension` — PASSES
  (`ND-100\dist\ghidra_12.0.4_PUBLIC_<date>_ND-100.zip`).
- Headless import test — **NOT yet green**. Attempts hit:
  1. `make install` fails in Git Bash: stale `JAVA_HOME`
     (`C:/Program Files/Eclipse Adoptium/jdk-21.0.6.7-hotspot/` invalid);
     `gradlew.bat` from PowerShell works.
  2. The running Ghidra GUI holds a lock on
     `%APPDATA%\ghidra\ghidra_12.0.4_PUBLIC\Extensions\ND-100\lib\ND-100.jar`,
     so the extension can't be replaced while Ghidra is open.
  3. Two copies named ND-100 (user dir + install dir) → headless aborts with
     "Multiple modules collided". Renaming the install-dir copy avoided the
     collision but then `-loader BRFLoader` was not found (loader class not
     registered — mechanism unclear, possibly extension-name dedupe).
  Recommended procedure: **close Ghidra**, run `make install` from a shell
  with a valid `JAVA_HOME` (or unzip `ND-100\dist\...zip` into
  `%APPDATA%\ghidra\ghidra_12.0.4_PUBLIC\Extensions\`), then:
  ```
  C:\Utils\Ghidra\ghidra_12.0.4_PUBLIC\support\analyzeHeadless.bat ^
    <scratch-dir> brftest -import <file>.brf -loader BRFLoader -noanalysis -deleteProject
  ```
  Expect in the log: block list `BRF_000000...`, "BRF: 174 units, N defined
  symbols, 0 checksum failures", one unresolved-externals line.

## Design notes

- Same package (`nd.bpun`) and code style as `BPUNLoader`/`ProgLoader`;
  registered automatically via Ghidra's classpath scan, language
  `ND-100:BE:16:default`, `SPECIALIZED_TARGET_LOADER`, tier priority 50.
- Probe (`findSupportedLoadSpecs`) is strict: skips FEED padding (max 4 KiB),
  requires BEG, then syntax-checks the ENTIRE first unit including checksum —
  false positives on non-BRF binaries are essentially impossible.
- ND-100 address space is word-addressed with `addressableUnitSize == 2`;
  every word address is multiplied by `wordSize` for Ghidra addresses (same
  pattern as the other two loaders).
