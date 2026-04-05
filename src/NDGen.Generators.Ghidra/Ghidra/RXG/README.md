# Ghidra RXG Schema Files

These RXG (RelaxNG) schema files are used for validating Ghidra processor specifications.

## Source
Original files are from the Ghidra repository:
https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Framework/SoftwareModeling/data/languages

## Files
- `compiler_spec.rxg`: Compiler specification schema
- `processor_spec.rxg`: Processor specification schema
- `language_definitions.rxg`: Language definitions schema
- `language_common.rxg`: Common language elements schema

## Updating
To update these schema files:
1. Visit the Ghidra repository link above
2. Download the latest versions of the RXG files
3. Replace the files in this directory
4. Test your processor specifications against the new schemas

Note: These files are kept locally to avoid network dependencies during validation. 