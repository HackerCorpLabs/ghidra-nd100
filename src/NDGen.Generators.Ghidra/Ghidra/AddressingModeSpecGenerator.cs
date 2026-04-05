using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NDGen.Core;
using NDGen.Core.Models;
using NDGen.Core.Utils;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates Ghidra processor specifications for addressing modes
    /// </summary>
    public class AddressingModeSpecGenerator
    {
        private readonly CpuDefinition _cpu;
        private readonly string _outputPath;

        public AddressingModeSpecGenerator(string outputPath, DefinitionLoader loader)
        {
            _outputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            _cpu = loader?.GetCpuDefinition() ?? throw new ArgumentNullException(nameof(loader));
        }

        /// <summary>
        /// Generates the Ghidra SLEIGH specification sections for addressing modes
        /// </summary>
        public void GenerateAddressingModesSpec(StringBuilder sleighSpec)
        {
            // Find the addressing_modes operand type
            var addressingModeType = _cpu.Metadata.OperandTypes
                .FirstOrDefault(ot => ot.Type == "addressing_mode");
                
            if (addressingModeType == null || addressingModeType.Subfields == null)
                return;
                
            // Generate bitfield definitions for the addressing mode subfields
            sleighSpec.AppendLine("\n# Addressing Mode Subfields");
            foreach (var subfield in addressingModeType.Subfields.OrderByDescending(sf => sf.Position))
            {
                sleighSpec.AppendLine($"define token addr_mode_field (");
                sleighSpec.AppendLine($"    {subfield.Name}:{subfield.Position}");
                sleighSpec.AppendLine($");");
                
                // Add documentation comment
                sleighSpec.AppendLine($"# {subfield.Name}: {subfield.Description}");
                if (!string.IsNullOrEmpty(subfield.EffectWhenSet))
                {
                    sleighSpec.AppendLine($"# When set: {subfield.EffectWhenSet}");
                }
                sleighSpec.AppendLine();
            }
            
            // Generate addressing mode constructors
            sleighSpec.AppendLine("\n# Addressing Mode Constructors");
            
            // Define the general addressing mode constructor
            sleighSpec.AppendLine("define pcodeop get_effective_address;");
            
            // Generate constructors for each addressing mode value
            if (addressingModeType.Values != null)
            {
                foreach (var mode in addressingModeType.Values)
                {
                    // Parse the bit pattern if available
                    int? x = null, i = null, b = null;
                    
                    if (mode.Fields != null)
                    {
                        // Extract X, I, B values from fields
                        foreach (var field in mode.Fields)
                        {
                            if (field.TryGetValue("X", out var xValue) && xValue != null)
                                x = Convert.ToInt32(xValue);
                            if (field.TryGetValue("I", out var iValue) && iValue != null)
                                i = Convert.ToInt32(iValue);
                            if (field.TryGetValue("B", out var bValue) && bValue != null)
                                b = Convert.ToInt32(bValue);
                        }
                    }
                    
                    // Define the constructor only if we have all field values
                    if (x.HasValue && i.HasValue && b.HasValue)
                    {
                        var xStr = x.Value == 1 ? "1" : "0";
                        var iStr = i.Value == 1 ? "1" : "0";
                        var bStr = b.Value == 1 ? "1" : "0";
                        
                        sleighSpec.AppendLine($"# {mode.Mode} ({mode.BitPattern})");
                        sleighSpec.AppendLine($"# {mode.Description}");
                        
                        // Define the constructor with pattern matching
                        sleighSpec.AppendLine($":addr_mode_{mode.Name} X={xStr} & I={iStr} & B={bStr} disp is X={xStr}; I={iStr}; B={bStr}; disp" + " {");
                        
                        // Generate pcode based on the effective address calculation
                        if (!string.IsNullOrEmpty(mode.EffectiveAddress))
                        {
                            sleighSpec.AppendLine($"    # Effective Address: {mode.EffectiveAddress}");
                            
                            // Generate appropriate pcode based on the addressing mode
                            string pcodeExpr = "";
                            
                            if (b.Value == 1)
                                pcodeExpr += "B + ";
                            else
                                pcodeExpr += "P + ";
                            
                            pcodeExpr += "disp";
                            
                            if (i.Value == 1)
                                pcodeExpr = $"*({pcodeExpr})";
                            
                            if (x.Value == 1)
                                pcodeExpr += " + X";
                                
                            sleighSpec.AppendLine($"    local result = {pcodeExpr};");
                            sleighSpec.AppendLine("    export result;");
                        }
                        
                        sleighSpec.AppendLine("}");
                        sleighSpec.AppendLine();
                    }
                }
            }
            
            // Generate the main addressing mode constructor
            sleighSpec.AppendLine("# Main Addressing Mode Constructor");
            sleighSpec.AppendLine(":addr_mode is addr_mode_prelative |");
            sleighSpec.AppendLine("            addr_mode_brelative |");
            sleighSpec.AppendLine("            addr_mode_indirect_prelative |");
            sleighSpec.AppendLine("            addr_mode_indirect_brelative |");
            sleighSpec.AppendLine("            addr_mode_xrelative |");
            sleighSpec.AppendLine("            addr_mode_brelative_indexed |");
            sleighSpec.AppendLine("            addr_mode_indirect_prelative_indexed |");
            sleighSpec.AppendLine("            addr_mode_indirect_brelative_indexed");
            sleighSpec.AppendLine("{");
            sleighSpec.AppendLine("    # General addressing mode constructor");
            sleighSpec.AppendLine("    export addr_mode;");
            sleighSpec.AppendLine("}");
        }

        /// <summary>
        /// Generates the Ghidra processor specification (pspec) file
        /// </summary>
        public void GenerateProgrammerModelSpec(StringBuilder pspecBuilder)
        {
            // Find the addressing_modes operand type
            var addressingModeType = _cpu.Metadata.OperandTypes
                .FirstOrDefault(ot => ot.Type == "addressing_mode");
                
            if (addressingModeType?.Subfields == null)
                return;
                
            pspecBuilder.AppendLine("    <!-- Addressing Mode Bit Fields -->");
            
            foreach (var subfield in addressingModeType.Subfields.OrderByDescending(sf => sf.Position))
            {
                pspecBuilder.AppendLine($"    <bitfield name=\"{subfield.Name}\" position=\"{subfield.Position}\" size=\"{subfield.BitSize}\">");
                pspecBuilder.AppendLine($"      <description>{subfield.Description}</description>");
                pspecBuilder.AppendLine("    </bitfield>");
            }
        }

        /// <summary>
        /// Generates detailed C++ Analyzer code for handling addressing modes in Ghidra
        /// </summary>
        public void GenerateAnalyzerCode()
        {
            var outputDir = Path.Combine(_outputPath, "ghidra", "src", "analyzer");
            Directory.CreateDirectory(outputDir);
            
            // Find the addressing_modes operand type
            var addressingModeType = _cpu.Metadata.OperandTypes
                .FirstOrDefault(ot => ot.Type == "addressing_mode");
                
            if (addressingModeType?.Subfields == null)
                return;
                
            var cppCode = new StringBuilder();
            
            // Generate the header
            cppCode.AppendLine("/**");
            cppCode.AppendLine(" * Auto-generated addressing mode analyzer for ND-100");
            cppCode.AppendLine(" */");
            cppCode.AppendLine("#include \"ghidra_include.h\"");
            cppCode.AppendLine("#include \"nd100_addressing.h\"");
            cppCode.AppendLine();
            
            // Generate the addressing mode analyzer class
            cppCode.AppendLine("namespace ghidra {");
            cppCode.AppendLine("namespace nd100 {");
            cppCode.AppendLine();
            
            // Generate the constructor
            cppCode.AppendLine("AddressingModeAnalyzer::AddressingModeAnalyzer(void)");
            cppCode.AppendLine("{");
            cppCode.AppendLine("    // Constructor initializes mode mappings");
            cppCode.AppendLine("}");
            cppCode.AppendLine();
            
            // Generate the analyze method
            cppCode.AppendLine("void AddressingModeAnalyzer::analyze(Address& addr, uint16_t instr, CodeUnit& code_unit)");
            cppCode.AppendLine("{");
            cppCode.AppendLine("    // Extract addressing mode bits from instruction");
            cppCode.AppendLine("    uint8_t mode = (instr >> 8) & 0x7;");
            cppCode.AppendLine("    uint8_t X = (mode >> 2) & 0x1;");
            cppCode.AppendLine("    uint8_t I = (mode >> 1) & 0x1;");
            cppCode.AppendLine("    uint8_t B = mode & 0x1;");
            cppCode.AppendLine();
            cppCode.AppendLine("    std::string modeStr;");
            cppCode.AppendLine();
            
            // Generate the switch statement for different modes
            cppCode.AppendLine("    switch (mode) {");
            
            if (addressingModeType.Values != null)
            {
                foreach (var mode in addressingModeType.Values.OrderBy(v => v.Value))
                {
                    cppCode.AppendLine($"    case {mode.Value}: // {mode.BitPattern}");
                    cppCode.AppendLine($"        modeStr = \"{mode.Mode}\";");
                    cppCode.AppendLine($"        // {mode.Description}");
                    cppCode.AppendLine($"        // Format: {mode.Format}");
                    cppCode.AppendLine($"        // Effective Address: {mode.EffectiveAddress}");
                    cppCode.AppendLine("        break;");
                }
            }
            
            cppCode.AppendLine("    default:");
            cppCode.AppendLine("        modeStr = \"Unknown Mode\";");
            cppCode.AppendLine("        break;");
            cppCode.AppendLine("    }");
            cppCode.AppendLine();
            
            // Add the mode as a comment in Ghidra
            cppCode.AppendLine("    // Add mode information as pre-comment to instruction");
            cppCode.AppendLine("    code_unit.setComment(CodeUnit::PRE_COMMENT, \"Addressing Mode: \" + modeStr);");
            cppCode.AppendLine("}");
            cppCode.AppendLine();
            
            // Close namespaces
            cppCode.AppendLine("} // namespace nd100");
            cppCode.AppendLine("} // namespace ghidra");
            
            // Write the C++ file
            File.WriteAllText(Path.Combine(outputDir, "nd100_addressing_analyzer.cpp"), cppCode.ToString());
            
            // Generate the header file
            var headerCode = new StringBuilder();
            
            headerCode.AppendLine("/**");
            headerCode.AppendLine(" * Auto-generated addressing mode analyzer header for ND-100");
            headerCode.AppendLine(" */");
            headerCode.AppendLine("#ifndef ND_100_ADDRESSING_ANALYZER_H");
            headerCode.AppendLine("#define ND_100_ADDRESSING_ANALYZER_H");
            headerCode.AppendLine();
            headerCode.AppendLine("#include <cstdint>");
            headerCode.AppendLine("#include <string>");
            headerCode.AppendLine("#include \"address.h\"");
            headerCode.AppendLine("#include \"codeunit.h\"");
            headerCode.AppendLine();
            
            headerCode.AppendLine("namespace ghidra {");
            headerCode.AppendLine("namespace nd100 {");
            headerCode.AppendLine();
            
            headerCode.AppendLine("/**");
            headerCode.AppendLine(" * Analyzer for ND-100 addressing modes");
            headerCode.AppendLine(" * Handles the 3-bit X,I,B addressing mode field");
            headerCode.AppendLine(" */");
            headerCode.AppendLine("class AddressingModeAnalyzer {");
            headerCode.AppendLine("public:");
            headerCode.AppendLine("    AddressingModeAnalyzer(void);");
            headerCode.AppendLine("    void analyze(Address& addr, uint16_t instr, CodeUnit& code_unit);");
            headerCode.AppendLine("};");
            headerCode.AppendLine();
            
            headerCode.AppendLine("} // namespace nd100");
            headerCode.AppendLine("} // namespace ghidra");
            headerCode.AppendLine();
            
            headerCode.AppendLine("#endif // ND_100_ADDRESSING_ANALYZER_H");
            
            // Write the header file
            File.WriteAllText(Path.Combine(outputDir, "nd100_addressing_analyzer.h"), headerCode.ToString());
        }
    }
}