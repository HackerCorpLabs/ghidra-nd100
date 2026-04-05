using System;
using System.IO;
using System.Text;
using NDGen.Core.Models;

namespace NDGen.Generators.Ghidra.PCodes
{
    public class PCodeGenerator
    {
        private readonly StringBuilder _builder;
        private readonly string _templatesPath;

        public PCodeGenerator(string baseDirectory)
        {
            _builder = new StringBuilder();
            _templatesPath = Path.Combine(baseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "p-codes");
        }

        public string Generate(InstructionDefinition inst)
        {
            _builder.Clear();

            // First try to load P-code from template file
            string templatePath = Path.Combine(_templatesPath, $"{inst.Name}.sinc");
            if (File.Exists(templatePath))
            {
                return LoadPCodeFromTemplate(templatePath);
            }

            // Fallback to hardcoded P-code for specific instructions
            switch (inst.Name)
            {
                case "IOX":
                case "IOXT":
                    GenerateIOTransferPCode(inst);
                    break;
                default:
                    GenerateDefaultPCode(inst);
                    break;
            }

            return _builder.ToString();
        }

        private string LoadPCodeFromTemplate(string templatePath)
        {
            try 
            {
                string content = File.ReadAllText(templatePath);
                // Extract just the P-code body (everything inside the braces)
                int startIndex = content.IndexOf('{');
                int endIndex = content.LastIndexOf('}');
                if (startIndex >= 0 && endIndex > startIndex)
                {
                    return content.Substring(startIndex + 1, endIndex - startIndex - 1).Trim();
                }
                return content;
            }
            catch
            {
                return $"    # Error loading P-code template from {templatePath}";
            }
        }

        private void GenerateIOTransferPCode(InstructionDefinition inst)
        {
            if (inst.Name == "IOX")
            {
                _builder.AppendLine("    local addr = DEVICE;");
                _builder.AppendLine("    local is_output = addr & 1;");
                _builder.AppendLine("    if (is_output) goto <o>;");
                _builder.AppendLine("    A = io[addr];");
                _builder.AppendLine("    goto <done>;");
                _builder.AppendLine("<o>");
                _builder.AppendLine("    io[addr] = A;");
                _builder.AppendLine("<done>");
            }
            else if (inst.Name == "IOXT")
            {
                _builder.AppendLine("    local addr = T;");
                _builder.AppendLine("    local is_output = addr & 1;");
                _builder.AppendLine("    if (is_output) goto <o>;");
                _builder.AppendLine("    A = io[addr];");
                _builder.AppendLine("    goto <done>;");
                _builder.AppendLine("<o>");
                _builder.AppendLine("    io[addr] = A;");
                _builder.AppendLine("<done>");
            }
        }

        private void GenerateDefaultPCode(InstructionDefinition inst)
        {
            // Generate basic P-code based on instruction name and operands
            _builder.AppendLine($"    # {inst.Name} instruction");
            if (inst.Operands != null)
            {
                foreach (var operand in inst.Operands)
                {
                    _builder.AppendLine($"    # Uses operand {operand.Name}: {operand.Description}");
                }
            }
        }
    }
} 