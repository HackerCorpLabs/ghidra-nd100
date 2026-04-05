using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using NDGen.Core.Models;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates I/O device annotations for Ghidra from specs/io-devices.json.
    /// Produces:
    /// 1. ND100IOAnalyzer.java - Ghidra analyzer with plate comments and labels
    /// 2. Pspec default_symbols XML block for I/O device registers
    /// </summary>
    public sealed class GhidraIODeviceGenerator
    {
        private readonly string _baseDirectory;
        private readonly string _outputDirectory;
        private IODeviceSpec? _spec;

        public GhidraIODeviceGenerator(string baseDirectory, string outputDirectory)
        {
            _baseDirectory = baseDirectory ?? throw new ArgumentNullException(nameof(baseDirectory));
            _outputDirectory = outputDirectory ?? throw new ArgumentNullException(nameof(outputDirectory));
        }

        public void Generate()
        {
            _spec = LoadDeviceSpec();
            GenerateJavaAnalyzer();
        }

        /// <summary>
        /// Generates the pspec default_symbols XML block for I/O devices.
        /// Called by GhidraSleighGenerator when processing the pspec template.
        /// </summary>
        public string GeneratePspecSymbols()
        {
            if (_spec == null)
                _spec = LoadDeviceSpec();

            var sb = new StringBuilder();
            sb.AppendLine("    <!-- I/O Device Registers (io_space)               -->");
            sb.AppendLine("    <!-- io_space is word-addressed (wordsize=2)        -->");
            sb.AppendLine("    <!-- AUTO-GENERATED from specs/io-devices.json      -->");

            List<IODeviceInstance> instances = _spec.DeviceInstances;
            for (int i = 0; i < instances.Count; i++)
            {
                IODeviceInstance inst = instances[i];
                if (!_spec.DeviceTypes.TryGetValue(inst.Type, out IODeviceType? deviceType))
                    continue;

                int baseAddr = ParseHexAddress(inst.BaseAddressHex);
                sb.AppendLine();
                sb.Append("    <!-- ");
                sb.Append(deviceType.Description);
                sb.Append(' ');
                sb.Append(inst.Unit);
                sb.Append(" (octal ");
                sb.Append(inst.OctalRange);
                sb.Append(", level ");
                sb.Append(inst.IrqLevel);
                sb.Append(", ident ");
                sb.Append(inst.IdentOctal);
                sb.AppendLine(") -->");

                List<IORegisterDefinition> regs = deviceType.Registers;
                for (int r = 0; r < regs.Count; r++)
                {
                    IORegisterDefinition reg = regs[r];
                    int addr = baseAddr + reg.Offset;
                    sb.Append("    <symbol name=\"");
                    sb.Append(inst.Prefix);
                    sb.Append('_');
                    sb.Append(reg.LabelSuffix);
                    sb.Append("\" address=\"io_space:0x");
                    sb.Append(addr.ToString("X"));
                    sb.AppendLine("\"/>");
                }
            }

            return sb.ToString();
        }

        private IODeviceSpec LoadDeviceSpec()
        {
            string jsonPath = Path.Combine(_baseDirectory, "nd100-definitions", "specs", "io-devices.json");
            string json = File.ReadAllText(jsonPath);
            return JsonSerializer.Deserialize<IODeviceSpec>(json)
                ?? throw new InvalidOperationException("Failed to deserialize io-devices.json");
        }

        private void GenerateJavaAnalyzer()
        {
            string templatePath = Path.Combine(_baseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "ND100IOAnalyzer.java.template");
            string template = File.ReadAllText(templatePath);

            string deviceCalls = GenerateDeviceCalls();
            string deviceMethods = GenerateDeviceMethods();

            string output = template
                .Replace("// {{DEVICE_ANNOTATION_CALLS}}", deviceCalls)
                .Replace("// {{DEVICE_ANNOTATION_METHODS}}", deviceMethods);

            string javaOutputPath = Path.Combine(_baseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "ND-100",
                "src", "main", "java", "nd", "bpun", "ND100IOAnalyzer.java");

            Directory.CreateDirectory(Path.GetDirectoryName(javaOutputPath)!);
            File.WriteAllText(javaOutputPath, output);
        }

        private string GenerateDeviceCalls()
        {
            var sb = new StringBuilder();
            List<IODeviceInstance> instances = _spec!.DeviceInstances;

            for (int i = 0; i < instances.Count; i++)
            {
                IODeviceInstance inst = instances[i];
                if (!_spec.DeviceTypes.TryGetValue(inst.Type, out IODeviceType? deviceType))
                    continue;

                sb.Append("\t\t// ");
                sb.Append(deviceType.Description);
                sb.Append(' ');
                sb.Append(inst.Unit);
                sb.Append(" (octal ");
                sb.Append(inst.OctalRange);
                sb.AppendLine(")");

                sb.Append("\t\tcount += annotateDevice(listing, ioSpace, ");
                sb.Append(inst.BaseAddressHex);
                sb.Append(", \"");
                sb.Append(inst.Prefix);
                sb.Append("\", \"");
                sb.Append(EscapeJavaString(deviceType.Description));
                sb.Append("\", \"");
                sb.Append(EscapeJavaString(inst.Unit));
                sb.Append("\", \"");
                sb.Append(inst.OctalRange);
                sb.Append("\", \"");
                sb.Append(inst.IrqLevel);
                sb.Append("\", \"");
                sb.Append(inst.IdentOctal);
                sb.Append("\", \"");
                sb.Append(inst.Type);
                sb.AppendLine("\");");

                if (i < instances.Count - 1)
                    sb.AppendLine();
            }

            return sb.ToString();
        }

        private string GenerateDeviceMethods()
        {
            // Generate a single generic annotateDevice method that uses a switch on device type
            // to format the plate comments per register
            var sb = new StringBuilder();

            // Build the register data as static arrays in the Java code
            sb.AppendLine("\t// =========================================================================");
            sb.AppendLine("\t// Device register definitions - generated from specs/io-devices.json");
            sb.AppendLine("\t// =========================================================================");
            sb.AppendLine();
            sb.AppendLine("\tprivate int annotateDevice(Listing listing, AddressSpace io, int base,");
            sb.AppendLine("\t\t\tString prefix, String deviceDesc, String unit, String octalRange,");
            sb.AppendLine("\t\t\tString level, String ident, String deviceType) {");
            sb.AppendLine();
            sb.AppendLine("\t\tString hdr = deviceDesc + \" \" + unit + \" (octal \" + octalRange +");
            sb.AppendLine("\t\t\t\", level \" + level + \", ident \" + ident + \")\";");
            sb.AppendLine();
            sb.AppendLine("\t\tswitch (deviceType) {");

            Dictionary<string, IODeviceType> types = _spec!.DeviceTypes;
            // Use sorted keys for deterministic output
            var typeKeys = new List<string>(types.Keys);
            typeKeys.Sort(StringComparer.Ordinal);

            for (int t = 0; t < typeKeys.Count; t++)
            {
                string typeName = typeKeys[t];
                IODeviceType deviceType = types[typeName];

                sb.Append("\t\t\tcase \"");
                sb.Append(typeName);
                sb.AppendLine("\":");

                List<IORegisterDefinition> regs = deviceType.Registers;
                for (int r = 0; r < regs.Count; r++)
                {
                    IORegisterDefinition reg = regs[r];
                    sb.Append("\t\t\t\tsetPlate(listing, io, base + ");
                    sb.Append(reg.Offset);
                    sb.Append(", prefix + \"_");
                    sb.Append(reg.LabelSuffix);
                    sb.Append("\", hdr + \"\\n\" +");
                    sb.AppendLine();

                    // Register name line
                    sb.Append("\t\t\t\t\tprefix + \" ");
                    sb.Append(EscapeJavaString(reg.Name));
                    sb.Append("\\n\" +");
                    sb.AppendLine();

                    // Direction line
                    if (reg.Direction != "None")
                    {
                        sb.Append("\t\t\t\t\t\"Direction: ");
                        sb.Append(EscapeJavaString(reg.Direction));
                        sb.Append("\\n\"");
                    }
                    else
                    {
                        sb.Append("\t\t\t\t\t\"\"");
                    }

                    // Description text (before bit fields)
                    if (!string.IsNullOrEmpty(reg.Description))
                    {
                        string[] descLines = reg.Description.Split('\n');
                        for (int d = 0; d < descLines.Length; d++)
                        {
                            sb.Append(" +");
                            sb.AppendLine();
                            sb.Append("\t\t\t\t\t\"");
                            sb.Append(EscapeJavaString(descLines[d]));
                            sb.Append("\\n\"");
                        }
                    }

                    // Bit fields
                    if (reg.BitFields != null)
                    {
                        for (int b = 0; b < reg.BitFields.Count; b++)
                        {
                            IOBitField bf = reg.BitFields[b];
                            sb.Append(" +");
                            sb.AppendLine();
                            sb.Append("\t\t\t\t\t\"");

                            // Format: single bit = "Bit  N:", range = "Bits N-M:"
                            if (bf.Bits.Contains('-'))
                            {
                                sb.Append("Bits ");
                                sb.Append(bf.Bits);
                            }
                            else
                            {
                                int bitNum = int.Parse(bf.Bits);
                                if (bitNum < 10)
                                    sb.Append("Bit  ");
                                else
                                    sb.Append("Bit ");
                                sb.Append(bf.Bits);
                            }
                            sb.Append(": ");
                            sb.Append(EscapeJavaString(bf.Name));
                            sb.Append("\\n\"");
                        }
                    }

                    sb.AppendLine(");");
                    sb.AppendLine();
                }

                sb.Append("\t\t\t\treturn ");
                sb.Append(deviceType.RegisterCount);
                sb.AppendLine(";");
            }

            sb.AppendLine("\t\t\tdefault:");
            sb.AppendLine("\t\t\t\treturn 0;");
            sb.AppendLine("\t\t}");
            sb.AppendLine("\t}");

            return sb.ToString();
        }

        private static string EscapeJavaString(string s)
        {
            if (string.IsNullOrEmpty(s))
                return s;

            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        private static int ParseHexAddress(string hex)
        {
            ReadOnlySpan<char> span = hex.AsSpan();
            if (span.StartsWith("0x") || span.StartsWith("0X"))
                span = span.Slice(2);
            return int.Parse(span, System.Globalization.NumberStyles.HexNumber);
        }
    }
}
