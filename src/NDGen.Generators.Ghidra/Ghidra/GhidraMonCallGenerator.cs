using System;
using System.IO;
using System.Text;
using System.Text.Json;
using NDGen.Core.Models;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates MON call annotations for Ghidra from specs/mon-calls.json.
    /// Produces ND100MonCallAnalyzer.java with a static lookup table of all
    /// 231 SINTRAN III monitor call names.
    /// </summary>
    public sealed class GhidraMonCallGenerator
    {
        private readonly string _baseDirectory;
        private readonly string _outputDirectory;

        public GhidraMonCallGenerator(string baseDirectory, string outputDirectory)
        {
            _baseDirectory = baseDirectory ?? throw new ArgumentNullException(nameof(baseDirectory));
            _outputDirectory = outputDirectory ?? throw new ArgumentNullException(nameof(outputDirectory));
        }

        public void Generate()
        {
            MonCallSpec spec = LoadMonCallSpec();
            GenerateJavaAnalyzer(spec);
        }

        private MonCallSpec LoadMonCallSpec()
        {
            string jsonPath = Path.Combine(_baseDirectory, "nd100-definitions", "specs", "mon-calls.json");
            string json = File.ReadAllText(jsonPath);
            return JsonSerializer.Deserialize<MonCallSpec>(json)
                ?? throw new InvalidOperationException("Failed to deserialize mon-calls.json");
        }

        private void GenerateJavaAnalyzer(MonCallSpec spec)
        {
            string templatePath = Path.Combine(_baseDirectory, "src", "NDGen.Generators.Ghidra",
                "Ghidra", "Templates", "ND100MonCallAnalyzer.java.template");
            string template = File.ReadAllText(templatePath);

            string table = GenerateMonCallTable(spec);

            string output = template.Replace("// {{MON_CALL_TABLE}}", table);

            string javaOutputPath = Path.Combine(_baseDirectory, "src", "NDGen.Generators.Ghidra",
                "Ghidra", "ND-100", "src", "main", "java", "nd", "bpun", "ND100MonCallAnalyzer.java");

            Directory.CreateDirectory(Path.GetDirectoryName(javaOutputPath)!);
            File.WriteAllText(javaOutputPath, output);
        }

        private static string GenerateMonCallTable(MonCallSpec spec)
        {
            // Find max decimal value to size the array
            int maxDecimal = 0;
            var calls = spec.MonCalls;
            for (int i = 0; i < calls.Count; i++)
            {
                if (calls[i].Decimal > maxDecimal)
                    maxDecimal = calls[i].Decimal;
            }

            int arraySize = maxDecimal + 1;
            var sb = new StringBuilder();

            sb.Append("\t// MON call lookup table — auto-generated from specs/mon-calls.json\n");
            sb.Append("\t// Index = decimal MON call number, value = \"Name (octalB)\"\n");
            sb.Append("\tprivate static final String[] MON_NAMES = new String[");
            sb.Append(arraySize);
            sb.Append("];\n");
            sb.Append("\tstatic {\n");

            for (int i = 0; i < calls.Count; i++)
            {
                MonCallDefinition call = calls[i];
                sb.Append("\t\tMON_NAMES[");
                sb.Append(call.Decimal);
                sb.Append("] = \"");
                sb.Append(EscapeJava(call.Name));
                if (!string.IsNullOrEmpty(call.ShortName))
                {
                    sb.Append(" / ");
                    sb.Append(EscapeJava(call.ShortName));
                }
                sb.Append(" (");
                sb.Append(EscapeJava(call.Octal));
                sb.Append(")\";");

                // Add brief description as Java comment
                if (!string.IsNullOrEmpty(call.Description))
                {
                    sb.Append(" // ");
                    // Truncate long descriptions for readability
                    string desc = call.Description;
                    if (desc.Length > 60)
                        desc = desc.Substring(0, 57) + "...";
                    sb.Append(EscapeJava(desc));
                }

                sb.Append('\n');
            }

            sb.Append("\t}");

            return sb.ToString();
        }

        private static string EscapeJava(string s)
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
                    case '\n': sb.Append("\\n"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
