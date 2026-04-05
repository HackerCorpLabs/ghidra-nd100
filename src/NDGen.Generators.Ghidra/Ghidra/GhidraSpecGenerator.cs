using System;
using System.IO;
using System.Text;
using NDGen.Core;
using NDGen.Core.Models;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates XML specification files for the ND-100 processor module in Ghidra
    /// </summary>
    public class GhidraSpecGenerator : BaseGenerator
    {
        private readonly string _outputPath;
        private readonly DefinitionLoader _loader;

        public GhidraSpecGenerator(string outputPath, DefinitionLoader loader) : base(outputPath, loader)
        {
            _outputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            _loader = loader ?? throw new ArgumentNullException(nameof(loader));
        }

        public override void Generate()
        {
            GenerateLanguageDef();
            GenerateProcessorSpec();
            GenerateCompilerSpec();
            GenerateModuleManifest();
            GenerateBuildXml();
            GenerateSleighArgs();
            GenerateBpunLoader();
            GenerateExtensionProperties();
            GenerateExtensionBuildGradle();
        }

        private void EnsureDirectoryExists(string filePath)
        {
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        private void GenerateLanguageDef()
        {
            var cpu = _loader.GetCpuDefinition();
            var path = Path.Combine(_outputPath, "data", "languages", "nd100.ldefs");
            EnsureDirectoryExists(path);

            var content = new StringBuilder();
            content.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            content.AppendLine("<language_definitions>");
            content.AppendLine("  <language processor=\"ND-100\"");
            content.AppendLine("            endian=\"big\"");
            content.AppendLine("            size=\"16\"");
            content.AppendLine("            variant=\"default\"");
            content.AppendLine("            version=\"1.0\"");
            content.AppendLine("            slafile=\"nd100.sla\"");
            content.AppendLine("            processorspec=\"nd100.pspec\"");
            content.AppendLine("            id=\"ND-100:BE:16:default\">");
            content.AppendLine("    <description>ND-100 Processor Module</description>");
            content.AppendLine("    <compiler name=\"default\" spec=\"nd100.cspec\" id=\"default\"/>");
            content.AppendLine("  </language>");
            content.AppendLine("</language_definitions>");

            File.WriteAllText(path, content.ToString());
        }

        private void GenerateProcessorSpec()
        {
            var cpu = _loader.GetCpuDefinition();
            var path = Path.Combine(_outputPath, "data", "languages", "nd100.pspec");
            EnsureDirectoryExists(path);

            var content = new StringBuilder();
            content.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            content.AppendLine("<processor_spec>");
            content.AppendLine("  <programcounter register=\"P\"/>");
            content.AppendLine();
            content.AppendLine("  <default_memory_blocks>");
            content.AppendLine("    <memory_block name=\"io_space\" start_address=\"io_space:0x0000\" length=\"0x4000\" mode=\"rwv\" initialized=\"false\"/>");
            content.AppendLine("  </default_memory_blocks>");
            content.AppendLine("</processor_spec>");

            File.WriteAllText(path, content.ToString());
        }

        private void GenerateCompilerSpec()
        {
            var path = Path.Combine(_outputPath, "data", "languages", "nd100.cspec");
            EnsureDirectoryExists(path);

            var content = new StringBuilder();
            content.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            content.AppendLine("<compiler_spec>");
            content.AppendLine("  <data_organization>");
            content.AppendLine("    <absolute_max_alignment value=\"0\" />");
            content.AppendLine("    <machine_alignment value=\"2\" />");
            content.AppendLine("    <default_alignment value=\"1\" />");
            content.AppendLine("    <default_pointer_alignment value=\"2\" />");
            content.AppendLine("    <pointer_size value=\"2\" />");
            content.AppendLine("    <wchar_size value=\"2\" />");
            content.AppendLine("    <short_size value=\"2\" />");
            content.AppendLine("    <integer_size value=\"2\" />");
            content.AppendLine("    <long_size value=\"4\" />");
            content.AppendLine("    <long_long_size value=\"8\" />");
            content.AppendLine("    <float_size value=\"4\" />");
            content.AppendLine("    <double_size value=\"8\" />");
            content.AppendLine("    <long_double_size value=\"8\" />");
            content.AppendLine("    <size_alignment_map>");
            content.AppendLine("      <entry size=\"1\" alignment=\"1\" />");
            content.AppendLine("      <entry size=\"2\" alignment=\"2\" />");
            content.AppendLine("      <entry size=\"4\" alignment=\"2\" />");
            content.AppendLine("      <entry size=\"8\" alignment=\"2\" />");
            content.AppendLine("    </size_alignment_map>");
            content.AppendLine("  </data_organization>");
            content.AppendLine();
            content.AppendLine("  <global>");
            content.AppendLine("    <range space=\"ram\"/>");
            content.AppendLine("  </global>");
            content.AppendLine();
            content.AppendLine("  <stackpointer register=\"B\" space=\"ram\"/>");
            content.AppendLine();
            content.AppendLine("  <default_proto>");
            content.AppendLine("    <prototype name=\"__stdcall\" extrapop=\"2\" stackshift=\"2\">");
            content.AppendLine("      <input>");
            content.AppendLine("        <pentry minsize=\"1\" maxsize=\"2\">");
            content.AppendLine("          <register name=\"A\"/>");
            content.AppendLine("        </pentry>");
            content.AppendLine("        <pentry minsize=\"1\" maxsize=\"2\">");
            content.AppendLine("          <register name=\"X\"/>");
            content.AppendLine("        </pentry>");
            content.AppendLine("      </input>");
            content.AppendLine("      <output>");
            content.AppendLine("        <pentry minsize=\"1\" maxsize=\"2\">");
            content.AppendLine("          <register name=\"A\"/>");
            content.AppendLine("        </pentry>");
            content.AppendLine("      </output>");
            content.AppendLine("      <unaffected>");
            content.AppendLine("        <register name=\"B\"/>");
            content.AppendLine("      </unaffected>");
            content.AppendLine("    </prototype>");
            content.AppendLine("  </default_proto>");
            content.AppendLine("</compiler_spec>");

            File.WriteAllText(path, content.ToString());
        }

        private void GenerateModuleManifest()
        {
            var path = Path.Combine(_outputPath, "Module.manifest");
            EnsureDirectoryExists(path);
            
            // Create empty Module.manifest file (like 68000)
            File.WriteAllText(path, "");
        }

        private void GenerateBuildXml()
        {
            var path = Path.Combine(_outputPath, "data", "build.xml");
            EnsureDirectoryExists(path);

            var templatePath = Path.Combine("src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "build.xml");
            if (File.Exists(templatePath))
            {
                var content = File.ReadAllText(templatePath);
                File.WriteAllText(path, content);
            }
            else
            {
                // Fallback hardcoded content if template missing
                var content = new StringBuilder();
                content.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                content.AppendLine("<project name=\"privateBuildDistribution\" default=\"sleigh-compile\">");
                content.AppendLine("</project>");
                File.WriteAllText(path, content.ToString());
            }
        }

        private void GenerateSleighArgs()
        {
            var path = Path.Combine(_outputPath, "data", "sleighArgs.txt");
            EnsureDirectoryExists(path);
            
            // Create empty sleighArgs.txt file (like 68000)
            File.WriteAllText(path, "");
        }

        private void GenerateBpunLoader()
        {
            var path = Path.Combine(_outputPath, "src", "main", "java", "ghidra", "app", "util", "loader", "nd100", "BpunLoader.java");
            EnsureDirectoryExists(path);

            var templatePath = Path.Combine("src", "NDGen.Generators.Ghidra", "Ghidra", "ND-100", "BpunLoader.java");
            if (File.Exists(templatePath))
            {
                var content = File.ReadAllText(templatePath);
                File.WriteAllText(path, content);
            }
            else
            {
                throw new FileNotFoundException($"BPUN loader template not found: {templatePath}");
            }
        }

        private void GenerateBpunLoaderTest()
        {
            var path = Path.Combine(_outputPath, "src", "test", "java", "ghidra", "app", "util", "loader", "nd100", "BpunLoaderTest.java");
            EnsureDirectoryExists(path);

            var templatePath = Path.Combine("src", "NDGen.Generators.Ghidra", "Ghidra", "ND-100", "BpunLoaderTest.java");
            if (File.Exists(templatePath))
            {
                var content = File.ReadAllText(templatePath);
                File.WriteAllText(path, content);
            }
            else
            {
                throw new FileNotFoundException($"BPUN loader test template not found: {templatePath}");
            }
        }

        private void GenerateExtensionProperties()
        {
            var path = Path.Combine(_outputPath, "extension.properties");
            EnsureDirectoryExists(path);

            var templatePath = Path.Combine("src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "extension.properties");
            if (File.Exists(templatePath))
            {
                var content = File.ReadAllText(templatePath);
                content = content.Replace("@name@", "ND-100");
                content = content.Replace("@description@", "ND-100 processor support with BPUN file format loader");
                content = content.Replace("@author@", "NDGen");
                content = content.Replace("@createdOn@", DateTime.Now.ToString("yyyy-MM-dd"));
                content = content.Replace("@version@", "1.0.0");
                File.WriteAllText(path, content);
            }
            else
            {
                var content = new StringBuilder();
                content.AppendLine("name=ND-100");
                content.AppendLine("description=ND-100 processor support with BPUN file format loader");
                content.AppendLine("author=NDGen");
                content.AppendLine($"createdOn={DateTime.Now:yyyy-MM-dd}");
                content.AppendLine("version=1.0.0");
                File.WriteAllText(path, content.ToString());
            }
        }

        private void GenerateExtensionBuildGradle()
        {
            var path = Path.Combine(_outputPath, "build.gradle");
            EnsureDirectoryExists(path);

            var templatePath = Path.Combine("src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "build.gradle");
            if (File.Exists(templatePath))
            {
                var content = File.ReadAllText(templatePath);
                File.WriteAllText(path, content);
            }
            else
            {
                var content = new StringBuilder();
                content.AppendLine("apply plugin: 'java'");
                content.AppendLine();
                content.AppendLine("repositories {");
                content.AppendLine("    mavenCentral()");
                content.AppendLine("}");
                content.AppendLine();
                content.AppendLine("dependencies {");
                content.AppendLine("    compile fileTree(dir: \"${GHIDRA_INSTALL_DIR}/Ghidra/Framework\", include: \"**/*.jar\")");
                content.AppendLine("    compile fileTree(dir: \"${GHIDRA_INSTALL_DIR}/Ghidra/Features\", include: \"**/*.jar\")");
                content.AppendLine("}");
                content.AppendLine();
                content.AppendLine("sourceSets {");
                content.AppendLine("    main {");
                content.AppendLine("        java {");
                content.AppendLine("            srcDir 'src/main/java'");
                content.AppendLine("        }");
                content.AppendLine("        resources {");
                content.AppendLine("            srcDir 'src/main/resources'");
                content.AppendLine("        }");
                content.AppendLine("    }");
                content.AppendLine("}");
                File.WriteAllText(path, content.ToString());
            }
        }

    }
} 