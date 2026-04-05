using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NDGen.Core;
using NDGen.Generators.Ghidra;

namespace ND100.Ghidra.Tool;

internal static class Program
{
    private const string SolutionMarker = "ND100.Ghidra.sln";

    public static int Main(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "help", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("ND100 Ghidra / SLEIGH generator. Requires nd100-definitions submodule.");
            Console.WriteLine("Usage: dotnet run --project src/ND100.Ghidra.Tool");
            Console.WriteLine("Output: ./ND-100/ (under repo root)");
            return 0;
        }

        try
        {
            var baseDir = FindRepoRoot();
            // Generated extension tree: ND-100/ under this repository root (folder that contains .git / ND100.Ghidra.sln).
            var ghidraDir = baseDir;
            Directory.CreateDirectory(ghidraDir);

            var services = new ServiceCollection();
            services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Information));
            services.AddTransient<YamlLoader>();
            services.AddTransient<DefinitionLoader>();
            var sp = services.BuildServiceProvider();
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("ghidra-nd100");

            var loader = sp.GetRequiredService<DefinitionLoader>();
            loader.Initialize(GetCpuYamlPath(baseDir));

            var ghidraSleighGen = new GhidraSleighGenerator(ghidraDir, loader);
            ghidraSleighGen.SetBaseDirectory(baseDir);

            logger.LogInformation("Generating I/O device analyzer...");
            new GhidraIODeviceGenerator(baseDir, ghidraDir).Generate();

            logger.LogInformation("Generating MON call analyzer...");
            new GhidraMonCallGenerator(baseDir, ghidraDir).Generate();

            logger.LogInformation("Generating Ghidra / SLEIGH output...");
            ghidraSleighGen.Generate();

            logger.LogInformation("Generating processor manual PDF...");
            new GhidraManualGenerator(ghidraDir, loader).Generate();

            try
            {
                logger.LogInformation("Building complete Ghidra extension...");
                var zip = ghidraSleighGen.BuildCompleteExtension();
                logger.LogInformation("Extension ZIP: {Zip}", zip);
            }
            catch (Exception ex)
            {
                logger.LogWarning("Extension ZIP build failed (SLEIGH still generated): {Message}", ex.Message);
            }

            logger.LogInformation("Done. Output: {Path}", ghidraDir);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, SolutionMarker)))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException($"Could not find {SolutionMarker} (repo root).");
    }

    private static string GetCpuYamlPath(string baseDir)
    {
        var env = Environment.GetEnvironmentVariable("ND100_SPECS_CPU_YAML");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env))
            return env;

        var path = Path.Combine(baseDir, "nd100-definitions", "specs", "cpu.yaml");
        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"CPU definition not found at '{path}'. Run: git submodule update --init --recursive");
        return path;
    }
}
