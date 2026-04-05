using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NDGen.Generators.Ghidra
{
    public class IODevice
    {
        public required string Name { get; set; }
        public required string Description { get; set; }
        public int Address { get; set; }
        public bool IsRead { get; set; }
        public bool IsWrite { get; set; }
        public bool IsIllegal { get; set; }
        public Dictionary<string, string> BitFields { get; init; } = new();
    }

    public class IOMemoryMapGenerator
    {
        private readonly string _inputPath;
        private readonly string _outputPath;
        private readonly List<IODevice> _devices;

        public IOMemoryMapGenerator(string inputPath, string outputPath)
        {
            _inputPath = inputPath ?? throw new ArgumentNullException(nameof(inputPath));
            _outputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            _devices = new List<IODevice>();
        }

        public void Generate()
        {
            ParseIOAddressFile();
            WriteJson();
        }

        private void ParseIOAddressFile()
        {
            var lines = File.ReadAllLines(_inputPath);
            IODevice? currentDevice = null;

            foreach (var line in lines)
            {
                // Skip empty lines
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Check for device definition (contains address)
                if (line.Contains("IOX"))
                {
                    var device = ParseDeviceLine(line);
                    if (device != null)
                    {
                        currentDevice = device;
                        _devices.Add(device);
                    }
                }
                // Add description to current device
                else if (currentDevice != null)
                {
                    currentDevice.Description += Environment.NewLine + line.Trim();
                }
            }

            // Mark illegal range
            foreach (var device in _devices)
            {
                if (device.Address >= 0x4000 && device.Address <= 0x7777)
                {
                    device.IsIllegal = true;
                }
            }
        }

        private IODevice? ParseDeviceLine(string line)
        {
            // Example: "IOX 300: Read input data"
            var match = Regex.Match(line, @"IOX\s+([0-7]+):\s*(.*)");
            if (!match.Success) return null;

            var address = Convert.ToInt32(match.Groups[1].Value, 8); // Parse octal
            var description = match.Groups[2].Value.Trim();

            return new IODevice
            {
                Name = $"IO_{address:X4}",
                Description = description,
                Address = address,
                IsRead = (address & 1) == 0, // Even addresses are read
                IsWrite = (address & 1) == 1, // Odd addresses are write
                IsIllegal = false,
                BitFields = new Dictionary<string, string>()
            };
        }

        private void WriteJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            var json = JsonSerializer.Serialize(_devices, options);
            File.WriteAllText(_outputPath, json);
        }
    }
} 