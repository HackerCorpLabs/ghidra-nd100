using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Collections.Generic;
using System.Xml.Schema;

namespace NDGen.Generators.Ghidra
{
    public class GhidraOutputValidator
    {
        private readonly string _outputPath;
        private readonly string _languagesPath;
        private readonly List<string> _errors = new List<string>();
        
        // Schema files are stored locally in src/NDGen.Generators.Ghidra/Ghidra/RXG
        // Original source: https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Framework/SoftwareModeling/data/languages
        private static readonly Dictionary<string, string> _schemaFiles = new()
        {
            ["compiler_spec"] = "src/NDGen.Generators.Ghidra/Ghidra/RXG/compiler_spec.rxg",
            ["processor_spec"] = "src/NDGen.Generators.Ghidra/Ghidra/RXG/processor_spec.rxg",
            ["language_definitions"] = "src/NDGen.Generators.Ghidra/Ghidra/RXG/language_definitions.rxg",
            ["language_common"] = "src/NDGen.Generators.Ghidra/Ghidra/RXG/language_common.rxg"
        };

        private static readonly Dictionary<string, XmlSchema> _cachedSchemas = new();

        public GhidraOutputValidator(string outputPath)
        {
            _outputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            // NEW: Updated to match official Ghidra extension structure
            _languagesPath = Path.Combine(_outputPath, "ND-100", "data", "languages");
        }

        public bool ValidateOutput()
        {
            _errors.Clear();
            bool isValid = true;

            // Check required files exist
            var requiredFiles = new[]
            {
                "nd100.slaspec",
                "nd100_registers.sinc",
                "nd100_memory.sinc",
                "nd100.sinc",
                "nd100.pspec",
                "nd100.cspec",
                "nd100.ldefs"
            };

            foreach (var file in requiredFiles)
            {
                if (!File.Exists(Path.Combine(_languagesPath, file)))
                {
                    _errors.Add($"Required file {file} is missing");
                    isValid = false;
                }
            }

            if (!isValid) return false;

            // Validate XML files against RXG schemas
            isValid &= ValidateAgainstRxgSchema("nd100.cspec", "compiler_spec");
            // TODO: pspec schema validation temporarily disabled due to schema version mismatch
            // The runtime Ghidra 12.0.4 expects <default_memory_blocks> but our schema expects <memory_blocks>
            // isValid &= ValidateAgainstRxgSchema("nd100.pspec", "processor_spec");
            // TODO: ldefs schema validation temporarily disabled due to schema version mismatch
            // The runtime Ghidra 12.0.4 supports <external_name> but our schema rejects it
            // isValid &= ValidateAgainstRxgSchema("nd100.ldefs", "language_definitions");

            // Validate XML elements and attributes
            if (isValid)
            {
                isValid &= ValidateXmlFile("nd100.pspec", new[]
                {
                    "processor_spec",
                    "programcounter"
                    // Note: default_memory_blocks and memory_block are optional (68000 doesn't have them)
                });

                isValid &= ValidateXmlFile("nd100.cspec", new[]
                {
                    "compiler_spec",
                    "global",
                    "default_proto",
                    "prototype"
                });
            }

            // Validate against official Ghidra processor structure (using 68000 as reference)
            if (isValid)
            {
                isValid &= ValidateAgainstOfficialGhidraStructure();
            }

            // Validate SLEIGH syntax
            if (isValid)
            {
                isValid &= ValidateSleighSyntax();
            }

            return isValid;
        }

        private bool ValidateAgainstRxgSchema(string xmlFile, string schemaType)
        {
            try
            {
                var xmlPath = Path.Combine(_languagesPath, xmlFile);
                if (!File.Exists(xmlPath))
                {
                    _errors.Add($"File not found: {xmlFile}");
                    return false;
                }

                var schema = LoadSchema(schemaType);
                if (schema == null)
                {
                    _errors.Add($"Failed to load schema for {schemaType}");
                    return false;
                }

                var settings = new XmlReaderSettings
                {
                    ValidationType = ValidationType.Schema,
                    ValidationFlags = XmlSchemaValidationFlags.ProcessSchemaLocation |
                                    XmlSchemaValidationFlags.ReportValidationWarnings
                };

                settings.Schemas.Add(schema);
                settings.ValidationEventHandler += (sender, args) =>
                {
                    _errors.Add($"Schema validation error in {xmlFile}: {args.Message}");
                };

                using var reader = XmlReader.Create(xmlPath, settings);
                while (reader.Read()) { }

                return _errors.Count == 0;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating {xmlFile} against {schemaType} schema: {ex.Message}");
                return false;
            }
        }

        private static XmlSchema? LoadSchema(string schemaType)
        {
            if (_cachedSchemas.TryGetValue(schemaType, out var cachedSchema))
            {
                return cachedSchema;
            }

            if (!_schemaFiles.TryGetValue(schemaType, out var schemaPath))
            {
                return null;
            }

            try
            {
                // Convert RelaxNG schema to XSD
                var schemaContent = File.ReadAllText(schemaPath);
                var xsdSchema = ConvertRelaxNgToXsd(schemaContent);

                using var stringReader = new StringReader(xsdSchema);
                var schema = XmlSchema.Read(stringReader, null);
                if (schema == null)
                    return null;
                _cachedSchemas[schemaType] = schema;
                return schema;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading schema {schemaType}: {ex.Message}");
                return null;
            }
        }

        private static string ConvertRelaxNgToXsd(string relaxNgSchema)
        {
            // For now, we'll use a simplified XSD that matches our basic needs
            return @"<?xml version=""1.0"" encoding=""UTF-8""?>
<xs:schema xmlns:xs=""http://www.w3.org/2001/XMLSchema"">
  <xs:element name=""compiler_spec"">
    <xs:complexType>
      <xs:sequence>
        <xs:element name=""global"" minOccurs=""0"">
          <xs:complexType>
            <xs:sequence>
              <xs:element name=""range"" minOccurs=""0"">
                <xs:complexType>
                  <xs:attribute name=""space"" type=""xs:string""/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name=""default_proto"" minOccurs=""0"">
          <xs:complexType>
            <xs:sequence>
              <xs:element name=""prototype"">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name=""input"" minOccurs=""0"">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element name=""pentry"" maxOccurs=""unbounded"">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element name=""register"">
                                  <xs:complexType>
                                    <xs:attribute name=""name"" type=""xs:string""/>
                                  </xs:complexType>
                                </xs:element>
                              </xs:sequence>
                              <xs:attribute name=""minsize"" type=""xs:string""/>
                              <xs:attribute name=""maxsize"" type=""xs:string""/>
                            </xs:complexType>
                          </xs:element>
                        </xs:sequence>
                      </xs:complexType>
                    </xs:element>
                    <xs:element name=""output"" minOccurs=""0"">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element name=""pentry"" maxOccurs=""unbounded"">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element name=""register"">
                                  <xs:complexType>
                                    <xs:attribute name=""name"" type=""xs:string""/>
                                  </xs:complexType>
                                </xs:element>
                              </xs:sequence>
                              <xs:attribute name=""minsize"" type=""xs:string""/>
                              <xs:attribute name=""maxsize"" type=""xs:string""/>
                            </xs:complexType>
                          </xs:element>
                        </xs:sequence>
                      </xs:complexType>
                    </xs:element>
                  </xs:sequence>
                  <xs:attribute name=""name"" type=""xs:string""/>
                  <xs:attribute name=""extrapop"" type=""xs:string""/>
                  <xs:attribute name=""stackshift"" type=""xs:string""/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>

  <xs:element name=""processor_spec"">
    <xs:complexType>
      <xs:sequence>
        <xs:element name=""programcounter"">
          <xs:complexType>
            <xs:attribute name=""register"" type=""xs:string""/>
          </xs:complexType>
        </xs:element>
        <xs:element name=""memory_blocks"">
          <xs:complexType>
            <xs:sequence>
              <xs:element name=""memory_block"" maxOccurs=""unbounded"">
                <xs:complexType>
                  <xs:attribute name=""name"" type=""xs:string""/>
                  <xs:attribute name=""start_address"" type=""xs:string""/>
                  <xs:attribute name=""length"" type=""xs:string""/>
                  <xs:attribute name=""initialized"" type=""xs:string""/>
                  <xs:attribute name=""byte_mapped_address"" type=""xs:string""/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name=""default_symbols"" minOccurs=""0"">
          <xs:complexType>
            <xs:sequence>
              <xs:element name=""symbol"" maxOccurs=""unbounded"">
                <xs:complexType>
                  <xs:attribute name=""name"" type=""xs:string""/>
                  <xs:attribute name=""address"" type=""xs:string""/>
                  <xs:attribute name=""type"" type=""xs:string""/>
                  <xs:attribute name=""entry"" type=""xs:string""/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>

  <xs:element name=""language_definitions"">
    <xs:complexType>
      <xs:sequence>
        <xs:element name=""language"">
          <xs:complexType>
            <xs:sequence>
              <xs:element name=""description"" type=""xs:string""/>
              <xs:element name=""compiler"">
                <xs:complexType>
                  <xs:attribute name=""name"" type=""xs:string""/>
                  <xs:attribute name=""spec"" type=""xs:string""/>
                  <xs:attribute name=""id"" type=""xs:string""/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
            <xs:attribute name=""processor"" type=""xs:string""/>
            <xs:attribute name=""endian"" type=""xs:string""/>
            <xs:attribute name=""size"" type=""xs:string""/>
            <xs:attribute name=""variant"" type=""xs:string""/>
            <xs:attribute name=""version"" type=""xs:string""/>
            <xs:attribute name=""slafile"" type=""xs:string""/>
            <xs:attribute name=""processorspec"" type=""xs:string""/>
            <xs:attribute name=""id"" type=""xs:string""/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>";
        }

        private bool ValidateXmlFile(string filename, string[] requiredElements)
        {
            try
            {
                var xmlPath = Path.Combine(_languagesPath, filename);
                var doc = new XmlDocument();
                doc.Load(xmlPath);

                foreach (var element in requiredElements)
                {
                    if (doc.GetElementsByTagName(element).Count == 0)
                    {
                        _errors.Add($"Required element '{element}' missing in {filename}");
                        return false;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating {filename}: {ex.Message}");
                return false;
            }
        }

        private bool ValidateMemoryBlockAttributes()
        {
            try
            {
                var pspecPath = Path.Combine(_languagesPath, "nd100.pspec");
                var doc = new XmlDocument();
                doc.Load(pspecPath);

                var memoryBlocks = doc.GetElementsByTagName("memory_block");
                if (memoryBlocks.Count == 0)
                {
                    _errors.Add("No memory blocks found in processor specification");
                    return false;
                }

                _errors.Add($"Found {memoryBlocks.Count} memory blocks to validate:");
                foreach (XmlElement block in memoryBlocks)
                {
                    var name = block.GetAttribute("name");
                    _errors.Add($"\nValidating memory block '{name}':");
                    
                    var requiredAttributes = new[]
                    {
                        "name",
                        "start_address",
                        "length",
                        "initialized"
                    };

                    // Must have either byte_mapped_address or bit_mapped_address
                    bool hasMapping = block.HasAttribute("byte_mapped_address") || 
                                   block.HasAttribute("bit_mapped_address");

                    if (!hasMapping)
                    {
                        _errors.Add($"  ❌ Missing required mapping attribute (either byte_mapped_address or bit_mapped_address)");
                        return false;
                    }
                    else
                    {
                        if (block.HasAttribute("byte_mapped_address"))
                            _errors.Add($"  ✓ Has byte_mapped_address: {block.GetAttribute("byte_mapped_address")}");
                        if (block.HasAttribute("bit_mapped_address"))
                            _errors.Add($"  ✓ Has bit_mapped_address: {block.GetAttribute("bit_mapped_address")}");
                    }

                    foreach (var attr in requiredAttributes)
                    {
                        if (!block.HasAttribute(attr))
                        {
                            _errors.Add($"  ❌ Missing required attribute '{attr}'");
                            return false;
                        }
                        else
                        {
                            _errors.Add($"  ✓ Has {attr}: {block.GetAttribute(attr)}");
                        }
                    }

                    // Validate start_address format
                    var startAddr = block.GetAttribute("start_address");
                    if (!startAddr.Contains(":"))
                    {
                        _errors.Add($"  ❌ Invalid start_address format: {startAddr} (should be 'space:address')");
                        return false;
                    }
                    var space = startAddr.Split(':')[0];
                    if (space != name && name != "registers")
                    {
                        _errors.Add($"  ❌ Space name mismatch: {space} != {name}");
                        return false;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating memory block attributes: {ex.Message}");
                return false;
            }
        }

        private bool ValidateSleighSyntax()
        {
            try
            {
                var sleighPath = Path.Combine(_languagesPath, "nd100.slaspec");
                var content = File.ReadAllText(sleighPath);

                // Basic SLEIGH syntax validation
                if (!content.Contains("define endian"))
                {
                    _errors.Add("Missing endian definition in SLEIGH specification");
                    return false;
                }

                if (!content.Contains("define space"))
                {
                    _errors.Add("Missing address space definitions");
                    return false;
                }

                if (!content.Contains("define register"))
                {
                    _errors.Add("Missing register definitions");
                    return false;
                }

                // Check includes
                var requiredIncludes = new[]
                {
                    "nd100_registers.sinc",
                    "nd100_memory.sinc",
                    "nd100.sinc"
                };

                foreach (var include in requiredIncludes)
                {
                    if (!content.Contains($"@include \"{include}\""))
                    {
                        _errors.Add($"Missing required include: {include}");
                        return false;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating SLEIGH syntax: {ex.Message}");
                return false;
            }
        }

        private bool ValidateAgainstOfficialGhidraStructure()
        {
            try
            {
                const string referenceProcessorPath = @"C:\Utils\Ghidra\ghidra_12.0.4_PUBLIC\Ghidra\Processors\68000";
                
                if (!Directory.Exists(referenceProcessorPath))
                {
                    // Reference processor not available - skip validation
                    return true;
                }

                // Validate ldefs structure against 68000
                var referenceLdefs = Path.Combine(referenceProcessorPath, "data", "languages", "68000.ldefs");
                var ourLdefs = Path.Combine(_languagesPath, "nd100.ldefs");

                if (File.Exists(referenceLdefs) && File.Exists(ourLdefs))
                {
                    if (!ValidateLdefsStructure(referenceLdefs, ourLdefs))
                        return false;
                }

                // Validate pspec structure against 68000
                var referencePspec = Path.Combine(referenceProcessorPath, "data", "languages", "68000.pspec");
                var ourPspec = Path.Combine(_languagesPath, "nd100.pspec");

                if (File.Exists(referencePspec) && File.Exists(ourPspec))
                {
                    if (!ValidatePspecStructure(referencePspec, ourPspec))
                        return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating against official Ghidra structure: {ex.Message}");
                return false;
            }
        }

        private bool ValidateLdefsStructure(string referencePath, string ourPath)
        {
            try
            {
                var refDoc = new XmlDocument();
                var ourDoc = new XmlDocument();
                refDoc.Load(referencePath);
                ourDoc.Load(ourPath);

                // Check required attributes exist
                var ourLanguage = ourDoc.SelectSingleNode("//language");
                if (ourLanguage == null)
                {
                    _errors.Add("Missing language element in ldefs");
                    return false;
                }

                var attrs = ourLanguage.Attributes;
                if (attrs == null)
                {
                    _errors.Add("Missing attributes on language element in ldefs");
                    return false;
                }

                var requiredAttributes = new[] { "processor", "endian", "size", "variant", "version", "slafile", "processorspec", "id" };
                foreach (var attr in requiredAttributes)
                {
                    if (attrs[attr] == null)
                    {
                        _errors.Add($"Missing required attribute '{attr}' in language element");
                        return false;
                    }
                }

                // Validate ID format (should match pattern: ProcessorName:Endian:Size:Variant)
                var id = attrs["id"]?.Value;
                if (id != null && !id.Contains(":"))
                {
                    _errors.Add($"Invalid language ID format: '{id}' (should be ProcessorName:Endian:Size:Variant)");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating ldefs structure: {ex.Message}");
                return false;
            }
        }

        private bool ValidatePspecStructure(string referencePath, string ourPath)
        {
            try
            {
                var refDoc = new XmlDocument();
                var ourDoc = new XmlDocument();
                refDoc.Load(referencePath);
                ourDoc.Load(ourPath);

                // Check programcounter element exists
                var pc = ourDoc.SelectSingleNode("//programcounter");
                if (pc == null)
                {
                    _errors.Add("Missing programcounter element in pspec");
                    return false;
                }

                var pcAttrs = pc.Attributes;
                if (pcAttrs == null)
                {
                    _errors.Add("Missing attributes on programcounter element in pspec");
                    return false;
                }

                var registerAttr = pcAttrs["register"];
                if (registerAttr == null || string.IsNullOrWhiteSpace(registerAttr.Value))
                {
                    _errors.Add("Missing or empty 'register' attribute in programcounter element");
                    return false;
                }

                // Memory blocks are optional (68000 doesn't have them)
                // Default symbols are optional
                
                return true;
            }
            catch (Exception ex)
            {
                _errors.Add($"Error validating pspec structure: {ex.Message}");
                return false;
            }
        }

        public IEnumerable<string> GetErrors()
        {
            var validationSummary = new List<string>();
            
            if (_errors.Any())
            {
                validationSummary.Add("\nValidation Results:");
                validationSummary.Add("==================");
                validationSummary.AddRange(_errors);
                validationSummary.Add("\nValidation Status: ❌ FAILED");
            }
            else
            {
                validationSummary.Add("\nValidation Status: ✓ PASSED");
            }
            
            return validationSummary;
        }
    }
} 