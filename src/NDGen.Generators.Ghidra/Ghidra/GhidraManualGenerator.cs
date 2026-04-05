using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using NDGen.Core;
using NDGen.Core.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates a PDF processor manual and Ghidra .idx index file for the ND-100.
    /// Two-pass approach:
    ///   Pass 1: Generate PDF with instructions first, then appendix (title/TOC)
    ///   Pass 2: Count actual PDF pages and compute correct .idx page numbers
    /// </summary>
    public class GhidraManualGenerator
    {
        private readonly string _outputPath;
        private readonly DefinitionLoader _loader;

        public GhidraManualGenerator(string outputPath, DefinitionLoader loader)
        {
            _outputPath = outputPath;
            _loader = loader;
        }

        public string Generate()
        {
            QuestPDF.Settings.License = LicenseType.Community;

            var manualsDir = Path.Combine(_outputPath, "ND-100", "data", "manuals");
            Directory.CreateDirectory(manualsDir);

            var pdfPath = Path.Combine(manualsDir, "nd100_manual.pdf");
            var idxPath = Path.Combine(manualsDir, "nd100.idx");

            var instructions = _loader.GetInstructions();
            var cpuDef = _loader.GetCpuDefinition();

            // Sort instructions alphabetically
            var sorted = new List<InstructionDefinition>(instructions);
            sorted.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

            // Pass 1: Generate individual PDFs per instruction to find exact page counts
            var pageCounts = new int[sorted.Count];
            for (int i = 0; i < sorted.Count; i++)
            {
                var instr = sorted[i];
                var singleDoc = Document.Create(c => GenerateInstructionPage(c, instr));
                var bytes = singleDoc.GeneratePdf();
                pageCounts[i] = CountPdfPages(bytes);
            }

            // Compute page mapping: instruction i starts at page = sum of all previous page counts + 1
            var pageStarts = new int[sorted.Count];
            int currentPage = 1;
            for (int i = 0; i < sorted.Count; i++)
            {
                pageStarts[i] = currentPage;
                currentPage += pageCounts[i];
            }

            // Pass 2: Generate the final combined PDF
            var document = Document.Create(container =>
            {
                // Instruction pages first
                for (int i = 0; i < sorted.Count; i++)
                {
                    GenerateInstructionPage(container, sorted[i]);
                }

                // Appendix: title page
                GenerateTitlePage(container, sorted, cpuDef);

                // Appendix: TOC with correct page numbers
                GenerateTocPage(container, sorted, pageStarts);
            });

            document.GeneratePdf(pdfPath);

            // Generate .idx with correct page numbers
            GenerateIndexFile(idxPath, sorted, pageStarts);

            return idxPath;
        }

        private static void GenerateInstructionPage(IDocumentContainer container, InstructionDefinition instr)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Header().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).PaddingBottom(5).Row(row =>
                {
                    row.RelativeItem().Text(instr.Name).FontSize(10).Bold();
                    row.ConstantItem(200).AlignRight().Text(instr.Category ?? "").FontSize(8).FontColor(Colors.Grey.Darken1);
                });

                page.Content().PaddingTop(10).Column(col =>
                {
                    col.Item().Text(instr.Name).FontSize(26).Bold();
                    col.Item().PaddingTop(4).Text(instr.Description ?? "").FontSize(11);

                    // Info box
                    col.Item().PaddingTop(12).Background(Colors.Grey.Lighten4).Padding(8).Column(info =>
                    {
                        info.Item().Row(row =>
                        {
                            row.ConstantItem(90).Text("Opcode:").FontSize(9).Bold();
                            row.RelativeItem().Text($"{instr.Opcode} (octal) = 0x{instr.OpcodeValue:X4}").FontSize(9).FontFamily(Fonts.CourierNew);
                        });
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Format:").FontSize(9).Bold();
                            row.RelativeItem().Text(instr.Format ?? "").FontSize(9).FontFamily(Fonts.CourierNew);
                        });
                        if (!string.IsNullOrEmpty(instr.Mask))
                        {
                            info.Item().PaddingTop(2).Row(row =>
                            {
                                row.ConstantItem(90).Text("Mask:").FontSize(9).Bold();
                                row.RelativeItem().Text(instr.Mask).FontSize(9).FontFamily(Fonts.CourierNew);
                            });
                        }
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Privilege:").FontSize(9).Bold();
                            row.RelativeItem().Text(instr.Privilege.ToString()).FontSize(9);
                        });
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Class:").FontSize(9).Bold();
                            row.RelativeItem().Text(instr.InstructionClass ?? "").FontSize(9);
                        });
                    });

                    // Bit format
                    if (!string.IsNullOrEmpty(instr.GeneratedBitFormat))
                    {
                        col.Item().PaddingTop(10).Text("Bit Format").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Text(instr.GeneratedBitFormat).FontSize(8).FontFamily(Fonts.CourierNew);
                    }

                    // Detailed description
                    if (!string.IsNullOrEmpty(instr.DetailedDescription))
                    {
                        col.Item().PaddingTop(10).Text("Description").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Text(instr.DetailedDescription).FontSize(9);
                    }

                    // Operands
                    if (instr.Operands != null && instr.Operands.Count > 0)
                    {
                        col.Item().PaddingTop(10).Text("Operands").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(90);
                                cols.ConstantColumn(55);
                                cols.ConstantColumn(75);
                                cols.RelativeColumn();
                            });

                            table.Header(header =>
                            {
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Name").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Bits").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Type").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Description").FontSize(8).Bold();
                            });

                            for (int o = 0; o < instr.Operands.Count; o++)
                            {
                                var op = instr.Operands[o];
                                var bg = o % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(2).Text(op.Name).FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Bits).FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Type ?? "").FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Description ?? "").FontSize(8);
                            }
                        });
                    }

                    // Flags
                    if (instr.FlagsAffected != null && instr.FlagsAffected.Count > 0)
                    {
                        var flagStr = new StringBuilder();
                        for (int f = 0; f < instr.FlagsAffected.Count; f++)
                        {
                            if (f > 0) flagStr.Append(", ");
                            flagStr.Append(instr.FlagsAffected[f]);
                        }
                        col.Item().PaddingTop(10).Text($"Flags: {flagStr}").FontSize(9).Bold();

                        if (instr.Flags != null)
                        {
                            var details = new StringBuilder();
                            AppendFlag(details, "C", instr.Flags.C);
                            AppendFlag(details, "O", instr.Flags.O);
                            AppendFlag(details, "Q", instr.Flags.Q);
                            AppendFlag(details, "Z", instr.Flags.Z);
                            if (details.Length > 0)
                                col.Item().PaddingTop(2).Text(details.ToString()).FontSize(8);
                        }
                    }

                    // Pseudocode
                    if (!string.IsNullOrEmpty(instr.Pseudocode))
                    {
                        col.Item().PaddingTop(10).Text("Pseudocode").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Background(Colors.Grey.Lighten4).Padding(6)
                            .Text(instr.Pseudocode).FontSize(8).FontFamily(Fonts.CourierNew);
                    }

                    // Examples
                    if (instr.Examples != null && instr.Examples.Count > 0)
                    {
                        col.Item().PaddingTop(10).Text("Examples").FontSize(11).Bold();
                        for (int e = 0; e < instr.Examples.Count; e++)
                        {
                            var ex = instr.Examples[e];
                            col.Item().PaddingTop(3).Text(ex.Description).FontSize(8).Italic();
                            col.Item().PaddingTop(1).Background(Colors.Grey.Lighten4).Padding(4)
                                .Text(ex.Code).FontSize(8).FontFamily(Fonts.CourierNew);
                        }
                    }
                });

                page.Footer().AlignCenter().Text(text =>
                {
                    text.Span("ND-100 Processor Reference — Page ").FontSize(8).FontColor(Colors.Grey.Medium);
                    text.CurrentPageNumber().FontSize(8).FontColor(Colors.Grey.Medium);
                });
            });
        }

        private static void GenerateTitlePage(IDocumentContainer container, List<InstructionDefinition> sorted, CpuDefinition? cpuDef)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Content().Column(col =>
                {
                    col.Item().PaddingTop(120).AlignCenter().Text("ND-100").FontSize(48).Bold();
                    col.Item().AlignCenter().Text("Processor Reference Manual").FontSize(24);
                    col.Item().PaddingTop(20).AlignCenter().Text("Norsk Data ND-100 16-bit Minicomputer").FontSize(14);
                    col.Item().PaddingTop(10).AlignCenter().Text($"Generated by NDGen — {DateTime.Now:yyyy-MM-dd}").FontSize(10).FontColor(Colors.Grey.Medium);

                    col.Item().PaddingTop(60).Text("Architecture").FontSize(16).Bold();
                    col.Item().PaddingTop(5).Text(text =>
                    {
                        text.Line("Word size: 16-bit").FontSize(10);
                        text.Line("Byte order: Big Endian").FontSize(10);
                        text.Line("Registers: A, D, B, L, T, X, STS, P").FontSize(10);
                        text.Line("Addressing: Direct, Indirect, Indexed, Base-relative").FontSize(10);
                        text.Line($"Instructions: {sorted.Count}").FontSize(10);
                    });

                    if (cpuDef?.Metadata?.Registers != null)
                    {
                        col.Item().PaddingTop(20).Text("Registers").FontSize(14).Bold();
                        col.Item().PaddingTop(5).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(60);
                                cols.ConstantColumn(50);
                                cols.RelativeColumn();
                            });

                            table.Header(header =>
                            {
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Name").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Size").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Description").FontSize(9).Bold();
                            });

                            var regs = cpuDef.Metadata.Registers;
                            for (int r = 0; r < regs.Count; r++)
                            {
                                var reg = regs[r];
                                var bg = r % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(3).Text(reg.Name).FontSize(9);
                                table.Cell().Background(bg).Padding(3).Text(reg.Size?.ToString() ?? "16").FontSize(9);
                                table.Cell().Background(bg).Padding(3).Text(reg.Description).FontSize(9);
                            }
                        });
                    }
                });
            });
        }

        private static void GenerateTocPage(IDocumentContainer container, List<InstructionDefinition> sorted, int[] pageStarts)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Content().Column(col =>
                {
                    col.Item().Text("Instruction Index").FontSize(20).Bold();
                    col.Item().PaddingTop(5).Text("Instructions are listed alphabetically.")
                        .FontSize(9).FontColor(Colors.Grey.Darken1);

                    col.Item().PaddingTop(10).Table(table =>
                    {
                        table.ColumnsDefinition(cols =>
                        {
                            cols.ConstantColumn(40);
                            cols.ConstantColumn(55);
                            cols.ConstantColumn(65);
                            cols.RelativeColumn();
                            cols.ConstantColumn(55);
                        });

                        table.Header(header =>
                        {
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Page").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Mnemonic").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Opcode").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Description").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Privilege").FontSize(8).Bold();
                        });

                        for (int i = 0; i < sorted.Count; i++)
                        {
                            var instr = sorted[i];
                            var bg = i % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                            table.Cell().Background(bg).Padding(2).Text(pageStarts[i].ToString()).FontSize(8);
                            table.Cell().Background(bg).Padding(2).Text(instr.Name).FontSize(8).Bold();
                            table.Cell().Background(bg).Padding(2).Text(instr.Opcode).FontSize(8).FontFamily(Fonts.CourierNew);
                            var desc = instr.Description ?? "";
                            if (desc.Length > 70) desc = desc.Substring(0, 67) + "...";
                            table.Cell().Background(bg).Padding(2).Text(desc).FontSize(8);
                            table.Cell().Background(bg).Padding(2).Text(instr.Privilege.ToString()).FontSize(8);
                        }
                    });
                });
            });
        }

        /// <summary>
        /// Count pages in a PDF by scanning for /Type /Page entries (not /Type /Pages)
        /// </summary>
        private static int CountPdfPages(byte[] pdfBytes)
        {
            var pdfText = Encoding.ASCII.GetString(pdfBytes);
            // Match /Type /Page followed by non-'s' (to exclude /Type /Pages)
            var matches = Regex.Matches(pdfText, @"/Type\s*/Page(?!s)");
            return matches.Count;
        }

        private static void AppendFlag(StringBuilder sb, string flag, string effect)
        {
            if (effect != "unaffected")
            {
                if (sb.Length > 0) sb.Append("  ");
                sb.Append(flag).Append(": ").Append(effect);
            }
        }

        private static void GenerateIndexFile(string idxPath, List<InstructionDefinition> sorted, int[] pageStarts)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ND-100 Processor Manual Index for Ghidra");
            sb.AppendLine("# Generated by NDGen");
            sb.AppendLine();
            sb.AppendLine("@nd100_manual.pdf [ND-100 Processor Reference Manual (NDGen Generated)]");
            sb.AppendLine();

            for (int i = 0; i < sorted.Count; i++)
            {
                sb.AppendLine($"{sorted[i].Name}, {pageStarts[i]}");
            }

            File.WriteAllText(idxPath, sb.ToString());
        }
    }
}
