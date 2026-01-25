using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using System.Data;
using System.Globalization;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using System.Threading.Tasks;

namespace RdpEventLogParser
{
    class Program
    {
        static void Main(string[] args)
        {
            SetupLogging();
            try
            {
                string scriptDir = GetScriptDirectory();
                string inputDir = Path.Combine(scriptDir, "input");
                string outputDir = Path.Combine(scriptDir, "output");

                Console.WriteLine("================================================================");
                Console.WriteLine("RDP Event Log Parser (C#) Started");
                Console.WriteLine("================================================================");
                Console.WriteLine($"Script directory: {scriptDir}");
                Console.WriteLine($"Input directory: {inputDir}");
                Console.WriteLine($"Output directory: {outputDir}");

                if (!Directory.Exists(inputDir))
                    throw new DirectoryNotFoundException($"Input directory does not exist: {inputDir}");

                var groupedFiles = FindEvtxFilesRecursive(inputDir);
                int totalFiles = groupedFiles.Sum(g => g.Value.Count);
                Console.WriteLine($"Found {totalFiles} .evtx file(s) across {groupedFiles.Count} location(s)");
                Console.WriteLine(new string('-', 80));

                Directory.CreateDirectory(outputDir);

                int[] targetEventIds = { 21, 23, 24, 25 };

                foreach (var kvp in groupedFiles)
                {
                    string hostname = kvp.Key;
                    string groupName = string.IsNullOrEmpty(hostname) ? "root" : hostname;
                    Console.WriteLine($"Processing group: [{groupName}]");

                    List<Dictionary<string, object>> allEvents = new List<Dictionary<string, object>>();

                    Parallel.ForEach(kvp.Value, evtxFile =>
                    {
                        var events = ParseEvtxFile(evtxFile, targetEventIds);
                        lock (allEvents)
                        {
                            allEvents.AddRange(events);
                        }
                    });

                    if (!allEvents.Any())
                    {
                        Console.WriteLine($"  No matching RDP events found for group: [{groupName}]");
                        Console.WriteLine(new string('-', 80));
                        continue;
                    }

                    string hostOutputDir = outputDir;
                    if (!string.IsNullOrEmpty(hostname))
                    {
                        hostOutputDir = Path.Combine(outputDir, hostname);
                        Directory.CreateDirectory(hostOutputDir);
                    }

                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH.mm.ss");
                    string csvFile = Path.Combine(hostOutputDir, $"{timestamp}_RDP_Report.csv");
                    string xlsxFile = Path.Combine(hostOutputDir, $"{timestamp}_RDP_Report.xlsx");

                    WriteCsvReport(allEvents, csvFile);
                    Console.WriteLine($"  CSV saved to: {csvFile}");

                    WriteXlsxReport(allEvents, xlsxFile);
                    Console.WriteLine($"  XLSX saved to: {xlsxFile}");

                    Console.WriteLine($"  Total events processed: {allEvents.Count}");
                    Console.WriteLine(new string('-', 80));
                }

                Console.WriteLine("================================================================");
                Console.WriteLine("Processing completed successfully");
                Console.WriteLine("================================================================");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private static void SetupLogging()
        {
            // Simple console logging
        }

        private static string GetScriptDirectory()
        {
            return AppDomain.CurrentDomain.BaseDirectory;
        }

        private static Dictionary<string, List<string>> FindEvtxFilesRecursive(string inputDirectory)
        {
            var groupedFiles = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var evtxFiles = Directory.EnumerateFiles(inputDirectory, "*.evtx", SearchOption.AllDirectories);

            foreach (string evtxFile in evtxFiles)
            {
                string relativePath = Path.GetRelativePath(inputDirectory, evtxFile);
                string[] parts = Path.GetDirectoryName(relativePath)?.Split(Path.DirectorySeparatorChar) ?? new string[0];
                string hostname = parts.Length > 0 ? parts[0] : "";

                if (!groupedFiles.TryGetValue(hostname, out var list))
                {
                    list = new List<string>();
                    groupedFiles[hostname] = list;
                }
                list.Add(evtxFile);
            }

            return groupedFiles;
        }

        private static List<Dictionary<string, object>> ParseEvtxFile(string evtxPath, int[] targetEventIds)
        {
            Console.WriteLine($"  Processing: {Path.GetFileName(evtxPath)}");
            var eventsData = new List<Dictionary<string, object>>();

            try
            {
                using var reader = new EventLogReader(evtxPath, PathType.FilePath);
                EventRecord record;
                while ((record = reader.ReadEvent()) != null)
                {
                    if (targetEventIds.Contains(record.Id))
                    {
                        var parsedData = ParseEventRecord(record);
                        if (parsedData != null)
                        {
                            eventsData.Add(parsedData);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Failed to read .evtx file {Path.GetFileName(evtxPath)}: {ex.Message}");
                throw;
            }

            Console.WriteLine($"    Found {eventsData.Count} matching events");
            return eventsData;
        }

        private static Dictionary<string, object> ParseEventRecord(EventRecord record)
        {
            try
            {
                string xml = record.ToXml();
                var doc = XDocument.Parse(xml);
                var ns = doc.Root.GetDefaultNamespace();

                var eventId = record.Id;
                var timeCreated = ConvertUtcToLocal(record.TimeCreated);
                var computer = record.MachineName ?? "";
                var user = "";
                var address = "";

                // Extract UserData or EventData
                var userData = doc.Descendants(ns + "UserData").FirstOrDefault() ?? doc.Descendants(ns + "EventData").FirstOrDefault();
                if (userData != null)
                {
                    user = userData.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals("User", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
                    address = userData.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals("Address", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
                }

                return new Dictionary<string, object>
                {
                    { "TimeCreated", timeCreated },
                    { "User", user },
                    { "IPAddress", address },
                    { "EventID", eventId },
                    { "ServerName", computer },
                    { "Action", GetActionDescription(eventId) }
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Failed to parse event {record.Id}: {ex.Message}");
                return null;
            }
        }

        private static string ConvertUtcToLocal(DateTime utcTime)
        {
            try
            {
                return utcTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch
            {
                return utcTime.ToString("yyyy-MM-dd HH:mm:ss");
            }
        }

        private static string GetActionDescription(int eventId)
        {
            return eventId switch
            {
                21 => "Logon",
                23 => "Logoff",
                24 => "Disconnected",
                25 => "Reconnection",
                _ => "Unknown"
            };
        }

        private static void WriteCsvReport(List<Dictionary<string, object>> eventsData, string outputPath)
        {
            var sortedEvents = eventsData.OrderBy(e => e["TimeCreated"] as string ?? "").ToList();
            var lines = new List<string> { "TimeCreated,User,IPAddress,EventID,ServerName,Action" };

            foreach (var evt in sortedEvents)
            {
                lines.Add($"\"{evt["TimeCreated"]}\",\"{evt["User"]}\",\"{evt["IPAddress"]}\",\"{evt["EventID"]}\",\"{evt["ServerName"]}\",\"{evt["Action"]}\"");
            }

            File.WriteAllLines(outputPath, lines, System.Text.Encoding.UTF8);
        }

        private static void WriteXlsxReport(List<Dictionary<string, object>> eventsData, string outputPath)
        {
            var sortedEvents = eventsData.OrderBy(e => e["TimeCreated"] as string ?? "").ToList();

            using var workbook = new SpreadsheetDocument.Create(outputPath, SpreadsheetDocumentType.Workbook);
            var workbookPart = workbook.WorkbookPart ?? workbook.AddWorkbookPart();
            workbookPart.Workbook = new Workbook();

            var sheetPart = workbookPart.AddNewPart<WorksheetPart>();
            sheetPart.Worksheet = new Worksheet(new SheetData());

            var sheets = workbookPart.Workbook.AppendChild(new Sheets(new Sheet()
            {
                Id = workbookPart.GetIdOfPart(sheetPart),
                SheetId = 1,
                Name = "RDP Events"
            }));

            var sheetData = sheetPart.Worksheet.GetFirstChild<SheetData>();

            // Headers
            var headerRow = new Row(new Cell[]
            {
                NewCell("TimeCreated", 1),
                NewCell("User", 1),
                NewCell("IPAddress", 1),
                NewCell("EventID", 1),
                NewCell("ServerName", 1),
                NewCell("Action", 1)
            });
            sheetData.Append(headerRow);

            // Data rows
            uint rowIndex = 2;
            foreach (var evt in sortedEvents)
            {
                var row = new Row(new Cell[]
                {
                    NewCell(evt["TimeCreated"]?.ToString(), rowIndex),
                    NewCell(evt["User"]?.ToString(), rowIndex),
                    NewCell(evt["IPAddress"]?.ToString(), rowIndex),
                    NewCell(evt["EventID"]?.ToString(), rowIndex),
                    NewCell(evt["ServerName"]?.ToString(), rowIndex),
                    NewCell(evt["Action"]?.ToString(), rowIndex)
                });
                sheetData.Append(row);
                rowIndex++;
            }

            workbookPart.Workbook.Save();
            workbook.Close();

            // Note: Basic styling omitted for brevity; add OpenXML styles for headers/colors as in Python openpyxl
        }

        private static Cell NewCell(string text, uint row)
        {
            return new Cell()
            {
                CellValue = new CellValue(text),
                DataType = CellValues.InlineString,
                InlineString = new InlineString(new Text(text))
            };
        }
    }
}

