using System;
using System.IO;
using System.Collections.Generic;
using System.Windows.Forms;

class Program
{
    [STAThread]
    static void Main()
    {
        while (true)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.SetCursorPosition(0, 0);
            Console.WriteLine("---------------");
            Console.SetCursorPosition(4, 1);
            Console.WriteLine("SCANNER");
            Console.SetCursorPosition(0, 2);
            Console.WriteLine("---------------");

            Console.SetCursorPosition(0, 4);
            Console.WriteLine("[1] Quick Scan");
            Console.SetCursorPosition(0, 5);
            Console.WriteLine("[2] Full Scan");
            Console.SetCursorPosition(0, 6);
            Console.WriteLine("[3] Custom Scan");
            Console.SetCursorPosition(0, 7);
            Console.WriteLine("[4] Look for specific files");
            Console.SetCursorPosition(0, 8);
            Console.WriteLine("[5] Information");
            Console.SetCursorPosition(0, 9);
            Console.WriteLine("[6] Exit");

            Console.SetCursorPosition(0, 10);
            string choice = Console.ReadLine() ?? string.Empty;

            if (choice == "1")
            {
                ExecuteQuickScan();
            }
            else if (choice == "2")
            {
                ExecuteFullScan();
            }
            else if (choice == "3")
            {
                ExecuteCustomScan();
            }
            else if (choice == "4")
            {
                LookForSpecificFiles();
            }
            else if (choice == "5")
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("This scanner is designed to detect suspicious files and potential threats on your system.");
                Console.WriteLine("It scans folders for files that may contain malicious content or exhibit unusual behavior.");
                Console.WriteLine("This scanner only checks file metadata and does not inspect file contents.")
                Console.WriteLine("Please note that this is just a scanner and every suspicious file does not mean that it is a malware.");
                Console.WriteLine("Always verify the files before taking any action.");
                Console.WriteLine("Yellow meaans low risk and red means high risk.");
                Console.SetCursorPosition(0, 7);
                Console.WriteLine("Press any key to return to the main menu...");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.ReadKey();
            }

            else if (choice == "6")
            {
                break;
            }
        }
    }

    static void ExecuteQuickScan()
    {
        Console.Clear();

        List<string> criticalFolders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        foreach (string folder in criticalFolders)
        {
            if (!Directory.Exists(folder))
            {
                continue;
            }

            Console.WriteLine($"Scanning {folder}...");
            System.Threading.Thread.Sleep(500);

            try
            {
                string[] filePaths = Directory.GetFiles(folder);

                foreach (string filePath in filePaths)
                {
                    int suspicionLevel = 0;

                    suspicionLevel += ContainsSuspiciousKeywords(filePath);


                    if (HasStrangeStructureOrAnomalies(filePath))
                    {
                        suspicionLevel++;
                    }

                    if (doubleExtension(filePath))
                    {
                        suspicionLevel += 2;
                    }

                    if (suspicionLevel == 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Suspicious file found: " + filePath);
                        Console.ForegroundColor = ConsoleColor.Blue;
                    }
                    else if (suspicionLevel > 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Highly suspicious file found: " + filePath);
                        Console.ForegroundColor = ConsoleColor.Blue;
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Skipping unauthorized folder: " + folder);
            }
            catch (IOException)
            {
                Console.WriteLine(
                    "Skipping unavailable folder: " + folder);
            }
        }
        Console.WriteLine("Scan completed.");
        Console.WriteLine("Press any key to return to the main menu...");
        Console.ReadKey();
    }

    static void ExecuteFullScan()
    {
        Console.Clear();
        List<string> criticalFolders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            Environment.GetFolderPath(Environment.SpecialFolder.PrinterShortcuts),
        };

        foreach (string folder in criticalFolders)
        {
            if (!Directory.Exists(folder))
            {
                continue;
            }

            Console.WriteLine($"Scanning {folder}...");
            System.Threading.Thread.Sleep(500);

            try
            {
                string[] filePaths = Directory.GetFiles(folder);

                foreach (string filePath in filePaths)
                {
                    int suspicionLevel = 0;

                    suspicionLevel += ContainsSuspiciousKeywords(filePath);

                    if (HasStrangeStructureOrAnomalies(filePath))
                    {
                        suspicionLevel++;
                    }

                    if (doubleExtension(filePath))
                    {
                        suspicionLevel += 2;
                    }

                    if (suspicionLevel == 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Suspicious file found: " + filePath);
                        Console.ForegroundColor = ConsoleColor.Blue;
                    }
                    if (suspicionLevel > 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Highly suspicious file found: " + filePath);
                        Console.ForegroundColor = ConsoleColor.Blue;
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Skipping unauthorized folder: " + folder);
            }
            catch (IOException)
            {
                Console.WriteLine(
                    "Skipping unavailable folder: " + folder);
            }
        }
        Console.WriteLine("Scan completed.");
        Console.WriteLine("Press any key to return to the main menu...");
        Console.ReadKey();
    }

    static void ExecuteCustomScan()
    {
        Console.Clear();

        using (var dialog = new FolderBrowserDialog())
        {
            DialogResult result = dialog.ShowDialog();
            if (result == DialogResult.OK && !string.IsNullOrEmpty(dialog.SelectedPath))
            {
                string selectedFolder = dialog.SelectedPath;
                if (Directory.Exists(selectedFolder))
                {
                    Console.WriteLine($"Scanning {selectedFolder}...");
                    System.Threading.Thread.Sleep(500);

                    try
                    {
                        string[] filePaths = Directory.GetFiles(selectedFolder);

                        foreach (string filePath in filePaths)
                        {
                            int suspicionLevel = 0;

                            suspicionLevel += ContainsSuspiciousKeywords(filePath);                         
                            

                            if (HasStrangeStructureOrAnomalies(filePath))
                            {
                                suspicionLevel++;
                            }

                            if (doubleExtension(filePath))
                            {
                                suspicionLevel+= 2;
                            }

                            if (suspicionLevel == 1)
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine("Suspicious file found: " + filePath);
                                Console.ForegroundColor = ConsoleColor.Blue;
                            }
                            else if (suspicionLevel > 1)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Highly suspicious file found: " + filePath);
                                Console.ForegroundColor = ConsoleColor.Blue;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("Skipping unauthorized folder: " + selectedFolder);
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("Skipping unavailable folder: " + selectedFolder);
                    }
                }
            }
        }
        Console.WriteLine("Scan completed.");
        Console.WriteLine("Press any key to return to the main menu...");
        Console.ReadKey();
    }


    static void LookForSpecificFiles()
    {
        Console.Clear();
        Console.WriteLine("Enter or drag the file to scan: ");
        string filePath = Console.ReadLine() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(filePath))
        {
            Console.WriteLine("No file entered. Press any key to return to the main menu...");
            Console.ReadKey();
            return;
        }
        else if (!File.Exists(filePath))
        {
            Console.WriteLine("File does not exist. Press any key to return to the main menu...");
            Console.ReadKey();
            return;
        }

        int suspicionLevel = 0;

        suspicionLevel += ContainsSuspiciousKeywords(filePath);

        if (HasStrangeStructureOrAnomalies(filePath))
           {
             suspicionLevel++;
        }
        if (doubleExtension(filePath))
        {
            suspicionLevel += 2;
        }
        Console.WriteLine("Scan completed.");
        Console.WriteLine("Press any key to return to the main menu...");
        Console.ReadKey();
    }


    static int ContainsSuspiciousKeywords(string filePath)
    {
        string fileName = Path.GetFileName(filePath).ToLower();

         if (fileName.Contains("http", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".crypto", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".locked", StringComparison.OrdinalIgnoreCase))
         {
            return 2;
         }

         if (fileName.Contains("AutoOpen", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("vba", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("shell", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("exec", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("macro", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".7z", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".chm", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains(".hta", StringComparison.OrdinalIgnoreCase))
         {
            return 1;
         }

         return 0;
    }

    static bool HasStrangeStructureOrAnomalies(string filePath)
    {
        FileInfo fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > 100000000000)
            {
            return true;
        }
        return false;
    }

    static bool doubleExtension(string filePath)
    {
            string fileName = Path.GetFileName(filePath);

            return fileName.EndsWith(".pdf.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".doc.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".docx.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".jpg.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".png.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".txt.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".zip.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".pdf.scr", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".jpg.scr", StringComparison.OrdinalIgnoreCase);
    }
}

