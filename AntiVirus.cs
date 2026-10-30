using System;
using System.IO;
using System.Collections.Generic;

class Scanner
{
    static void Main()
    {
        while (true)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.SetCursorPosition(0, 0);
            Console.WriteLine("---------------");
            Console.SetCursorPosition(0, 1);
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
            Console.WriteLine("[5] Leave");

            Console.SetCursorPosition(0, 9);
            string choice = Console.ReadLine();

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

                    if (ContainsSuspiciousKeywords(filePath))
                    {
                        suspicionLevel++;
                    }

                    if (HasStrangeStructureOrAnomalies(filePath))
                    {
                        suspicionLevel++;
                    }

                    if (suspicionLevel > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Suspicious file found: " + filePath);
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
    }

    static void ExecuteCustomScan()
    {
        Console.Clear();
    }
    static void LookForSpecificFiles()
    {
        Console.Clear();
    }


    static bool ContainsSuspiciousKeywords(string filePath)
    {
        string fileName = Path.GetFileName(filePath).ToLower();


        return fileName.Contains("powershell")
            || fileName.Contains("cmd.exe")
            || fileName.Contains("AutoOpen")
            || fileName.Contains("vba")
            || fileName.Contains("shell")
            || fileName.Contains("exec")
            || fileName.Contains("http")
            || fileName.Contains("macro")
            || fileName.Contains(".7z")
            || fileName.Contains(".chm")
            || fileName.Contains(".hta")
            || fileName.Contains(".crypto")
            || fileName.Contains(".locked");
    }

    static bool HasStrangeStructureOrAnomalies(string filePath)
    {
        FileInfo fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > 2000000000000)
            {
            return true;
        }
        return false;
    }
}