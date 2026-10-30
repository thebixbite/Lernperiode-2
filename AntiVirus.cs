using System;
using System.IO;
using System.Collections.Generic;

class AntiVirus
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
            Console.WriteLine("ANTI-VIRUS");
            Console.SetCursorPosition(0, 2);
            Console.WriteLine("---------------");

            Console.SetCursorPosition(0, 4);
            Console.WriteLine("[1] Quick Scan");
            Console.SetCursorPosition(0, 5);
            Console.WriteLine("[2] Full Scan");
            Console.SetCursorPosition(0, 6);
            Console.WriteLine("[3] Custom Scan");
            Console.SetCursorPosition(0, 7);
            Console.WriteLine("[4] Leave");

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
                break;
            }
        }
    }
    static void ExecuteQuickScan()
    {

        Console.Clear();

        List<string> criticalFiles = new List<string>
        {
        Environment.GetFolderPath(Environment.SpecialFolder.System),

        Path.GetTempPath(),

        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),

        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),

        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),

        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        foreach (string file in criticalFiles)
        {
            if (Directory.Exists(file))
            {
                Console.WriteLine($"Scanning {file}...");
                System.Threading.Thread.Sleep(500);
            }

            int suspicionLevel = 0;
        string[] filePath = Directory.GetFiles(file);

        if (ContainsSuspiciousKeywords(filePath)) suspicionLevel++;
        if (HasStrangeStructureOrAnomalies(file)) suspicionLevel++;

        if (suspicionLevel > 0)
            { 
                Console.WriteLine("Suspicious files found in " + file);
            }
        else 
            {
                Console.WriteLine("No suspicious files found");
            }
        try
            {
                System.UnauthorizedAccessException;
            }
        catch (Exception)
            {
                Console.WriteLine("Skipping unauthorized files");

            }
    }
    static void ExecuteFullScan()
    {
        Console.Clear();
    }
    static void ExecuteCustomScan()
    {
        Console.Clear();
    }
}
}