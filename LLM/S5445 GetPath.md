# Target: 'Path.GetTempFileName()' is insecure. Use 'Path.GetRandomFileName()' instead.

**Role:** Senior .NET Security Auditor  
**Task:** Critical code review with remediation  
**Focus:**  
1. Security vulnerabilities (map to CWE)  
2. Code smells 
3. Bugs  
4. Performance optimizations

**Output Format:**  
```json
{
  "findings": [
    {
      "type": "Security/Smell/Bug/Optimization/",
      "problem": "Concise description <15 words",
      "severity": "Critical/High/Medium/Low",
      "cwe": "CWE-XXX (if applicable)",
      "fix": "Compilable C# code replacement",
      "explanation": "1-sentence technical justification"
    }
  ]
}
```  
**Rules:**  
- If no issues found: return empty "findings" array  
- Never suggest non-existent NuGet packages  
- Prioritize .NET best practices  
- Assume enterprise-scale deployment context

**Code**:
```cs
private async Task Download()
    {
        try
        {
            //Save to a temp folder.
            var temp = Path.Combine(Path.GetTempPath(), Path.GetTempFileName());
            var downloadUrl = GetDownloadUrl();

            if (string.IsNullOrWhiteSpace(downloadUrl))
            {
                StatusBand.Error("Download URL not provided...");
                return;
            }

            //Download.
            using (var client = new WebClient { Proxy = WebRequest.GetSystemWebProxy() })
            {
                client.DownloadProgressChanged += (_, args) =>
                {
                    TotalTextBlock.Text = LocalizationHelper.GetWithFormat("S.Downloader.Size", "{0} of {1}", Humanizer.BytesToString(args.BytesReceived), Humanizer.BytesToString(args.TotalBytesToReceive));
                    MainProgressBar.Value = args.ProgressPercentage;

                    if (_cancel)
                    {
                        client.CancelAsync();
                        Environment.Exit(35);
                    }
                };

                await client.DownloadFileTaskAsync(new Uri(downloadUrl), temp);
            }

            if (_cancel)
            {
                Environment.Exit(90);
                return;
            }

            //Decompress.
            using (var zip = ZipFile.Open(temp, ZipArchiveMode.Read))
            {
                switch (DownloadMode)
                {
                    case "gifski":
                    {
                        var entry = zip.Entries.FirstOrDefault(x => x.Name.Contains("gifski.dll"));

                        if (File.Exists(DestinationPath))
                            File.Delete(DestinationPath);

                        entry?.ExtractToFile(DestinationPath, true);
                        break;
                    }
                    case "ffmpeg":
                    {
                        var entry = zip.Entries.FirstOrDefault(x => x.Name.Contains("ffmpeg.exe"));

                        if (File.Exists(DestinationPath))
                            File.Delete(DestinationPath);

                        entry?.ExtractToFile(DestinationPath, true);
                        break;
                    }
                    case "sharpdx":
                    {
                        foreach (var entry in zip.Entries)
                        {
                            if (File.Exists(Path.Combine(DestinationPath, entry.Name)))
                                File.Delete(Path.Combine(DestinationPath, entry.Name));

                            entry?.ExtractToFile(Path.Combine(DestinationPath, entry.Name), true);
                        }

                        break;
                    }
                }
            }

            File.Delete(temp);
            Environment.Exit(10);
        }
        catch (Exception e)
        {
            LogWriter.Log(e, "Impossible to download");

            StatusBand.Error(e.Message);
            RetryButton.IsEnabled = true;
        }
    }
```

# Yandex
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unsafe temporary file creation",
            "severity": "High",
            "cwe": "CWE-377",
            "fix": "Use Path.GetRandomFileName() and specify full path manually",
            "explanation": "Path.GetTempFileName() can lead to predictable file names and security risks"
        },
        {
            "type": "Security",
            "problem": "Unsafe URL handling in WebClient",
            "severity": "High",
            "cwe": "CWE-89",
            "fix": "Validate downloadUrl against allowed schemes and patterns",
            "explanation": "Unvalidated URLs can lead to SSRF or other injection attacks"
        },
        {
            "type": "Security",
            "problem": "Unsafe file extraction",
            "severity": "Critical",
            "cwe": "CWE-426",
            "fix": "Add whitelist validation for extracted file names",
            "explanation": "Extracting arbitrary files can lead to path traversal attacks"
        },
        {
            "type": "Smell",
            "problem": "Repetitive file deletion logic",
            "severity": "Medium",
            "cwe": null,
            "fix": "Extract file deletion logic into a separate method",
            "explanation": "Duplicate code increases maintenance complexity"
        },
        {
            "type": "Bug",
            "problem": "Environment.Exit in non-main thread",
            "severity": "Critical",
            "cwe": "CWE-693",
            "fix": "Remove Environment.Exit and use proper cancellation mechanism",
            "explanation": "Calling Environment.Exit from non-main thread can crash application"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient progress reporting",
            "severity": "Medium",
            "cwe": null,
            "fix": "Use Dispatcher.Invoke for UI updates to avoid cross-thread exceptions",
            "explanation": "Direct UI updates from async callback can cause threading issues"
        },
        {
            "type": "Smell",
            "problem": "Switch case duplication",
            "severity": "Medium",
            "cwe": null,
            "fix": "Refactor extraction logic into separate methods",
            "explanation": "Duplicate extraction logic violates DRY principle"
        },
        {
            "type": "Security",
            "problem": "Unprotected file deletion",
            "severity": "Medium",
            "cwe": "CWE-732",
            "fix": "Add try-catch around File.Delete with proper error handling",
            "explanation": "File deletion can fail and leave temporary files"
        }
    ]
}
```

# GigaChat
```json
{
  "findings": [
    {
      "type": "Security",
      "problem": "Hardcoded proxy usage without user consent",
      "severity": "Medium",
      "cwe": "CWE-676",
      "fix": "// Remove hardcoding or prompt for user input\n// client.Proxy = WebRequest.GetSystemWebProxy();",
      "explanation": "Using system-wide proxies may expose sensitive data."
    },
    {
      "type": "Bug",
      "problem": "Inconsistent cancellation handling",
      "severity": "High",
      "cwe": "",
      "fix": "client.CancelAsync();\nawait Task.Delay(-1); // Wait until task is cancelled properly",
      "explanation": "Cancellation should be handled synchronously to avoid race conditions."
    },
    {
      "type": "Performance Optimization",
      "problem": "Unnecessary file deletion before extraction",
      "severity": "Low",
      "cwe": "",
      "fix": "// Remove pre-deletion logic\n// if (File.Exists(...))\n//     File.Delete(...);\nentry.ExtractToFile(...);",
      "explanation": "ZipFile.ExtractToFile automatically overwrites existing files."
    },
    {
      "type": "Security",
      "problem": "Directory traversal vulnerability",
      "severity": "Critical",
      "cwe": "CWE-22",
      "fix": "if (!Path.GetFullPath(entry.FullName).StartsWith(zip.FileName)) throw new Exception(\"Invalid path\");",
      "explanation": "Validate extracted paths to prevent directory traversal attacks."
    },
    {
      "type": "Bug",
      "problem": "Improper error logging and exit",
      "severity": "High",
      "cwe": "",
      "fix": "LogWriter.Log(e, \"Error downloading\", LogLevel.Error);\nEnvironment.Exit(1);",
      "explanation": "Properly log errors and use consistent exit codes."
    }
  ]
}
```