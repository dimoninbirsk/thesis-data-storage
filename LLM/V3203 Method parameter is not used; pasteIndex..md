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
public static List<FrameInfo> Paste(string location, int index, int pasteIndex)

    {
        var newList = new List<FrameInfo>();
        //var recordingFolder = Path.GetDirectoryName(Items[index][0].Path);
        var recordingFolder = Path.GetDirectoryName(location);
 
        foreach (var frameInfo in Items[index])
        {
            //Changes the path of the image.
            var filename = GetUniqueFilename(recordingFolder, "P");
            //var filename = Path.Combine(recordingFolder, $"{pasteIndex} - {Path.GetFileNameWithoutExtension(frameInfo.Path)} {DateTime.Now:hh-mm-ss-ffff}.png");
 
            //Copy the image to the folder.
            File.Copy(frameInfo.Path, filename, true);

 
            //Create the new object and add to the list.
            newList.Add(new FrameInfo(filename, frameInfo.Delay, frameInfo.CursorX, frameInfo.CursorY, frameInfo.ButtonClicked, frameInfo.KeyList, frameInfo.Index));
        }
 
        return newList;
    }
```
# YandexGpt
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unsafe file path manipulation",
            "severity": "High",
            "cwe": "CWE-73: External Control of File Name or Path",
            "fix": "var safeRecordingFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, \"uploads\", Path.GetFileName(location));\nvar recordingFolder = Path.GetFullPath(safeRecordingFolder);",
            "explanation": "Direct use of user-provided paths can lead to path traversal attacks"
        },
        {
            "type": "Security",
            "problem": "Overwriting existing files without validation",
            "severity": "Medium",
            "cwe": "CWE-366: Use of Hard-coded Password",
            "fix": "if (File.Exists(filename))\n{\n    throw new IOException(\"File already exists\");\n}\nFile.Copy(frameInfo.Path, filename, false);",
            "explanation": "Allowing file overwrite can lead to unintended data loss"
        },
        {
            "type": "Smell",
            "problem": "Unused commented code",
            "severity": "Low",
            "cwe": null,
            "fix": "Remove commented lines",
            "explanation": "Dead code should be removed to prevent confusion"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient file naming logic",
            "severity": "Medium",
            "cwe": null,
            "fix": "var filename = Path.Combine(recordingFolder, $\"{pasteIndex:D4}-{Path.GetFileNameWithoutExtension(frameInfo.Path)}-{DateTime.Now:yyyyMMdd_HHmmssfff}.png\");",
            "explanation": "Using more structured naming improves file organization and searchability"
        },
        {
            "type": "Security",
            "problem": "Lack of input validation for parameters",
            "severity": "Medium",
            "cwe": "CWE-20: Improper Input Validation",
            "fix": "public static List<FrameInfo> Paste(string location, int index, int pasteIndex)\n{\n    if (string.IsNullOrEmpty(location))\n        throw new ArgumentException(\"Location cannot be null or empty\");\n    if (index < 0)\n        throw new ArgumentOutOfRangeException(nameof(index));\n    if (pasteIndex < 0)\n        throw new ArgumentOutOfRangeException(nameof(pasteIndex));",
            "explanation": "Missing validation can lead to unexpected behavior or errors"
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
      "problem": "Unsafe use of `File.Copy()` with overwrite enabled",
      "severity": "Medium",
      "cwe": "CWE-73",
      "fix": "Validate `filename` before copying files",
      "explanation": "Malicious filenames can overwrite critical system files."
    },
    {
      "type": "Smell",
      "problem": "Hardcoded prefix 'P' in unique filename generation",
      "severity": "Low",
      "cwe": "",
      "fix": "Parameterize or randomize filename prefix",
      "explanation": "Static prefixes reduce uniqueness and predictability."
    }
  ]
}
```
