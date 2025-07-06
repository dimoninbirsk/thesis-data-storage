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
public override void Dispose()
        {
            try
            {
                if (this.PersistedReader != null)
                    this.PersistedReader.Dispose();
            }
            finally
            {
                this.ReleaseLock();
            }

            GC.SuppressFinalize(this);
        }
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Smell",
            "problem": "Incorrect Dispose pattern implementation",
            "severity": "High",
            "cwe": null,
            "fix": "Implement IDisposable pattern correctly with virtual Dispose(bool disposing)",
            "explanation": "Missing proper disposable pattern can lead to resource leaks"
        },
        {
            "type": "Smell",
            "problem": "Unnecessary GC.SuppressFinalize",
            "severity": "Medium",
            "cwe": null,
            "fix": "Remove GC.SuppressFinalize unless finalizer is implemented",
            "explanation": "SuppressFinalize should only be called if class has a finalizer"
        },
        {
            "type": "Smell",
            "problem": "Try-finally without exception handling",
            "severity": "Medium",
            "cwe": null,
            "fix": "Simplify to single finally block if no exception handling needed",
            "explanation": "Try block without exception handling is unnecessary and confusing"
        },
        {
            "type": "Optimization",
            "problem": "Missing dispose pattern safeguards",
            "severity": "Medium",
            "cwe": null,
            "fix": "Add bool disposing parameter and check for disposed state",
            "explanation": "Proper dispose pattern prevents multiple disposal issues"
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
      "problem": "Potential resource leak in exception scenario.",
      "severity": "High",
      "cwe": "CWE-401",
      "fix": "try { PersistedReader?.Dispose(); } catch {} finally { ReleaseLock(); }",
      "explanation": "Ensures lock release even if dispose fails."
    },
    {
      "type": "Code Smell",
      "problem": "Unnecessary suppression of finalization.",
      "severity": "Low",
      "cwe": "",
      "fix": "// Remove call to GC.SuppressFinalize",
      "explanation": "Modern .NET manages finalizers automatically."
    }
  ]
}
```