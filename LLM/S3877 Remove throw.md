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
public void Dispose()
	{
		if (Disposed)
			return;
		if (Running)
			throw new Exception("Cannot dispose App while running");

		GC.SuppressFinalize(this);
		Disposed = true;

		GraphicsDevice.Shutdown();
		Window.Close();
		GraphicsDevice.DestroyDevice();
		inputProvider.Dispose();
		mainThreadQueue.Clear();

		SDL_Quit();
	}
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Exception message contains sensitive runtime state",
            "severity": "Medium",
            "cwe": "CWE-209",
            "fix": "throw new InvalidOperationException(\"App must be stopped before disposal\");",
            "explanation": "Leaking runtime state in exception messages can expose application internals to attackers"
        },
        {
            "type": "Smell",
            "problem": "Missing IDisposable pattern implementation",
            "severity": "High",
            "cwe": "CWE-590",
            "fix": "public class YourClass : IDisposable\n{\n    private bool _disposed = false;\n\n    public void Dispose()\n    {\n        Dispose(true);\n        GC.SuppressFinalize(this);\n    }\n\n    protected virtual void Dispose(bool disposing)\n    {\n        if (_disposed)\n            return;\n\n        if (disposing)\n        {\n            // Dispose managed resources\n        }\n\n        // Dispose unmanaged resources\n        _disposed = true;\n    }\n}",
            "explanation": "Proper IDisposable pattern ensures correct resource disposal in all scenarios"
        },
        {
            "type": "Smell",
            "problem": "No check for null references before disposal",
            "severity": "Medium",
            "cwe": "CWE-476",
            "fix": "if (inputProvider != null)\n    inputProvider.Dispose();",
            "explanation": "Null reference exceptions can occur if referenced objects are null"
        },
        {
            "type": "Optimization",
            "problem": "Unnecessary method calls after shutdown",
            "severity": "Low",
            "cwe": null,
            "fix": "public void Dispose()\n{\n    if (Disposed)\n        return;\n    if (Running)\n        throw new InvalidOperationException(\"App must be stopped before disposal\");\n\n    GC.SuppressFinalize(this);\n    Disposed = true;\n\n    Window.Close();\n    GraphicsDevice.Shutdown();\n    inputProvider?.Dispose();\n    mainThreadQueue.Clear();\n    GraphicsDevice.DestroyDevice();\n    SDL_Quit();\n}",
            "explanation": "Reordering method calls can prevent unnecessary operations on already shutdown components"
        }
    ]
}


# GigaChat
```json
{
  "findings": [
    {
      "type": "Security",
      "problem": "Unchecked exception thrown in Dispose method",
      "severity": "High",
      "cwe": "CWE-703",
      "fix": "Replace `throw new Exception` with a more specific exception type or handle the condition gracefully.",
      "explanation": "Throwing general exceptions can lead to unexpected application crashes."
    },
    {
      "type": "Performance Optimization",
      "problem": "Inefficient use of GC.SuppressFinalize",
      "severity": "Medium",
      "fix": "Call `GC.SuppressFinalize(this)` only if finalizer is implemented.",
      "explanation": "Suppressing finalization when not needed adds unnecessary overhead."
    },
    {
      "type": "Smell",
      "problem": "Direct calls to unmanaged resources cleanup",
      "severity": "Medium",
      "fix": "Encapsulate resource disposal logic into dedicated methods for better separation of concerns.",
      "explanation": "Improves maintainability by isolating resource management from business logic."
    }
  ]
}
```