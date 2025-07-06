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
private void Step(TimeSpan delta)
{
    Time = Time.Advance(delta);
    // warp mouse to center of the window if Relative Mode is enabled
    if (SDL_GetWindowRelativeMouseMode(Window.Handle) && Window.Focused)
        SDL_WarpMouseInWindow(Window.Handle, Window.Width / 2, Window.Height / 2);
    inputProvider.Update(Time);
    PollEvents();
    FramePool.NextFrame();

    while (mainThreadQueue.TryDequeue(out var action))
        action.Invoke();

    Update();
}
```
# YandexGpt
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Potential integer division without validation",
            "severity": "Medium",
            "cwe": "CWE-682",
            "fix": "SDL_WarpMouseInWindow(Window.Handle, Window.Width / 2, Window.Height / 2);",
            "explanation": "Integer division by zero possible if Window.Width/Height are zero"
        },
        {
            "type": "Smell",
            "problem": "Unclear method name 'Update'",
            "severity": "Low",
            "cwe": null,
            "fix": "UpdateGameState()",
            "explanation": "Method name should clearly describe its purpose"
        },
        {
            "type": "Optimization",
            "problem": "Uncached event polling",
            "severity": "Medium",
            "cwe": null,
            "fix": "void Step(TimeSpan delta)\n{\n    Time = Time.Advance(delta);\n    \n    if (SDL_GetWindowRelativeMouseMode(Window.Handle) && Window.Focused)\n        SDL_WarpMouseInWindow(Window.Handle, Window.Width / 2, Window.Height / 2);\n\n    inputProvider.Update(Time);\n    var events = PollEvents(); // Cache result\n    FramePool.NextFrame();\n\n    while (mainThreadQueue.TryDequeue(out var action))\n        action.Invoke();\n\n    Update();\n}",
            "explanation": "Caching event polling result can improve performance"
        },
        {
            "type": "Smell",
            "problem": "No null checks for Window properties",
            "severity": "Medium",
            "cwe": "CWE-476",
            "fix": "if (Window != null && SDL_GetWindowRelativeMouseMode(Window.Handle) && Window.Focused)\n    SDL_WarpMouseInWindow(Window.Handle, Window.Width / 2, Window.Height / 2);",
            "explanation": "Null checks should be performed to prevent potential null reference exceptions"
        }
    ]
}

```

# GigaChat
```json
{
  "findings": []
}
```
