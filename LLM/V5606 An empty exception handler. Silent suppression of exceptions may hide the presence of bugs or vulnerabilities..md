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
public static void AddCookies(this CookieContainer cookieContainer, Uri uri, IEnumerable<string> cookiesHeader) {
        foreach (var header in cookiesHeader) {
            try {
                cookieContainer.SetCookies(uri, header);
            }
            catch (CookieException) {
                // Do not fail request if we cannot parse a cookie
            }
        }
    }

```
# YandexGpt:

```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unhandled CookieException can lead to security risks",
            "severity": "High",
            "cwe": "CWE-707: Improper Handling of Exceptional Conditions",
            "fix": "public static void AddCookies(this CookieContainer cookieContainer, Uri uri, IEnumerable<string> cookiesHeader)\n{\n    foreach (var header in cookiesHeader)\n    {\n        try\n        {\n            cookieContainer.SetCookies(uri, header);\n        }\n        catch (CookieException ex)\n        {\n            // Log the exception with details\n            Log.Error(\"Failed to parse cookie: \" + header, ex);\n        }\n    }\n}",
            "explanation": "Silent exception handling can mask malicious cookie injection attempts"
        },
        {
            "type": "Security",
            "problem": "No validation of input cookie headers",
            "severity": "High",
            "cWE": "CWE-862: Missing Input Validation",
            "fix": "public static void AddCookies(this CookieContainer cookieContainer, Uri uri, IEnumerable<string> cookiesHeader)\n{\n    foreach (var header in cookiesHeader)\n    {\n        if (string.IsNullOrEmpty(header) || !IsValidCookieHeader(header))\n        {\n            continue;\n        }\n        try\n        {\n            cookieContainer.SetCookies(uri, header);\n        }\n        catch (CookieException ex)\n        {\n            Log.Error(\"Failed to parse cookie: \" + header, ex);\n        }\n    }\n}\n\nprivate static bool IsValidCookieHeader(string header)\n{\n    // Add proper validation logic here\n    return !header.Contains(';') && !header.Contains(',');\n}",
            "explanation": "Untrusted cookie headers can lead to security vulnerabilities"
        },
        {
            "type": "Smell",
            "problem": "Lack of parameter validation",
            "severity": "Medium",
            "cwe": "CWE-259: Use of Hard-coded Password",
            "fix": "public static void AddCookies(this CookieContainer cookieContainer, Uri uri, IEnumerable<string> cookiesHeader)\n{\n    if (cookieContainer == null) throw new ArgumentNullException(nameof(cookieContainer));\n    if (uri == null) throw new ArgumentNullException(nameof(uri));\n    if (cookiesHeader == null) throw new ArgumentNullException(nameof(cookiesHeader));\n    \n    foreach (var header in cookiesHeader)\n    {\n        // existing logic\n    }\n}",
            "explanation": "Null checks prevent runtime exceptions and improve code robustness"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient exception handling in loop",
            "severity": "Medium",
            "cwe": null,
            "fix": "public static void AddCookies(this CookieContainer cookieContainer, Uri uri, IEnumerable<string> cookiesHeader)\n{\n    foreach (var header in cookiesHeader)\n    {\n        if (ValidateCookieHeader(header))\n        {\n            cookieContainer.SetCookies(uri, header);\n        }\n    }\n}\n\nprivate static bool ValidateCookieHeader(string header)\n{\n    try\n    {\n        // Perform validation checks\n        return true;\n    }\n    catch (CookieException ex)\n    {\n        Log.Error(\"Failed to parse cookie: \" + header, ex);\n        return false;\n    }\n}",
            "explanation": "Avoiding exceptions in loops improves performance in high-throughput scenarios"
        }
    ]
}

```


# GigaChat:

```json
{
  "findings": [
    {
      "type": "Security",
      "problem": "Swallowing exceptions hides security-relevant errors",
      "severity": "High",
      "cwe": "CWE-754",
      "fix": "Log exception details or propagate error",
      "explanation": "Silent failure prevents detection of potential attacks via malformed cookies."
    }
  ]
}
```