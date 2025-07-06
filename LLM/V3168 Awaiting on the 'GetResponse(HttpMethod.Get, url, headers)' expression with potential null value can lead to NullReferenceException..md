```
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

**Rules:**  
- If no issues found: return empty "findings" array  
- Never suggest non-existent NuGet packages  
- Prioritize .NET best practices  
- Assume enterprise-scale deployment context

**Code**:
```

# YandexGpt:
```
{
    "findings": [
        {
            "type": "Security",
            "problem": "Missing validation for HTTP response status codes",
            "severity": "High",
            "cwe": "CWE-754",
            "fix": "public static async Task<string> Get(string url, NameValueCollection headers = null)\n{\n    using (var webResponse = await GetResponse(HttpMethod.Get, url, headers))\n    {\n        if (webResponse.StatusCode != HttpStatusCode.OK)\n            throw new HttpRequestException(\"Unexpected response status code: \" + webResponse.StatusCode);\n\n        await using (var responseStream = webResponse.GetResponseStream())\n        {\n            if (responseStream == null)\n                return null;\n\n            using (var reader = new StreamReader(responseStream, Encoding.UTF8))\n                return await reader.ReadToEndAsync();\n        }\n    }\n}",
            "explanation": "Failure to check response status codes can lead to processing unexpected or malicious responses"
        },
        {
            "type": "Security",
            "problem": "Potential SSRF vulnerability",
            "severity": "Critical",
            "cwe": "CWE-918",
            "fix": "public static async Task<string> Get(string url, NameValueCollection headers = null)\n{\n    if (!IsValidUrl(url))\n        throw new ArgumentException(\"Invalid URL provided\");\n\n    using (var webResponse = await GetResponse(HttpMethod.Get, url, headers))\n    {\n        // existing code\n    }\n\n    private static bool IsValidUrl(string url)\n    {\n        var uri = new Uri(url);\n        return uri.IsWellFormedUriString(UriKind.Absolute) &&\n               uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;\n    }",
            "explanation": "Unvalidated URL input can be exploited for server-side request forgery attacks"
        },
        {
            "type": "Smell",
            "problem": "Null return on null response stream",
            "severity": "Medium",
            "cwe": null,
            "fix": "public static async Task<string> Get(string url, NameValueCollection headers = null)\n{\n    // existing code\n    if (responseStream == null)\n        throw new InvalidOperationException(\"Response stream is null\");\n    // existing code\n}",
            "explanation": "Returning null can lead to NullReferenceExceptions in calling code"
        },
        {
            "type": "Optimization",
            "problem": "Synchronous encoding detection in async method",
            "severity": "Low",
            "cwe": null,
            "fix": "public static async Task<string> Get(string url, NameValueCollection headers = null)\n{\n    // existing code\n    using (var reader = new StreamReader(responseStream))\n        return await reader.ReadToEndAsync();\n    // existing code\n}",
            "explanation": "Removing hardcoded UTF8 encoding allows automatic detection from response headers"
        }
    ]
}

```

# GigaChat:
```
{
  "findings": [
    {
      "type": "Security",
      "problem": "No validation of URL parameter",
      "severity": "High",
      "cwe": "CWE-918",
      "fix": "Add validation for `url` parameter",
      "explanation": "Unvalidated URLs allow SSRF attacks."
    },
    {
      "type": "Smell",
      "problem": "Null returned instead of throwing exception",
      "severity": "Medium",
      "cwe": "",
      "fix": "Throw informative exception when stream is null",
      "explanation": "Returning null obscures root cause of failures."
    }
  ]
}
```