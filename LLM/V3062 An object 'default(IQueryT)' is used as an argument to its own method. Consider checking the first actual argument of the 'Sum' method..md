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
public async Task<int?> SumAsync(Expression<Func<T, int>> selector)
        {
            return await this.ExecuteAggregateQueryAsync<int?>(GetCalledMethod(() => default(IQuery<T>).Sum(default(Expression<Func<T, int>>))), selector);
        }

```


# YandexGpt

```json
{
    "findings": [
        {
            "type": "Smell",
            "problem": "Complex method call with reflection",
            "severity": "Medium",
            "cwe": null,
            "fix": "public async Task<int?> SumAsync(Expression<Func<T, int>> selector)\n{\n    return await this.ExecuteAggregateQueryAsync<int?>(\n        Expression.Call(\n            typeof(Queryable),\n            nameof(Queryable.Sum),\n            new[] { typeof(T) },\n            this.Queryable,\n            selector\n        ));\n}",
            "explanation": "Using direct expression construction improves code readability and maintainability"
        },
        {
            "type": "Smell",
            "problem": "Unclear method purpose in reflection call",
            "severity": "Low",
            "cwe": null,
            "fix": "private static MethodInfo SumMethodInfo = GetCalledMethod(() => default(IQuery<T>).Sum(default(Expression<Func<T, int>>)));\n\npublic async Task<int?> SumAsync(Expression<Func<T, int>> selector)\n{\n    return await this.ExecuteAggregateQueryAsync<int?>(SumMethodInfo, selector);\n}",
            "explanation": "Extracting reflection call to static field reduces overhead and improves clarity"
        },
        {
            "type": "Optimization",
            "problem": "Potential performance overhead in reflection",
            "severity": "Medium",
            "cwe": null,
            "fix": "private static readonly MethodInfo SumMethod = typeof(Queryable).GetMethod(nameof(Queryable.Sum), new[] { typeof(Expression<Func<T, int>>) });\n\npublic async Task<int?> SumAsync(Expression<Func<T, int>> selector)\n{\n    return await this.ExecuteAggregateQueryAsync<int?>(SumMethod, selector);\n}",
            "explanation": "Caching reflection results improves performance in high-throughput scenarios"
        },
        {
            "type": "Smell",
            "problem": "Lack of parameter validation",
            "severity": "Medium",
            "cwe": "CWE-295: Improper Certification of a Security Procedure",
            "fix": "public async Task<int?> SumAsync(Expression<Func<T, int>> selector)\n{\n    if (selector == null)\n        throw new ArgumentNullException(nameof(selector));\n    \n    return await this.ExecuteAggregateQueryAsync<int?>(\n        GetCalledMethod(() => default(IQuery<T>).Sum(default(Expression<Func<T, int>>))),\n        selector);\n}",
            "explanation": "Null checks prevent runtime exceptions and improve code robustness"
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