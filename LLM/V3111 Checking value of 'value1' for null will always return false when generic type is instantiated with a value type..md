
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
public static IQuery<TSource> WhereIfNotNull<TSource, V>(this IQuery<TSource> source, V val, Expression<Func<TSource, V, bool>> predicate)
        {
            if (val != null)
            {
                Expression<Func<TSource, bool>> newPredicate = (Expression<Func<TSource, bool>>)ParameterTwoExpressionReplacer.Replace(predicate, val);
                source = source.Where(newPredicate);
            }
 
            return source;
        }
```

# YandexGpt

```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Null-conditional operator misuse in hash computation",
            "severity": "Medium",
            "cwe": "CWE-570: Expression Evaluation Without Proper Sanitization",
            "fix": "uint hc1 = (uint)(value1?.GetHashCode() ?? throw new ArgumentNullException(nameof(value1)));\nuint hc2 = (uint)(value2?.GetHashCode() ?? throw new ArgumentNullException(nameof(value2)));",
            "explanation": "Returning 0 for null values can lead to hash collisions and potential security issues"
        },
        {
            "type": "Smell",
            "problem": "Magic numbers in hash computation",
            "severity": "Medium",
            "cwe": null,
            "fix": "private const int HashOffset = 8;\n...\nhash += HashOffset;",
            "explanation": "Using constants instead of magic numbers improves code readability and maintainability"
        },
        {
            "type": "Optimization",
            "problem": "Lack of generic constraint for GetHashCode",
            "severity": "Medium",
            "cwe": null,
            "fix": "public static int Combine<T1, T2>(T1 value1, T2 value2)\n    where T1 : class\n    where T2 : class",
            "explanation": "Adding constraints prevents unnecessary boxing and potential runtime errors"
        },
        {
            "type": "Smell",
            "problem": "Unclear method purpose and behavior",
            "severity": "Low",
            "cwe": null,
            "fix": "/// <summary>\n/// Combines two values into a single hash code using custom hashing algorithm.\n/// </summary>\n/// <typeparam name=\"T1\">First value type</typeparam>\n/// <typeparam name=\"T2\">Second value type</typeparam>\n/// <param name=\"value1\">First value</param>\n/// <param name=\"value2\">Second value</param>\n/// <returns>Combined hash code</returns>\npublic static int Combine<T1, T2>(T1 value1, T2 value2)",
            "explanation": "Proper documentation improves code maintainability and understanding"
        }
    ]
}
```


# GigaChat:

```json
{
  "findings": []
}
```

