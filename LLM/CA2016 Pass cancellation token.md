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
public override IFeatureEnumerator<T> GetFeatureEnumerator(CancellationToken cancellationToken = default)
        {
            ShardingQueryContext queryContext = new ShardingQueryContext(this._query.DbContextProvider);
            ShardingQueryStateBase queryState = ShardingQueryExpressionResolver.Resolve(queryContext, this._query.QueryExpression);

            IFeatureEnumerable<object> queryEnumerable = queryState.CreateQuery();

            var enumerator = queryEnumerable.Select(a => (T)a).GetFeatureEnumerator();

            return enumerator;
        }
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unsafe casting without type checking",
            "severity": "High",
            "cwe": "CWE-843",
            "fix": "public override IFeatureEnumerator<T> GetFeatureEnumerator(CancellationToken cancellationToken = default)\n{\n    ShardingQueryContext queryContext = new ShardingQueryContext(this._query.DbContextProvider);\n    ShardingQueryStateBase queryState = ShardingQueryExpressionResolver.Resolve(queryContext, this._query.QueryExpression);\n\n    IFeatureEnumerable<object> queryEnumerable = queryState.CreateQuery();\n\n    var enumerator = queryEnumerable\n        .OfType<T>()\n        .GetFeatureEnumerator();\n\n    return enumerator;\n}",
            "explanation": "Unsafe casting can lead to runtime exceptions and potential type confusion attacks"
        },
        {
            "type": "Smell",
            "problem": "Lack of null checks for query results",
            "severity": "Medium",
            "cwe": "CWE-476",
            "fix": "public override IFeatureEnumerator<T> GetFeatureEnumerator(CancellationToken cancellationToken = default)\n{\n    if (this._query == null)\n        throw new ArgumentNullException(nameof(this._query));\n\n    ShardingQueryContext queryContext = new ShardingQueryContext(this._query.DbContextProvider);\n    ShardingQueryStateBase queryState = ShardingQueryExpressionResolver.Resolve(queryContext, this._query.QueryExpression);\n\n    if (queryState == null)\n        throw new InvalidOperationException(\"Query state resolution failed\");\n\n    IFeatureEnumerable<object> queryEnumerable = queryState.CreateQuery();\n\n    if (queryEnumerable == null)\n        throw new InvalidOperationException(\"Query enumerable creation failed\");\n\n    var enumerator = queryEnumerable.OfType<T>().GetFeatureEnumerator();\n    return enumerator;\n}",
            "explanation": "Null checks prevent potential null reference exceptions in production"
        },
        {
            "type": "Optimization",
            "problem": "Missing cancellation token usage",
            "severity": "Medium",
            "cwe": "CWE-399",
            "fix": "public override IFeatureEnumerator<T> GetFeatureEnumerator(CancellationToken cancellationToken = default)\n{\n    if (cancellationToken.IsCancellationRequested)\n        throw new OperationCanceledException(cancellationToken);\n\n    ShardingQueryContext queryContext = new ShardingQueryContext(this._query.DbContextProvider);\n    ShardingQueryStateBase queryState = ShardingQueryExpressionResolver.Resolve(queryContext, this._query.QueryExpression);\n\n    IFeatureEnumerable<object> queryEnumerable = queryState.CreateQuery();\n\n    var enumerator = queryEnumerable\n        .OfType<T>()\n        .Where(_ => !cancellationToken.IsCancellationRequested)\n        .GetFeatureEnumerator();\n\n    return enumerator;\n}",
            "explanation": "Proper cancellation token handling improves system responsiveness and stability"
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
      "problem": "Unvalidated input may lead to injection attacks",
      "severity": "High",
      "cwe": "CWE-89",
      "fix": "// Validate inputs before executing queries\nShardingQueryStateBase queryState = ShardingQueryExpressionResolver.ValidateAndResolve(queryContext, this._query.QueryExpression);",
      "explanation": "Ensures proper sanitization preventing SQL injection."
    },
    {
      "type": "Performance Optimization",
      "problem": "Casting can degrade performance",
      "severity": "Medium",
      "cwe": "",
      "fix": "// Use generic casting instead of boxing/unboxing\nIFeatureEnumerable<T> queryEnumerable = queryState.CreateTypedQuery<T>();",
      "explanation": "Avoids unnecessary casts enhancing runtime efficiency."
    },
    {
      "type": "Smell",
      "problem": "Complex method chaining decreases maintainability",
      "severity": "Low",
      "cwe": "",
      "fix": "// Break down complex chain into simpler steps\nvar intermediateResult = queryEnumerable.Select(a => (T)a);\nreturn intermediateResult.GetFeatureEnumerator();",
      "explanation": "Simplifies the method increasing future maintainability."
    }
  ]
}
```
