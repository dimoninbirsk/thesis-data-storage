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
public static ObjectMemberMapper GetInstance(Type type)
        {
            ObjectMemberMapper instance;
            if (!InstanceCache.TryGetValue(type, out instance))
            {
                lock (type)
                {
                    if (!InstanceCache.TryGetValue(type, out instance))
                    {
                        instance = new ObjectMemberMapper(type);
                        InstanceCache.GetOrAdd(type, instance);
                    }
                }
            }

            return instance;
        }
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Locking on user-supplied type object",
            "severity": "High",
            "cwe": "CWE-666",
            "fix": "private static readonly object _lock = new object();\n\npublic static ObjectMemberMapper GetInstance(Type type)\n{\n    ObjectMemberMapper instance;\n    if (!InstanceCache.TryGetValue(type, out instance))\n    {\n        lock (_lock)\n        {\n            if (!InstanceCache.TryGetValue(type, out instance))\n            {\n                instance = new ObjectMemberMapper(type);\n                InstanceCache.GetOrAdd(type, instance);\n            }\n        }\n    }\n    return instance;\n}",
            "explanation": "Locking on a user-supplied object can lead to deadlocks and security vulnerabilities"
        },
        {
            "type": "Smell",
            "problem": "Incorrect double-check locking pattern",
            "severity": "Medium",
            "cwe": "CWE-669",
            "fix": "private static readonly object _lock = new object();\nprivate static readonly ConcurrentDictionary<Type, ObjectMemberMapper> InstanceCache = new ConcurrentDictionary<Type, ObjectMemberMapper>();\n\npublic static ObjectMemberMapper GetInstance(Type type)\n{\n    return InstanceCache.GetOrAdd(type, t => new ObjectMemberMapper(t));\n}",
            "explanation": "Using ConcurrentDictionary simplifies thread-safe lazy initialization"
        },
        {
            "type": "Smell",
            "problem": "Unclear cache initialization",
            "severity": "Low",
            "cwe": null,
            "fix": "private static readonly ConcurrentDictionary<Type, ObjectMemberMapper> InstanceCache = new ConcurrentDictionary<Type, ObjectMemberMapper>();\n\npublic static ObjectMemberMapper GetInstance(Type type)\n{\n    return InstanceCache.GetOrAdd(type, t => new ObjectMemberMapper(t));\n}",
            "explanation": "Explicitly initializing cache as ConcurrentDictionary improves code clarity and safety"
        },
        {
            "type": "Optimization",
            "problem": "Redundant method calls in double-check",
            "severity": "Low",
            "cwe": null,
            "fix": "private static readonly ConcurrentDictionary<Type, ObjectMemberMapper> InstanceCache = new ConcurrentDictionary<Type, ObjectMemberMapper>();\n\npublic static ObjectMemberMapper GetInstance(Type type)\n{\n    return InstanceCache.GetOrAdd(type, t => new ObjectMemberMapper(t));\n}",
            "explanation": "ConcurrentDictionary eliminates need for manual double-check pattern"
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
      "problem": "Synchronization on mutable object",
      "severity": "High",
      "cwe": "CWE-833",
      "fix": "Use private static readonly object as synchronization primitive instead of locking on Type object.",
      "explanation": "Locking on public objects may cause deadlocks or synchronization issues across threads."
    },
    {
      "type": "Smell",
      "problem": "Double-check locking anti-pattern",
      "severity": "Medium",
      "fix": "Remove inner null check after acquiring lock since ConcurrentDictionary ensures thread safety.",
      "explanation": "ConcurrentDictionary already handles concurrent access safely, making double checking redundant."
    },
    {
      "type": "Optimization",
      "problem": "Inefficient cache update mechanism",
      "severity": "Medium",
      "fix": "Replace `TryGetValue + GetOrAdd` pattern with direct `GetOrAdd` call.",
      "explanation": "Simplifies caching logic and reduces unnecessary operations."
    }
  ]
}
```