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
private static Lex LexText(QueryLexer lexer)
        {
            while(true)
            {
                (bool EOS, char ch) = lexer.Next();

                if (EOS) return LexEOS;

                // Escape character is '\'
                if (ch == '\\')
                {
                    lexer.EscapeCharacter();
                    continue;
                }

                if (ch == ':') return LexField;

                if (ch == '~')
                {
                    lexer.Backup();
                    if (lexer.Width > 0) lexer.Emit(LexemeType.Term);
                    return LexEditDistance;
                }

                if (ch == '^')
                {
                    lexer.Backup();
                    if (lexer.Width > 0) lexer.Emit(LexemeType.Term);
                    return LexBoost;
                }

                // "+" indicates term presence is required
                // checking for length to ensure that only
                // leading "+" are considered
                if (ch == '+' && lexer.Width == 1)
                {
                    lexer.Emit(LexemeType.Presence);
                    return LexText;
                }

                // "-" indicates term presence is prohibited
                // checking for length to ensure that only
                // leading "-" are considered
                if (ch == '-' && lexer.Width == 1)
                {
                    lexer.Emit(LexemeType.Presence);
                    return LexText;
                }

                if (ch.IsLunrSeparator())
                {
                    return LexTerm;
                }
            }
        }
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Potential infinite loop without exit condition",
            "severity": "Critical",
            "cwe": "CWE-835",
            "fix": "private static Lex LexText(QueryLexer lexer)\n{\n    int iterationCount = 0;\n    const int maxIterations = 1000;\n    \n    while (iterationCount < maxIterations)\n    {\n        iterationCount++;\n        (bool EOS, char ch) = lexer.Next();\n        \n        if (EOS) return LexEOS;\n        \n        // остальной код без изменений\n    }\n    \n    throw new Exception(\"Lexer processing exceeded maximum iterations\");\n}",
            "explanation": "Infinite loops can lead to denial of service attacks and system instability"
        },
        {
            "type": "Smell",
            "problem": "Repetitive code for presence operators",
            "severity": "Medium",
            "cwe": null,
            "fix": "private static Lex LexText(QueryLexer lexer)\n{\n    // ... existing code\n    \n    if (lexer.Width == 1 && (ch == '+' || ch == '-'))\n    {\n        lexer.Emit(LexemeType.Presence);\n        return LexText;\n    }\n    \n    // ... remaining code\n}",
            "explanation": "Duplicate logic for handling '+' and '-' operators can be consolidated"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient multiple method calls in loop",
            "severity": "Medium",
            "cwe": null,
            "fix": "private static Lex LexText(QueryLexer lexer)\n{\n    while (true)\n    {\n        (bool EOS, char ch) = lexer.Next();\n        \n        if (EOS) return LexEOS;\n        \n        if (ch == '\\')\n        {\n            lexer.EscapeCharacter();\n            continue;\n        }\n        \n        bool widthCheck = lexer.Width > 0;\n        \n        if (ch == '~')\n        {\n            lexer.Backup();\n            if (widthCheck) lexer.Emit(LexemeType.Term);\n            return LexEditDistance;\n        }\n        \n        // аналогичный подход для других проверок width\n    }\n}",
            "explanation": "Caching repeated property access improves performance and reduces method call overhead"
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
      "problem": "Potential logic flaw in token parsing",
      "severity": "Medium",
      "cwe": "CWE-787",
      "fix": "// Revised handling of separator check\nif (char.IsWhiteSpace(ch)) { return LexTerm; }",
      "explanation": "Improves robustness by explicitly checking whitespace as separators."
    },
    {
      "type": "Performance Optimization",
      "problem": "Inefficient string operations",
      "severity": "Medium",
      "cwe": "",
      "fix": "// Avoid multiple calls to `Width`\nvar width = lexer.Width;\nif (ch == '+' && width == 1)\n{\n   lexer.Emit(LexemeType.Presence);\n   return LexText;\n}",
      "explanation": "Reduces redundant method invocations improving performance."
    },
    {
      "type": "Smell",
      "problem": "Excessive use of `continue`",
      "severity": "Low",
      "cwe": "",
      "fix": "// Refactor loop structure for clarity\nwhile (!EOS)\n{\n   switch (ch)\n   {\n       case '\\': lexer.EscapeCharacter(); break;\n       case ':': return LexField;\n       default: /* process other cases */ break;\n   }\n}",
      "explanation": "Enhances readability through structured control flow."
    }
  ]
}
```