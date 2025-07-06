# Target: Complete the task associated to this 'TODO' comment.

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
public void RenderText(Batcher batch, ReadOnlySpan<char> text, Vector2 position, Vector2 justify, Color color)
	{
		var at = position + new Vector2(0, Ascent);
		var last = 0;

		if (justify.X != 0)
			at.X -= justify.X * WidthOfLine(text);

		if (justify.Y != 0)
			at.Y -= justify.Y * HeightOf(text);
		
		// TODO:
		// this is incorrect, this should only happen if the font is a pixel font.
		// (otherwise using matrices and so on will not play nicely with this)
		at.X = Calc.Round(at.X);
		at.Y = Calc.Round(at.Y);

		// apply changes that we have so far that may have been generated off-thread
		if (WaitForPendingCharacters)
			PrepareCharacters(text, true);
		else
			BlitApplyChanges();

		for (int i = 0; i < text.Length; i++)
		{
			if (text[i] == '\n')
			{
				at.X = position.X;
				if (justify.X != 0 && i < text.Length - 1)
					at.X -= justify.X * WidthOfLine(text[(i + 1)..]);
				at.Y += LineHeight;
				last = 0;
				continue;
			}

			if (TryGetCharacter(text, i, out var ch, out var step))
			{
				if (last != 0)
					at.X += GetKerning(last, ch.Codepoint);

				if (ch.Subtexture.Texture != null)
					batch.Image(ch.Subtexture, at + ch.Offset, color);

				last = ch.Codepoint;
				at.X += ch.Advance;
				i += step - 1;
			}
		}
	}
```

# Yandex
```json
{
    "findings": [
        {
            "type": "Optimization",
            "problem": "Repeated calculation of WidthOfLine in loop",
            "severity": "Medium",
            "cwe": null,
            "fix": "var remainingText = text[(i + 1)..];\nif (justify.X != 0 && i < text.Length - 1)\nat.X -= justify.X * WidthOfLine(remainingText);",
            "explanation": "Caching the slice operation avoids recalculating the span multiple times"
        },
        {
            "type": "Smell",
            "problem": "Magic numbers in rounding operation",
            "severity": "Low",
            "cwe": null,
            "fix": "const float JUSTIFY_ROUNDING_FACTOR = 0.5f;\nat.X = Calc.Round(at.X * JUSTIFY_ROUNDING_FACTOR);\nat.Y = Calc.Round(at.Y * JUSTIFY_ROUNDING_FACTOR);",
            "explanation": "Using constants improves code readability and maintainability"
        },
        {
            "type": "Optimization",
            "problem": "Conditional checks in critical path",
            "severity": "Medium",
            "cwe": null,
            "fix": "bool shouldPrepare = WaitForPendingCharacters;\nif (shouldPrepare)\n    PrepareCharacters(text, true);\nelse\n    BlitApplyChanges();",
            "explanation": "Avoiding repeated property access improves performance in tight loops"
        },
        {
            "type": "Smell",
            "problem": "Complex conditional logic in loop",
            "severity": "Medium",
            "cwe": null,
            "fix": "bool shouldAdjustX = justify.X != 0 && i < text.Length - 1;\nif (shouldAdjustX)\nat.X -= justify.X * WidthOfLine(text[(i + 1)..]);",
            "explanation": "Breaking down complex conditions improves code readability"
        },
        {
            "type": "Optimization",
            "problem": "Multiple property accesses in loop",
            "severity": "Medium",
            "cwe": null,
            "fix": "if (TryGetCharacter(text, i, out var ch, out var step))\n{\n    float kern = GetKerning(last, ch.Codepoint);\n    at.X += kern;\n    \n    if (ch.Subtexture.Texture != null)\n        batch.Image(ch.Subtexture, at + ch.Offset, color);\n    \n    last = ch.Codepoint;\n    at.X += ch.Advance;\n    i += step - 1;\n}",
            "explanation": "Caching property values reduces overhead in performance-critical loop"
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
      "problem": "Hardcoded wait condition introduces race conditions.",
      "severity": "High",
      "cwe": "CWE-833",
      "fix": "// Apply thread synchronization or remove hardcoding\nlock(_pendingCharactersLock)\n{\n\tPrepareCharacters(text, true);\n}",
      "explanation": "Thread-safety issue leading to potential data corruption."
    },
    {
      "type": "Performance Optimization",
      "problem": "Redundant string slicing impacts performance.",
      "severity": "Medium",
      "cwe": "",
      "fix": "var nextLineStartIndex = i + 1;\nif (nextLineStartIndex < text.Length)\n{\n\tvar remainingText = text[nextLineStartIndex..];\n}",
      "explanation": "Avoids unnecessary memory allocations by caching slice index."
    },
    {
      "type": "Code Smell",
      "problem": "Magic numbers reduce readability.",
      "severity": "Low",
      "cwe": "",
      "fix": "const int offsetFactor = 1;\nat.X += GetKerning(last, ch.Codepoint) * offsetFactor;",
      "explanation": "Improves clarity through named constants."
    }
  ]
}
```