V3022 Expression 'Text.Length == 10' is always false.

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
protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        base.OnPreviewKeyDown(e);
 
        #region Navigation or selection
 
        if (e.Key == Key.Enter || e.Key == Key.Return || e.Key == Key.Tab || e.Key == Key.Left || e.Key == Key.Right || e.Key == Key.Escape || e.Key == Key.Home || e.Key == Key.End)

        {
            e.Handled = false;
            return;
        }
 
        #endregion
 
        if (IsReadOnly)
        {
            e.Handled = true;
            return;
        }
 
        #region Remove
 
        if (e.Key == Key.Back || e.Key == Key.Delete)
        {
            if (SelectionLength == Text.Length || Text.Length == 1 && (SelectionStart == 0 && e.Key == Key.Delete || SelectionStart == 1 && e.Key == Key.Back))
            {
                Text = "";
                RaiseEvent(new RoutedEventArgs(TextChangedEvent));
                UpdateSource();
            }
 
            e.Handled = false;
            return;
        }
 
        #endregion
 
        #region Colon (:) and period (.)
 
        if ((e.Key == Key.OemQuestion || e.Key == Key.OemPeriod) && (Keyboard.Modifiers & ModifierKeys.Control) == 0)
        {
            var separatorSelected = Text.Substring(SelectionStart, SelectionLength).Contains(":") || Text.Substring(SelectionStart, SelectionLength).Contains(".");
 
            //Let it add a separator if in the right position.
            if (SelectionStart == 2 || SelectionStart == 5 && DisplaySeconds || SelectionStart == 8 || separatorSelected)

            {
                e.Handled = false;
                return;
            }
 
            if (Text.Length > 8)
            {
                e.Handled = true;
                return;
            }
 
            #region Adds the hour, minute, second and millisecond
 
            //1 --> 01:
            //0 --> 01:
            if (Text.Length == 1)
                Text = "0" + (Text.Equals("0") ? "1" : Text) + ":";
 
            //01:2 --> 01:02:
            //01:0 --> 01:01:
            else if (Text.Length == 4)
                Text = Text.Substring(0, 3) + "0" + (Text.Substring(3, 1).Equals("0") ? "1" : Text.Substring(3, 1)) + (DisplaySeconds ? ":" : "");
 
            //01:02:5 --> 01:02:05
            //01:02:0 --> 01:02:00
            else if (Text.Length == 7)
                Text = Text.Substring(0, 6) + "0" + Text.Substring(6, 1);
 
            //01:02:03.5 --> 01:02:03.005
            //01:02:03.0 --> 01:02:03.000
            else if (Text.Length == 10)
↑ V3022 Expression 'Text.Length == 10' is always false.

                Text = Text.Substring(0, 9) + Text.Substring(6, 1).PadLeft(3, '0');
 
            #endregion
 
            SelectionStart = Text.Length;
            e.Handled = true;
            return;
        }
 
        #endregion
 
        #region Numeric
 
        if (e.Key >= Key.D0 && e.Key <= Key.D9 || e.Key >= Key.NumPad0 && e.Key <= Key.NumPad9)
        {
            //01
            if (Text.Length - SelectionLength == 2)
            {
                Text = Text + ":";
                Select(Text.Length, 0);
            }
 
            //01:02
            if (Text.Length - SelectionLength == 5 && DisplaySeconds)
            {
                Text = Text + ":";
                Select(Text.Length, 0);
            }
 
            //01:02:03
            if (Text.Length - SelectionLength == 8 && DisplayMilliseconds)
            {
                Text = Text + ".";
                Select(Text.Length, 0);
            }
 
            e.Handled = false;
            return;
        }
 
        #endregion
 
        #region Value Navigation
 
        if (Keyboard.Modifiers == ModifierKeys.Control)
        {
            //System's actions. Ignore.
            if (e.Key == Key.A || e.Key == Key.X || e.Key == Key.C || e.Key == Key.V)
            {
                e.Handled = false;
                return;
            }
 
            //Now or maximum.
            if (e.Key == Key.OemSemicolon || e.Key == Key.Oem2)
            {
                //Text = DateTime.Now.TimeOfDay.ToString(Format);
                Selected = Maximum ?? DateTime.Now.TimeOfDay;
                SelectAll();
                return;
            }
 
            //Increase or decrease.
            if (e.Key == Key.OemComma || e.Key == Key.Decimal)
            {
                Change(Selected, -1, TimeSpan.FromMinutes(1));
 
                //Text = string.IsNullOrWhiteSpace(Text) ? DateTime.Now.TimeOfDay.ToString(Format) : Text;
 
                ////Previous minute.
                //if (TimeSpan.TryParse(Text, out var aux))
                //{
                //    if (aux - TimeSpan.FromMinutes(1) < (Minimum ?? TimeSpan.Zero)) //Deal with milliseconds...
                //    {
                //        aux = Maximum ?? new TimeSpan(0, 23, 59, 59, 999);
                //        Text = aux.ToString(Format);
                //    }
                //    else
                //        Text = aux.Add(TimeSpan.FromMinutes(-1)).ToString(Format);
                //}
            }
            else if (e.Key == Key.OemPeriod)
            {
                Change(Selected, 1, TimeSpan.FromMinutes(1));
 
                //Text = string.IsNullOrWhiteSpace(Text) ? DateTime.Now.TimeOfDay.ToString(Format) : Text;
 
                ////Next minute.
                //if (TimeSpan.TryParse(Text, out var aux))
                //{
                //    if (aux + TimeSpan.FromMinutes(1) > (Maximum ?? new TimeSpan(0, 23, 59, 59, 999))) //Deal with milliseconds...
                //    {
                //        aux = Minimum ?? TimeSpan.Zero;
                //        Text = aux.ToString(Format);
                //    }
                //    else
                //        Text = aux.Add(TimeSpan.FromMinutes(1)).ToString(Format);
                //}
            }
 
            //UpdateSource();
        }
 
        #endregion
    }
```
# YandexGpt
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Insecure handling of special keys without validation",
            "severity": "Medium",
            "cwe": "CWE-862",
            "fix": "if (e.Key == Key.Enter || e.Key == Key.Return || e.Key == Key.Tab || e.Key == Key.Left || e.Key == Key.Right || e.Key == Key.Escape || e.Key == Key.Home || e.Key == Key.End) {\n    e.Handled = true; // Changed to true for security\n    return;\n}",
            "explanation": "Unhandled keys can lead to unintended navigation or selection manipulation"
        },
        {
            "type": "Smell",
            "problem": "Redundant substring operations in condition",
            "severity": "Low",
            "cwe": null,
            "fix": "var selectedText = Text.Substring(SelectionStart, SelectionLength);\nvar separatorSelected = selectedText.Contains(':') || selectedText.Contains('.');",
            "explanation": "Duplicate substring calls can be optimized by storing result in variable"
        },
        {
            "type": "Optimization",
            "problem": "Repetitive string manipulation logic",
            "severity": "Medium",
            "cwe": null,
            "fix": "string UpdateTextWithSeparator()\n{\n    switch (Text.Length)\n    {\n        case 1:\n            return \"0\" + (Text.Equals(\"0\") ? \"1\" : Text) + \":\";\n        case 4:\n            return Text.Substring(0, 3) + \"0\" + (Text[3] == '0' ? \"1\" : Text[3].ToString()) + (DisplaySeconds ? \":\" : \"\");\n        case 7:\n            return Text.Substring(0, 6) + \"0\" + Text[6];\n        case 10:\n            return Text.Substring(0, 9) + Text[6].ToString().PadLeft(3, '0');\n        default:\n            return Text;\n    }\n}",
            "explanation": "Refactoring repetitive string logic into a reusable method improves maintainability"
        },
        {
            "type": "Smell",
            "problem": "Complex conditional logic for backspace/delete",
            "severity": "Medium",
            "cwe": null,
            "fix": "if (e.Key == Key.Back || e.Key == Key.Delete)\n{\n    if (ShouldClearText())\n    {\n        Text = \"\";\n        RaiseEvent(new RoutedEventArgs(TextChangedEvent));\n        UpdateSource();\n    }\n    e.Handled = false;\n    return;\n}\n\nprivate bool ShouldClearText()\n{\n    return SelectionLength == Text.Length ||\n           (Text.Length == 1 &&\n            ((SelectionStart == 0 && e.Key == Key.Delete) ||\n             (SelectionStart == 1 && e.Key == Key.Back)));\n}",
            "explanation": "Extracting complex condition into a method improves readability"
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
      "problem": "Improper Input Validation",
      "severity": "High",
      "cwe": "CWE-20",
      "fix": "// Validate input before processing\nif (!Regex.IsMatch(e.Key.ToString(), \"^[a-zA-Z0-9]+$\"))\n{\ne.Handled = true;\nreturn;\n}",
      "explanation": "Input validation prevents injection attacks."
    },
    {
      "type": "Performance Optimization",
      "problem": "Inefficient String Manipulation",
      "severity": "Medium",
      "cwe": "",
      "fix": "// Use StringBuilder for efficient string manipulation\nvar sb = new StringBuilder();\nsb.Append(\"0\");\nif (Text.Equals(\"0\"))\n{\nsb.Append(\"1\");\n}\nelsb.Append(Text);",
      "explanation": "StringBuilder reduces memory allocations during concatenation."
    },
    {
      "type": "Code Smell",
      "problem": "Magic Numbers",
      "severity": "Low",
      "cwe": "",
      "fix": "// Define constants for magic numbers\nconst int MAX_LENGTH = 8;\nif (Text.Length > MAX_LENGTH)\n{\ne.Handled = true;\nreturn;\n}",
      "explanation": "Constants improve readability and maintainability."
    }
  ]
}
```
