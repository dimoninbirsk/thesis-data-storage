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
public static async Task Run(params string[] args)
    {
        var uciChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(100) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        var engineChannel = Channel.CreateBounded<object>(new BoundedChannelOptions(2 * Configuration.EngineSettings.MaxDepth) { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.DropOldest });
 
        using CancellationTokenSource source = new();
        CancellationToken cancellationToken = source.Token;
 
        var searcher = new Searcher(uciChannel, engineChannel);
        var uciHandler = new UCIHandler(uciChannel, engineChannel, searcher);
        var writer = new Writer(engineChannel);
        var listener = new Listener(uciHandler);
 
        var tasks = new List<Task>
        {
            Task.Run(() => writer.Run(cancellationToken)),
            Task.Run(() => searcher.Run(cancellationToken)),
            Task.Run(() => listener.Run(cancellationToken, args)),
            uciChannel.Reader.Completion,
            engineChannel.Reader.Completion
        };
 
        try
        {
            Console.WriteLine($"{IdCommand.EngineName} {IdCommand.GetLynxVersion()} by {IdCommand.EngineAuthor}");
            await Task.WhenAny(tasks);
        }
        catch (AggregateException ae)
        {
            foreach (var e in ae.InnerExceptions)
            {
                if (e is TaskCanceledException taskCanceledException)
                {
                    Console.WriteLine("Cancellation requested exception: {0}", taskCanceledException.Message);

                    _logger.Fatal(ae, "Cancellation requested exception: {0}", taskCanceledException.Message);
                }
                else
                {
                    Console.WriteLine("Exception {0}: {1}", e.GetType().Name, e.Message);

                    _logger.Fatal(ae, "Exception {0}: {1}", e.GetType().Name, e.Message);
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Unexpected exception");
            Console.WriteLine(e.Message);

 
            _logger.Fatal(e, "Unexpected exception: {Exception}", e.Message);
        }
        finally
        {
            engineChannel.Writer.TryComplete();
            uciChannel.Writer.TryComplete();
            //source.Cancel();
            LogManager.Shutdown(); // Flush and close down internal threads and timers
        }
    }
```
# YandexGpt

```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unvalidated channel size configuration",
            "severity": "Medium",
            "cwe": "CWE-770: Missing Size Constraint for a Resource",
            "fix": "var engineChannel = Channel.CreateBounded<object>(new BoundedChannelOptions(Math.Min(2 * Configuration.EngineSettings.MaxDepth, 1000)) { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.DropOldest });",
            "explanation": "Dynamic configuration values should be validated to prevent resource exhaustion attacks"
        },
        {
            "type": "Smell",
            "problem": "Unclear task list composition",
            "severity": "Low",
            "cwe": null,
            "fix": "var tasks = new List<Task>\n{\n    Task.Run(() => writer.Run(cancellationToken)),\n    Task.Run(() => searcher.Run(cancellationToken)),\n    Task.Run(() => listener.Run(cancellationToken, args)),\n    Task.FromResult(uciChannel.Reader.Completion),\n    Task.FromResult(engineChannel.Reader.Completion)\n};",
            "explanation": "Mixing different task types in a single list can lead to confusion and maintenance issues"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient exception handling",
            "severity": "Medium",
            "cwe": "CWE-704: Incorrect Damage Assessment",
            "fix": "try\n{\n    Console.WriteLine($\"{IdCommand.EngineName} {IdCommand.GetLynxVersion()} by {IdCommand.EngineAuthor}\");\n    await Task.WhenAll(tasks);\n}\ncatch (Exception e)\n{\n    _logger.Fatal(e, \"Unhandled exception: {Exception}\", e.Message);\n    Console.WriteLine(\"Unexpected exception: {0}\", e.Message);\n}\nfinally\n{\n    // cleanup\n}",
            "explanation": "Using Task.WhenAll and unified exception logging improves error handling and performance"
        },
        {
            "type": "Smell",
            "problem": "Unnecessary commented code",
            "severity": "Low",
            "cwe": null,
            "fix": "Remove commented line: //source.Cancel();",
            "explanation": "Dead code should be removed to prevent confusion and maintenance overhead"
        }
    ]
}

```

# GigaChat
```json
{
  "findings": [
    {
      "type": "Smell",
      "problem": "Logger used inconsistently across exception types",
      "severity": "Medium",
      "cwe": "",
      "fix": "Consolidate logging approach",
      "explanation": "Inconsistent logging makes debugging harder."
    },
    {
      "type": "Optimization",
      "problem": "Channels closed without ensuring all readers have finished",
      "severity": "Medium",
      "cwe": "",
      "fix": "Synchronize channel completions properly",
      "explanation": "Incomplete synchronization could lead to lost messages or data corruption."
    }
  ]
}
```