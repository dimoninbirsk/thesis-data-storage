# Target: Return 'Task' instead.

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
private async void SeekInDirectStream(int sampleOffset)
{
    try
    {
        if (_decoder == null || _stream == null) return;
        if (!CanSeek || !_contentLength.HasValue || Length <= 0) return;

        var timeProportion = (float)sampleOffset / Length;
        var targetByteOffset = (long)(timeProportion * _contentLength.Value);
        targetByteOffset = Math.Max(0, targetByteOffset);
        targetByteOffset = Math.Min(targetByteOffset, _contentLength.Value - 1);


        if (sampleOffset < _samplePosition) // Backward Seek
        {
            _stream.Seek(targetByteOffset, SeekOrigin.Begin);
            _decoder.Seek(sampleOffset);
            _samplePosition = sampleOffset;
            _audioBuffer.Clear();
            PositionChanged?.Invoke(this, new PositionChangedEventArgs(_samplePosition));
        }
        else // Forward Seek (or same position)
        {
            if (targetByteOffset >= _stream.Length)
            {
                var currentStreamLength = _stream.Length;
                var endByteToFetch = Math.Min(targetByteOffset + 1024 * 1024,
                    _contentLength.GetValueOrDefault(long.MaxValue) - 1);
                if (endByteToFetch < currentStreamLength) endByteToFetch = currentStreamLength + (1024 * 1024);

                using (var rangeRequest = new HttpRequestMessage(HttpMethod.Get, _url))
                {
                    rangeRequest.Headers.Range = new RangeHeaderValue(currentStreamLength, endByteToFetch);

                    using (var rangeResponse = await _httpClient.SendAsync(rangeRequest, HttpCompletionOption.ResponseContentRead))
                    {
                        rangeResponse.EnsureSuccessStatusCode();
                        await using (var contentStream = await rangeResponse.Content.ReadAsStreamAsync())
                        {
                            await contentStream.CopyToAsync(_stream);
                        }
                    }
                }

                _stream.Position = targetByteOffset;
                _decoder.Seek(sampleOffset);
                _samplePosition = sampleOffset;
                _audioBuffer.Clear();
                PositionChanged?.Invoke(this, new PositionChangedEventArgs(_samplePosition));
            }
            else // Forward seek within current stream (or backward seek, if the condition is not met)
            {
                _stream.Seek(targetByteOffset, SeekOrigin.Begin);
                _decoder.Seek(sampleOffset);
                _samplePosition = sampleOffset;
                _audioBuffer.Clear();
                PositionChanged?.Invoke(this, new PositionChangedEventArgs(_samplePosition));
            }
        }

        _ = Task.Run(() => BufferDirectStreamAsync(CancellationToken.None));
    }
    catch
    {
        _isEndOfStream = true;
        Monitor.PulseAll(_lock);
    }
}
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Unhandled exceptions in async void method",
            "severity": "Critical",
            "cwe": "CWE-754",
            "fix": "Change method signature to async Task and handle exceptions properly",
            "explanation": "Async void methods can hide exceptions and cause unhandled exception termination"
        },
        {
            "type": "Security",
            "problem": "Potential HTTP header injection via RangeHeaderValue",
            "severity": "High",
            "cwe": "CWE-113",
            "fix": "Validate and sanitize input values before constructing RangeHeaderValue",
            "explanation": "User-controlled input for HTTP headers can lead to injection attacks"
        },
        {
            "type": "Smell",
            "problem": "Complex nested conditional logic",
            "severity": "Medium",
            "cwe": null,
            "fix": "Refactor into separate methods for backward and forward seek operations",
            "explanation": "Reduces cognitive complexity and improves code maintainability"
        },
        {
            "type": "Optimization",
            "problem": "Unnecessary Task.Run usage",
            "severity": "Medium",
            "cwe": null,
            "fix": "Remove Task.Run and use ConfigureAwait(false) if needed",
            "explanation": "Avoids thread pool overhead for non-blocking operations"
        },
        {
            "type": "Smell",
            "problem": "Magic number used for buffer size",
            "severity": "Low",
            "cwe": null,
            "fix": "Replace 1024 * 1024 with constant const int BUFFER_SIZE_MB = 1024 * 1024;",
            "explanation": "Improves code readability and maintainability"
        },
        {
            "type": "Security",
            "problem": "Null checks in multiple places",
            "severity": "Medium",
            "cwe": "CWE-754",
            "fix": "Add null checks at method entry and throw ArgumentNullException",
            "explanation": "Centralized null checks improve code consistency and safety"
        }
    ]
}
```
GigaChat
```json
{
  "findings": [
    {
      "type": "Security",
      "problem": "Unchecked exception leads to silent failure",
      "severity": "High",
      "cwe": "CWE-703",
      "fix": "_ = Task.Run(async () => { try { await BufferDirectStreamAsync(CancellationToken.None); } catch(Exception ex) { LogError(ex); } });",
      "explanation": "General exceptions should be logged or handled explicitly."
    },
    {
      "type": "Smell",
      "problem": "Inefficient memory allocation in large streams",
      "severity": "Medium",
      "cwe": "",
      "fix": "endByteToFetch = Math.Min(endByteToFetch, _contentLength.GetValueOrDefault() - 1);",
      "explanation": "Avoids unnecessary buffer overflow when fetching data from a very long stream."
    },
    {
      "type": "Optimization",
      "problem": "Suboptimal HTTP request header usage",
      "severity": "Medium",
      "cwe": "",
      "fix": "rangeRequest.Headers.Range = new RangeHeaderValue(currentStreamLength, Math.Min(endByteToFetch, _contentLength.GetValueOrDefault()));",
      "explanation": "Improves performance by reducing excessive network traffic."
    },
    {
      "type": "Security",
      "problem": "Potential deadlock on Monitor.PulseAll",
      "severity": "High",
      "cwe": "CWE-833",
      "fix": "Monitor.Exit(_lock); Monitor.Enter(_lock); Monitor.PulseAll(_lock);",
      "explanation": "Ensures correct synchronization and avoids potential deadlocks."
    }
  ]
}
```