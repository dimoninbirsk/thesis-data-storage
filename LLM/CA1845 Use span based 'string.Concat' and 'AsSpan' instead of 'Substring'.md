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
public static Type CreateMRMType(MemberInfo propertyOrField)
        {
            Type entityType = propertyOrField.DeclaringType;

            Assembly assembly = entityType.GetAssembly();

            ModuleBuilder moduleBuilder;
            if (!_moduleBuilders.TryGetValue(assembly, out moduleBuilder))
            {
                lock (assembly)
                {
                    if (!_moduleBuilders.TryGetValue(assembly, out moduleBuilder))
                    {
                        var assemblyName = new AssemblyName(String.Format(CultureInfo.InvariantCulture, "ChloeMRMs-{0}", assembly.FullName));
                        assemblyName.Version = new Version(1, 0, 0, 0);

                        AssemblyBuilder assemblyBuilder;
                        assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
                        moduleBuilder = assemblyBuilder.DefineDynamicModule("ChloeMRMModule");

                        _moduleBuilders.Add(assembly, moduleBuilder);
                    }
                }
            }

            TypeAttributes typeAttributes = TypeAttributes.Class | TypeAttributes.NotPublic | TypeAttributes.Sealed;
            TypeBuilder tb = moduleBuilder.DefineType(string.Format("Chloe.Mapper.MRMs.{0}_{1}_{2}", entityType.Name, propertyOrField.Name, Guid.NewGuid().ToString("N").Substring(0, 5) + System.Threading.Interlocked.Increment(ref _sequenceNumber).ToString()), typeAttributes, null, new Type[] { typeof(IMRM) });

            tb.DefineDefaultConstructor(MethodAttributes.Public | MethodAttributes.SpecialName);

            MethodBuilder methodBuilder = tb.DefineMethod(nameof(IMRM.Map), MethodAttributes.Public | MethodAttributes.Virtual, CallingConventions.HasThis, typeof(void), new Type[] { typeof(object), typeof(System.Data.IDataReader), typeof(int) });

            ILGenerator il = methodBuilder.GetILGenerator();

            int parameStartIndex = 1;

            il.Emit(OpCodes.Ldarg_S, parameStartIndex);//将第一个参数 object 对象加载到栈顶
            il.Emit(OpCodes.Castclass, propertyOrField.DeclaringType);//将 object 对象转换为强类型对象 此时栈顶为强类型的对象

            var readerMethod = DataReaderConstant.GetReaderMethod(ReflectionExtension.GetMemberType(propertyOrField));

            //ordinal
            il.Emit(OpCodes.Ldarg_S, parameStartIndex + 1);    //加载参数DataReader
            il.Emit(OpCodes.Ldarg_S, parameStartIndex + 2);    //加载 read ordinal
            il.EmitCall(OpCodes.Call, readerMethod, null);     //调用对应的 readerMethod 得到 value  reader.Getxx(ordinal);  此时栈顶为 value

            EmitHelper.SetValueIL(il, propertyOrField); // object.XX = value; 此时栈顶为空

            il.Emit(OpCodes.Ret);   // 即可 return

            Type t = tb.CreateType();

            return t;
        }
```

# YandexGPT
```json
{
    "findings": [
        {
            "type": "Security",
            "problem": "Potential race condition in dynamic assembly creation",
            "severity": "High",
            "cwe": "CWE-669",
            "fix": "Replace lock(assembly) with dedicated static object:\nprivate static readonly object _assemblyLock = new object();\n...\nlock (_assemblyLock) { /* existing code */ }",
            "explanation": "Locking on an external object (assembly) can lead to unexpected locking behavior across different parts of the application"
        },
        {
            "type": "Security",
            "problem": "Dynamic assembly naming collision risk",
            "severity": "Medium",
            "cwe": "CWE-939",
            "fix": "Use more robust naming strategy:\nvar assemblyName = new AssemblyName(\"ChloeMRMs-\" + assembly.GetName().Name + \"-\" + Guid.NewGuid().ToString());",
            "explanation": "Current naming scheme may result in assembly name conflicts in complex environments"
        },
        {
            "type": "Smell",
            "problem": "Hardcoded version numbers in dynamic assemblies",
            "severity": "Medium",
            "cwe": null,
            "fix": "Use dynamic versioning:\nassemblyName.Version = AssemblyFileVersion.GetCurrentVersion();",
            "explanation": "Hardcoded version numbers make it difficult to manage assembly versions in production"
        },
        {
            "type": "Optimization",
            "problem": "Inefficient GUID substring usage",
            "severity": "Low",
            "cwe": null,
            "fix": "Use more efficient GUID generation:\nGuid.NewGuid().ToString(\"N\").Substring(0, 8)",
            "explanation": "Increasing substring length improves uniqueness while maintaining performance"
        },
        {
            "type": "Smell",
            "problem": "Magic number in parameter index",
            "severity": "Low",
            "cwe": null,
            "fix": "int parameterStartIndex = 1;\nconst int DataReaderIndex = parameterStartIndex + 1;\nconst int OrdinalIndex = parameterStartIndex + 2;",
            "explanation": "Using constants improves code readability and maintainability"
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
      "problem": "Potential thread-safety issue in lock usage",
      "severity": "High",
      "cwe": "CWE-833",
      "fix": "// Replace the lock on 'assembly' with a more granular locking mechanism\nlock (_moduleBuilders)\n{\n    if (!_moduleBuilders.TryGetValue(assembly, out moduleBuilder))\n    {\n        // existing logic...\n    }\n}",
      "explanation": "Locking on an external object ('assembly') can lead to deadlocks or race conditions."
    },
    {
      "type": "Optimization",
      "problem": "Inefficient GUID generation for class names",
      "severity": "Medium",
      "fix": "// Use a simpler naming strategy that avoids GUID generation\ntb.DefineType(string.Format(\"Chloe.Mapper.MRMs.{0}_{1}\", entityType.Name, propertyOrField.Name));",
      "explanation": "GUID generation is expensive; simplify the naming convention to improve performance."
    },
    {
      "type": "Security",
      "problem": "Unnecessary reflection usage increases attack surface",
      "severity": "Medium",
      "cwe": "CWE-749",
      "fix": "// Avoid using reflection where possible by pre-defining types\ntypeAttributes |= TypeAttributes.AutoClass;\ntb.DefineDefaultConstructor(MethodAttributes.Public);\n// Pre-generate methods during initialization rather than dynamically at runtime.",
      "explanation": "Reflection allows arbitrary code execution and should be minimized."
    },
    {
      "type": "Smell",
      "problem": "Hardcoded version number in dynamic assemblies",
      "severity": "Low",
      "fix": "// Dynamically set the version based on the current assembly's version\nvar currentVersion = assembly.GetName().Version;\nassemblyName.Version = new Version(currentVersion.Major, currentVersion.Minor, currentVersion.Build, currentVersion.Revision + 1);",
      "explanation": "Hardcoding versions may cause inconsistencies across deployments."
    }
  ]
}
```