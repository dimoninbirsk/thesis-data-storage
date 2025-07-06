$thesisRoot = "C:\Users\dimoninbirsk\source\thesis"
$solutionDir = Get-Location
$solutionName = (Get-Item $solutionDir).Name
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$reportRoot = Join-Path $thesisRoot "package_reports"
$solutionReportDir = Join-Path $reportRoot $solutionName
$timestampedReportDir = Join-Path $solutionReportDir $timestamp

New-Item -ItemType Directory -Path $timestampedReportDir -Force | Out-Null

$packageData = @()
$markdownContent = "# .NET Package Report`n"
$markdownContent += "**Solution:** $solutionName`n"
$markdownContent += "**Generated:** $(Get-Date)`n`n"
$markdownContent += "| Status | Package ID | Current Version | Latest Version | Reason |`n"
$markdownContent += "|--------|------------|-----------------|----------------|--------|`n"

$states = @{
    "deprecated" = "Deprecated"
    "vulnerable" = "Vulnerable"
    "outdated"   = "Outdated"
}

foreach ($state in $states.Keys) {
    try {
        $output = dotnet list package "--$state"
        $output -split "`n" | Select-String -Pattern ">" | ForEach-Object {
            $line = $_.ToString().Trim() -split "\s+"
            
            $package = [PSCustomObject]@{
                Status = $states[$state]
                PackageID = $line[1]
                CurrentVersion = $line[3] 
                LatestVersion = $line[4]
                Reason = if ($state -eq "outdated") { "New version available" } else { $line[5..($line.Length-1)] -join ' ' }
                Solution = $solutionName
                Timestamp = $timestamp
            }
            
            $packageData += $package
            $markdownContent += "| $($package.Status) | $($package.PackageID) | $($package.CurrentVersion) | $($package.LatestVersion) | $($package.Reason) |`n"
        }
    }
    catch {
        Write-Warning "Failed to analyze $state packages: $_"
    }
}

if ($packageData.Count -gt 0) {
    $csvPath = Join-Path $timestampedReportDir "packages.csv"
    $packageData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $jsonPath = Join-Path $timestampedReportDir "packages.json"
    $packageData | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8

    $mdPath = Join-Path $timestampedReportDir "packages.md"
    $markdownContent | Out-File -FilePath $mdPath -Encoding UTF8

    Write-Host "Reports generated in: $timestampedReportDir" -ForegroundColor Green
    Write-Host "Found $($packageData.Count) packages with issues" -ForegroundColor Cyan
}
else {
    Write-Host "No packages with issues found in this solution." -ForegroundColor Yellow
}

$shortcutPath = Join-Path $solutionDir "Latest_Package_Reports.lnk"
$wshell = New-Object -ComObject WScript.Shell
$shortcut = $wshell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $timestampedReportDir
$shortcut.Save()