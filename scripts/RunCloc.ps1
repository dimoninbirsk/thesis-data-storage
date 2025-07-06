$clocDir = New-Item -ItemType Directory -Name "cloc" -Force

Get-ChildItem -Directory | Where-Object { $_.Name -ne "cloc" } | ForEach-Object {
    $repoName = $_.Name
    $repoClocDir = New-Item -ItemType Directory -Path (Join-Path $clocDir.FullName $repoName) -Force
    
    Write-Host "Processing $repoName..."
    cloc $_.FullName --out="$($repoClocDir.FullName)\metadata.csv" --csv 
    cloc $_.FullName --out="$($repoClocDir.FullName)\metadata.json" --json 
    cloc $_.FullName --out="$($repoClocDir.FullName)\metadata.md" --md
}

Write-Host "All repositories processed!" -ForegroundColor Green