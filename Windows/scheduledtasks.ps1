# simple script to show the tasks scheduled and running powershell

# Filter for tasks that run PowerShell
$psTasks = $tasks | Where-Object { 
    ($_.Actions -match "powershell.exe") -or ($_.Actions -match "pwsh.exe") 
}

# Print results
Write-Host "=== Non-Microsoft Scheduled Tasks ===" -ForegroundColor Cyan
$tasks | Select-Object TaskName, TaskPath, State, Description | Format-Table -AutoSize

Write-Host "`n=== Scheduled Tasks Running PowerShell ===" -ForegroundColor Yellow
$psTasks | Select-Object TaskName, TaskPath, State, Description | Format-Table -AutoSize