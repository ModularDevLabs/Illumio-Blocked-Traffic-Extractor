param(
    [string]$BinaryPath = (Join-Path (Get-Location) "IllumioTrafficTool_Windows.exe"),
    [switch]$Uninstall
)

$TaskName = "Illumio Blocked Traffic Extractor Scheduler"
if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Illumio traffic scheduler task removed."
    exit 0
}

$ResolvedBinary = (Resolve-Path $BinaryPath -ErrorAction Stop).Path
$Action = New-ScheduledTaskAction -Execute $ResolvedBinary -Argument "--open-browser=false"
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Runs scheduled Illumio blocked traffic report templates." -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Illumio traffic scheduler installed and started for the current user."
