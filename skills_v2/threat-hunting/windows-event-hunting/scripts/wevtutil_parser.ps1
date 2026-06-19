# Windows Event Log Hunter
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [int]$HoursBack = 24,
    [string[]]$EventIDs = @(4624, 4625, 4648, 4672, 4688, 4697, 4703, 4720, 4738, 4742, 5136, 1102, 4104),
    [string]$OutputFile = "hunt_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$results = @()

# Query each Event ID
foreach ($EventID in $EventIDs) {
    $filter = @{
        LogName = 'Security'
        ID = $EventID
        StartTime = (Get-Date).AddHours(-$HoursBack)
    }
    
    if ($EventID -eq 4104) {
        $filter.LogName = 'Microsoft-Windows-PowerShell/Operational'
    }
    
    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        foreach ($event in $events) {
            $props = @{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Computer = $event.MachineName
                Level = $event.LevelDisplayName
                Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                UserID = $event.UserId
            }
            $results += New-Object PSObject -Property $props
        }
    }
    catch {
        Write-Warning "Error querying Event ID $EventID : $_"
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "Exported $($results.Count) events to $OutputFile"

# Summarize findings
$results | Group-Object EventID | Select-Object Name, Count | Format-Table -AutoSize
