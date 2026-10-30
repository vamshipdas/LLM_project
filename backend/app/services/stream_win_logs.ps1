[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$logs = @('System', 'Application')
try {
    $null = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
    $logs = @('System', 'Application', 'Security')
} catch {
    Write-Output "WARN_SECURITY_DENIED"
}

# 1. Initial seed: emit last 50 events from host immediately
try {
    $seed = Get-WinEvent -LogName $logs -MaxEvents 50 -ErrorAction SilentlyContinue | Sort-Object TimeCreated
    if ($seed) {
        foreach ($e in $seed) {
            $msg = if ($e.Message) { $e.Message.Replace("`r", " ").Replace("`n", " ") } else { "" }
            $obj = @{
                TimeCreated = $e.TimeCreated.ToString('o')
                Level = $e.LevelDisplayName
                Source = $e.ProviderName
                EventID = $e.Id
                Message = $msg
                Host = $e.MachineName
            }
            Write-Output ($obj | ConvertTo-Json -Compress)
        }
    }
} catch {}

# 2. Continuous real-time loop polling for newly arriving events
$lastCheck = Get-Date
while ($true) {
    Start-Sleep -Seconds 2
    $now = Get-Date
    foreach ($logName in $logs) {
        try {
            $filter = @{LogName=$logName; StartTime=$lastCheck}
            $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | Sort-Object TimeCreated
            if ($events) {
                foreach ($e in $events) {
                    $msg = if ($e.Message) { $e.Message.Replace("`r", " ").Replace("`n", " ") } else { "" }
                    $obj = @{
                        TimeCreated = $e.TimeCreated.ToString('o')
                        Level = $e.LevelDisplayName
                        Source = $e.ProviderName
                        EventID = $e.Id
                        Message = $msg
                        Host = $e.MachineName
                    }
                    Write-Output ($obj | ConvertTo-Json -Compress)
                }
            }
        } catch {}
    }
    $lastCheck = $now
}
