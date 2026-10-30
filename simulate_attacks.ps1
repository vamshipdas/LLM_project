# =============================================================================
# CyberLLM / Sentinel Desk — Attack Simulation Script
# SAFE: All commands local-only. No real network traffic is sent.
# =============================================================================
param([int]$RepeatCount = 5, [int]$DelayBetweenMs = 600)
$ErrorActionPreference = "SilentlyContinue"

function Write-SimEvent {
    param([string]$LogName="Application",[string]$Source="CyberLLM-Sim",[int]$EventId=4625,[string]$EntryType="Warning",[string]$Message)
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
        try { New-EventLog -LogName $LogName -Source $Source -ErrorAction SilentlyContinue } catch {}
    }
    Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction SilentlyContinue
    Write-Host "  [+] EventID $EventId : $($Message.Substring(0,[Math]::Min(70,$Message.Length)))..."
    Start-Sleep -Milliseconds $DelayBetweenMs
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberLLM SOC - Attack Simulation (SAFE/LOCAL)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "NOTE: In Sentinel Desk, open 'Log Analysis' -> 'Real-Time Logs'" -ForegroundColor Yellow
Write-Host "and click 'Start Real-Time Stream' to see alerts arrive live!" -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Cyan

# SCENARIO 1: Brute-Force (T1110) from Tehran Iran (5+ attempts triggers Brute Force Finding)
Write-Host "`n[1] Brute-Force Authentication from 203.0.113.45 (Tehran, Iran)" -ForegroundColor Red
for ($i=1; $i -le $RepeatCount; $i++) {
    Write-SimEvent -EventId 4625 -EntryType Warning -Message "An account failed to log on.`nAccount Name: Administrator`nLogon Type: 3`nFailure Reason: Unknown user name or bad password`nSource Network Address: 203.0.113.45`nSource Port: 4923$i`nWorkstation Name: ATTACKER-HOST-$i`nStatus: 0xC000006D`nTechnique: T1110 Brute Force"
}

# SCENARIO 2: Account Compromise (T1078) - Successful login following failed attempts
Write-Host "`n[2] Account Compromise from 203.0.113.45 (Tehran, Iran)" -ForegroundColor Red
Write-SimEvent -EventId 4624 -EntryType Information -Message "An account was successfully logged on.`nAccount Name: Administrator`nTarget Server Name: DC01.corp.local`nNetwork Address: 203.0.113.45`nAuthentication Package: Negotiate`nTechnique: T1078 Valid Accounts"

# SCENARIO 3: Credential Dumping / Mimikatz (T1003.001) from Amsterdam NL
Write-Host "`n[3] LSASS Credential Dump from 203.0.113.88 (Amsterdam, NL)" -ForegroundColor Red
for ($i=1; $i -le 3; $i++) {
    Write-SimEvent -EventId 4656 -EntryType Error -Message "A handle to an object was requested.`nObject Name: \Device\HarddiskVolume3\Windows\System32\lsass.exe`nAccess Mask: 0x1010 (Read Process Memory)`nProcess Name: C:\Users\attacker\mimikatz64.exe`nSource Network Address: 203.0.113.88`nPrivilege List: SeDebugPrivilege`nTechnique: T1003.001 LSASS Memory"
}

# SCENARIO 4: Port Scan Reconnaissance (T1046) from Bucharest Romania (5+ probes triggers Recon Finding)
Write-Host "`n[4] Port Scan from 192.0.2.45 (Bucharest, Romania)" -ForegroundColor Yellow
foreach ($port in @(22,80,443,3389,445,8080)) {
    Write-SimEvent -EventId 5156 -EntryType Warning -Message "Windows Filtering Platform detected connection attempt.`nDirection: Inbound`nSource IP Address: 192.0.2.45`nDestination Port: $port`nProtocol: 6 (TCP)`nAction: connection refused`nport scan probe detected`nTechnique: T1046 Network Service Discovery"
}

# SCENARIO 5: Persistence - Scheduled Service Created (T1543)
Write-Host "`n[5] Persistence Service Installed from 198.51.100.77 (Seoul, South Korea)" -ForegroundColor Red
Write-SimEvent -EventId 7045 -EntryType Error -Message "A service was installed in the system.`nService Name: BackdoorSvc`nService File Name: C:\Windows\Temp\malware_service.exe`nService Type: user mode service`nService Account: LocalSystem`nSource Network Address: 198.51.100.77`nTechnique: T1543 Create or Modify System Process"

# SCENARIO 6: Defense Evasion - Audit Log Cleared (T1070)
Write-Host "`n[6] Defense Evasion: Security Audit Log Cleared from 198.51.100.23 (Beijing, China)" -ForegroundColor Red
Write-SimEvent -EventId 1102 -EntryType Warning -Message "The audit log was cleared.`nSubject User Name: Administrator`nDomain: CORP`nClient Address: 198.51.100.23`nTechnique: T1070 Indicator Removal on Host"

# SCENARIO 7: Privilege Escalation - Backdoor Admin Created (T1098)
Write-Host "`n[7] Privilege Escalation: Admin Account Created from 198.51.100.77 (Seoul, South Korea)" -ForegroundColor Red
Write-SimEvent -EventId 4720 -EntryType Error -Message "A user account was created.`nTarget Account Name: backdoor_admin`nCreator Subject: Administrator`nadded to administrators group`nSource IP: 198.51.100.77`nTechnique: T1098 Account Manipulation"

# SCENARIO 8: Malware / Ransomware Detected (T1204 / T1486) with Moscow Russia C2
Write-Host "`n[8] Malware & Ransomware Alert with C2 at 203.0.113.195 (Moscow, Russia)" -ForegroundColor Magenta
Write-SimEvent -EventId 1116 -EntryType Error -Message "Microsoft Defender Antivirus has detected malware.`nDetection Name: Ransom:Win32/WannaCrypt.A`nPath: C:\Windows\Temp\crypt0r.exe`nSeverity: Severe`nAction: Quarantine FAILED - Trojan virus detected`nSource IP: 203.0.113.195`nTechnique: T1204 / T1486 Data Encrypted for Impact"

# SCENARIO 9: Suspicious PowerShell Execution (T1059.001)
Write-Host "`n[9] Suspicious Encoded PowerShell Execution from 192.0.2.100 (Sao Paulo, Brazil)" -ForegroundColor Yellow
Write-SimEvent -EventId 4104 -EntryType Warning -Message "Script block text execution.`nScriptBlock: powershell -nop -w hidden -encodedcommand JABjAGwAaQBlAG4AdAAgAD0A...`nDownloadString detected from 192.0.2.100`nTechnique: T1059.001 Command and Scripting Interpreter: PowerShell"

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  Simulation Complete!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "Next steps in Sentinel Desk (http://localhost:5173):" -ForegroundColor Cyan
Write-Host "1. In top navigation, click 'Log Analysis'" -ForegroundColor White
Write-Host "2. In 'Real-Time Logs', click 'Start Real-Time Stream' to see live events" -ForegroundColor White
Write-Host "3. Or upload 'sample_attack_simulation.log' in 'Upload Logs' for full SOP analysis!" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Green
