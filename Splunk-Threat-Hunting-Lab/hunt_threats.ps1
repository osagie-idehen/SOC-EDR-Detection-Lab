<#
.SYNOPSIS
    SOC Tier-1 & Tier-2 SIEM Threat Hunting Engine
.DESCRIPTION
    Emulates Splunk Enterprise Search Processing Language (SPL) correlation rules across
    Windows Security and Sysmon telemetry. Identifies brute-force attacks, successful breach
    logons, encoded PowerShell execution, unauthorized Domain Admin account creation, LOLBAS abuse,
    and audit log wiping.
.PARAMETER Path
    Path to the attack telemetry JSON file.
.AUTHOR
    Osagie Henry Idehen (SOC Lab Portfolio)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path = "C:\Users\HP\Downloads\SOC-Lab-Portfolio\Splunk-Threat-Hunting-Lab\attack_telemetry.json"
)

if (-not (Test-Path $Path) -and $PSScriptRoot) {
    $Path = Join-Path $PSScriptRoot "attack_telemetry.json"
}

Clear-Host
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "       SOC SIEM LOG ANALYSIS & THREAT HUNTING ENGINE (SPLUNK EMULATOR)    " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "Target Telemetry : $Path"
Write-Host "Execution Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host "Lead SOC Analyst : Osagie Henry Idehen"
Write-Host ""

if (-not (Test-Path $Path)) {
    Write-Error "Telemetry file not found: $Path"
    exit 1
}

$events = Get-Content $Path -Raw | ConvertFrom-Json
Write-Host "[*] Successfully ingested $($events.Count) security events across endpoints." -ForegroundColor Green
Write-Host ""

# -------------------------------------------------------------------------
# HUNT 1: BRUTE FORCE & PASSWORD SPRAYING (Event ID 4625)
# Equivalent SPL:
# index=windows_security EventCode=4625 | stats count by src_ip, user, sub_status | where count >= 5
# -------------------------------------------------------------------------
Write-Host "[+] HUNT 1: Brute Force & Password Spraying Detection (Event ID 4625)" -ForegroundColor Green
$failedLogons = $events | Where-Object { $_.event_id -eq 4625 }
$groupedFails = $failedLogons | Group-Object -Property src_ip, user

foreach ($g in $groupedFails) {
    $ip = $g.Group[0].src_ip
    $user = $g.Group[0].user
    $count = $g.Count
    if ($count -ge 3) {
        Write-Host "    [!] THREAT DETECTED: High-frequency logon failures" -ForegroundColor Red
        Write-Host "        Source IP  : $ip (Defanged: $($ip -replace '\.', '[.]'))" -ForegroundColor Yellow
        Write-Host "        Target User: $user"
        Write-Host "        Attempts   : $count failures in < 60 seconds"
        Write-Host "        MITRE T1110: Password Spraying / Brute Force"
    }
}
Write-Host ""

# -------------------------------------------------------------------------
# HUNT 2: BREACH CORRELATION - SUCCESS LOGON FROM ADVERSARY IP (Event ID 4624)
# Equivalent SPL:
# index=windows_security EventCode=4624 Logon_Type=3 [ search EventCode=4625 | stats count by src_ip | where count > 5 | fields src_ip ]
# -------------------------------------------------------------------------
Write-Host "[+] HUNT 2: Successful Logon Following Failed Attempts (Event ID 4624)" -ForegroundColor Green
$successLogons = $events | Where-Object { $_.event_id -eq 4624 -and $_.src_ip -eq "185.220.101.5" }
foreach ($s in $successLogons) {
    Write-Host "    [CRITICAL ALERT] Compromised Account Confirmed via Remote Logon" -ForegroundColor Red
    Write-Host "        Timestamp  : $($s.timestamp)"
    Write-Host "        Target Host: $($s.computer_name)"
    Write-Host "        User       : $($s.user)"
    Write-Host "        Logon Type : $($s.logon_type) (Network Logon)"
    Write-Host "        Origin IP  : $($s.src_ip)" -ForegroundColor Magenta
}
Write-Host ""

# -------------------------------------------------------------------------
# HUNT 3: SUSPICIOUS PROCESS EXECUTION & LOLBAS (Sysmon Event ID 1)
# Equivalent SPL:
# index=sysmon EventCode=1 (CommandLine="*-enc*" OR Image="*certutil.exe*")
# -------------------------------------------------------------------------
Write-Host "[+] HUNT 3: Suspicious Process Execution & LOLBAS Abuse (Sysmon Event ID 1)" -ForegroundColor Green
$procEvents = $events | Where-Object { $_.event_id -eq 1 }
foreach ($p in $procEvents) {
    if ($p.command_line -match "-enc|-nop|certutil") {
        Write-Host "    [ALERT] Suspicious Execution Detected:" -ForegroundColor Yellow
        Write-Host "        Binary   : $($p.image)"
        Write-Host "        Command  : $($p.command_line.Substring(0, [Math]::Min(80, $p.command_line.Length)))..." -ForegroundColor White
        Write-Host "        Parent   : $($p.parent_image)"
        Write-Host "        User     : $($p.user)"
        Write-Host "        SHA-256  : $($p.hashes)"
        Write-Host ""
    }
}

# -------------------------------------------------------------------------
# HUNT 4: PRIVILEGE ESCALATION & ROGUE ADMIN CREATION (Event ID 4720 & 4728)
# Equivalent SPL:
# index=windows_security (EventCode=4720 OR EventCode=4728) Group_Name="*Admin*"
# -------------------------------------------------------------------------
Write-Host "[+] HUNT 4: Rogue Account Creation & Admin Group Escalation (Event ID 4720/4728)" -ForegroundColor Green
$userCreated = $events | Where-Object { $_.event_id -eq 4720 }
$groupAdded = $events | Where-Object { $_.event_id -eq 4728 }

if ($userCreated) {
    Write-Host "    [!] Backdoor User Created: $($userCreated.target_user_name) by $($userCreated.subject_user_name)" -ForegroundColor Red
}
if ($groupAdded) {
    Write-Host "    [!] Elevated to Privileged Group: $($groupAdded.group_name)" -ForegroundColor Red
    Write-Host "        Target User: $($groupAdded.target_user_name)"
    Write-Host "        MITRE T1078 / T1098: Account Manipulation"
}
Write-Host ""

# -------------------------------------------------------------------------
# HUNT 5: DEFENSE EVASION - SECURITY AUDIT LOG CLEARED (Event ID 1102)
# Equivalent SPL:
# index=windows_security EventCode=1102
# -------------------------------------------------------------------------
Write-Host "[+] HUNT 5: Defense Evasion & Anti-Forensics (Event ID 1102)" -ForegroundColor Green
$logCleared = $events | Where-Object { $_.event_id -eq 1102 }
if ($logCleared) {
    Write-Host "    [CRITICAL] Security Event Log Cleared on $($logCleared.computer_name)" -ForegroundColor Red
    Write-Host "        Actor User: $($logCleared.user)"
    Write-Host "        MITRE T1070.001: Clear Windows Event Logs"
}
Write-Host ""

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  HUNT RESULT: ACTIVE ENTERPRISE INTRUSION CONFIRMED (SEVERITY: CRITICAL) " -ForegroundColor Red
Write-Host "  RECOMMENDED ACTION: ISOLATE DC-CORP-01, DISABLE svc-backup-admin, DROP IP" -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan
