<#
.SYNOPSIS
    Microsoft 365 & Perimeter Incident Containment Playbook
.DESCRIPTION
    Standard operating containment commands for SOC Analysts responding to INC-20261025-002:
    - Search & Purge malicious phishing emails across tenant mailboxes
    - Enforce tenant-wide Exchange Online anti-spoofing mail flow rule
    - Isolate compromised identity via Microsoft Entra ID (Azure AD)
    - Block adversary IoCs across Microsoft Defender & firewall perimeter
.AUTHOR
    Osagie Henry Idehen (SOC Lab Portfolio)
#>

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "     ENTERPRISE PHISHING CONTAINMENT & ERADICATION PLAYBOOK              " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# STEP 1: TENANT-WIDE SEARCH & PURGE (Microsoft 365 Security & Compliance)
# -------------------------------------------------------------------------
Write-Host "`n[+] STEP 1: Initiating Compliance Search across all tenant mailboxes..." -ForegroundColor Green

$searchQuery = 'Subject:"ACTION REQUIRED: Immediate Password Expiration Notice*" OR ' +
               'From:"support@login-microsoft365-verify.com" OR ' +
               'c:c "secure-login-microsoft365-auth.online"'

Write-Host "Query String: $searchQuery"

<#
# Connect to Security & Compliance PowerShell (Admin Session)
Connect-IPPSSession

# 1. Create the compliance search
New-ComplianceSearch -Name "PhishIncident_INC-20261025-002" `
                     -ExchangeLocation All `
                     -ContentMatchQuery $searchQuery

# 2. Start the search
Start-ComplianceSearch -Identity "PhishIncident_INC-20261025-002"

# 3. Check status until completed
Get-ComplianceSearch -Identity "PhishIncident_INC-20261025-002"

# 4. Hard delete (purge) the malicious email from all victim mailboxes
New-ComplianceSearchAction -SearchName "PhishIncident_INC-20261025-002" `
                          -Purge `
                          -PurgeType HardDelete `
                          -Confirm:$false
#>

# -------------------------------------------------------------------------
# STEP 2: IDENTITY CONTAINMENT (Microsoft Entra ID / Azure AD)
# -------------------------------------------------------------------------
Write-Host "`n[+] STEP 2: Isolating potential victim account..." -ForegroundColor Green
$victimUser = "victim-employee@globaltech-solutions.com"

<#
# Connect to Microsoft Graph PowerShell
Connect-MgGraph -Scopes "User.ReadWrite.All"

# 1. Immediately revoke all active refresh tokens and OAuth sessions
Revoke-MgUserSignSession -UserId $victimUser

# 2. Force password reset on next logon and invalidate current password
$passwordProfile = @{
    ForceChangePasswordNextSignIn = $true
    Password = [System.Web.Security.Membership]::GeneratePassword(16, 3)
}
Update-MgUser -UserId $victimUser -PasswordProfile $passwordProfile

# 3. Flag user in Entra ID Identity Protection as Confirmed Compromised
Invoke-MgConfirmCompromisedRiskyUser -UserIds @($victimUser)
#>
Write-Host "Target User: $victimUser"
Write-Host "Actions: Session Revocation, Password Invalidation, Enforced MFA Re-registration"

# -------------------------------------------------------------------------
# STEP 3: EXCHANGE ONLINE MAIL FLOW RULE (Prevent Future Delivery)
# -------------------------------------------------------------------------
Write-Host "`n[+] STEP 3: Deploying Exchange Transport Rule for Domain Spoofing Defense..." -ForegroundColor Green

<#
# Connect to Exchange Online PowerShell
Connect-ExchangeOnline

# Rule: Quarantine emails where From header displays internal brand but sender is external
New-TransportRule -Name "Block-Spoofed-M365-Identity-Urgent-Password" `
    -HeaderMatchesMessageHeader "Subject" `
    -HeaderMatchesPatterns "Password Expiration", "Multi-Factor Sync" `
    -FromScope "NotInOrganization" `
    -SenderDomainIs "login-microsoft365-verify.com", "secure-recovery-helpdesk.top" `
    -Quarantine $true `
    -SetAuditSeverity High `
    -Comments "SOC Rule INC-20261025-002: Block credential harvester campaign targeting M365 accounts"
#>

# -------------------------------------------------------------------------
# STEP 4: PERIMETER IOC BLOCKING (Firewall / Web Proxy / DNS Sinkhole)
# -------------------------------------------------------------------------
Write-Host "`n[+] STEP 4: Defanged Indicators of Compromise for Perimeter Firewall/DNS Block:" -ForegroundColor Green
$domainsToBlock = @(
    "login-microsoft365-verify[.]com",
    "secure-login-microsoft365-auth[.]online",
    "secure-recovery-helpdesk[.]top",
    "mailserver-vps99[.]ru"
)
$ipsToBlock = @(
    "185[.]220[.]101[.]5"
)

Write-Host "    [DOMAINS TO SINKHOLE / BLOCK]" -ForegroundColor Yellow
$domainsToBlock | ForEach-Object { Write-Host "     - $_" }

Write-Host "    [IPs TO DROP ON PERIMETER FIREWALL]" -ForegroundColor Yellow
$ipsToBlock | ForEach-Object { Write-Host "     - $_" }

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host "     CONTAINMENT ACTIONS DOCUMENTED & READY FOR INCIDENT CLOSURE         " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan
