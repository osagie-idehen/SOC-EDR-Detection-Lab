rule Detect_M365_Credential_Phish {
    meta:
        description = "Detects credential harvesting phishing emails masquerading as Microsoft 365 password expiration and MFA alerts"
        author = "Osagie Henry Idehen"
        date = "2026-10-25"
        reference = "SOC-Lab-Portfolio / Phishing-Lab / INC-20261025-002"
        mitre_att_ck = "T1566.002, T1036.005, T1539"
        severity = "High"

    strings:
        // Header indicators & Phishing mailer
        $hdr_mailer = "PHPMailer" ascii nocase
        $hdr_priority = "X-Priority: 1" ascii nocase
        
        // Social engineering urgency hooks in subject or body
        $urgency_1 = "ACTION REQUIRED: Immediate Password Expiration" ascii nocase
        $urgency_2 = "Multi-Factor Sync" ascii nocase
        $urgency_3 = "corporate password expires in less than 24 hours" ascii nocase
        $urgency_4 = "mandatory security protocol update and multi-factor re-authentication" ascii nocase
        $urgency_5 = "Keep Same Password & Synchronize Credentials" ascii nocase

        // Deceptive anchor link spoofing Microsoft Online login
        $legit_anchor = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" ascii nocase

        // Malicious destination domains and credential harvesting paths
        $phish_domain_1 = "secure-login-microsoft365-auth.online" ascii nocase
        $phish_domain_2 = "login-microsoft365-verify.com" ascii nocase
        $phish_domain_3 = "secure-recovery-helpdesk.top" ascii nocase
        $harvest_path = "/portal/login.php?user=" ascii nocase

    condition:
        // Match if the email contains the direct malicious infrastructure OR spoofing lures combined with urgency
        1 of ($phish_domain_*) or
        ($legit_anchor and $harvest_path) or
        ($hdr_mailer and 2 of ($urgency_*) and ($phish_domain_1 or $legit_anchor))
}
