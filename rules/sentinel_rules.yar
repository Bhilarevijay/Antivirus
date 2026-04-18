/*
 * Sentinel Antivirus - Default YARA Rules
 * These rules detect common malware patterns and suspicious behaviors.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file - standard test string"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar at 0
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Detects files containing common ransomware note patterns"
        author = "Sentinel AV"
        threat_level = 4

    strings:
        // Ransom demand phrases (very specific to ransomware)
        $demand1 = "your files have been encrypted" nocase
        $demand2 = "pay the ransom" nocase
        $demand3 = "send bitcoin" nocase
        $demand4 = "your personal files are encrypted" nocase
        $demand5 = "to decrypt your files" nocase
        $demand6 = "buy decryption key" nocase
        // Payment indicators
        $payment1 = "bitcoin wallet" nocase
        $payment2 = "monero" nocase
        $payment3 = "restore your files" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

    condition:
        // Require at least 2 ransom demands + 1 payment indicator (eliminates crypto tool false positives)
        (2 of ($demand*) and 1 of ($payment*)) or
        ($wallet and 2 of ($demand*))
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Detects scripts that delete Volume Shadow Copies"
        author = "Sentinel AV"
        threat_level = 4

    strings:
        $del_shadow = "vssadmin delete shadows" nocase
        $wmic_shadow = "wmic shadowcopy delete" nocase
        $bcdedit = "bcdedit /set {default} recoveryenabled No" nocase

    condition:
        any of them
}

rule Process_Injection_Combo
{
    meta:
        description = "Detects PE files importing classic process injection API combination"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $mz = { 4D 5A }
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii

    condition:
        $mz at 0 and 3 of ($api*)
}

rule Webshell_Generic
{
    meta:
        description = "Detects generic webshell patterns in script files"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $php_eval = "eval($_" ascii
        $php_exec = "exec($_" ascii
        $php_system = "system($_" ascii
        $php_base64 = "base64_decode($_" ascii
        $asp_eval = "eval(Request" ascii nocase

    condition:
        2 of them
}

rule Suspicious_Office_Macro
{
    meta:
        description = "Detects suspicious VBA macro patterns in Office documents"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $auto = "Auto_Open" ascii nocase
        $auto2 = "AutoExec" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $shell = "Shell(" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
        $powershell = "powershell" ascii nocase
        $download = "URLDownloadToFile" ascii nocase

    condition:
        ($auto or $auto2 or $auto3) and 2 of ($shell, $wscript, $powershell, $download)
}

rule Packed_UPX_Executable
{
    meta:
        description = "Detects UPX-packed executables often used to hide malware"
        author = "Sentinel AV"
        threat_level = 1

    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii

    condition:
        $mz at 0 and 2 of ($upx*)
}

rule Suspicious_Encoded_PowerShell
{
    meta:
        description = "Detects encoded PowerShell commands used to evade detection"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $ps = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-e " nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase

    condition:
        $ps and ($enc1 or $enc2 or $enc3) and ($hidden or $bypass)
}
