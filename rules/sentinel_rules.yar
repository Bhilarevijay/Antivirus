/*
 * Sentinel Antivirus - Default YARA Rules
 * These rules detect common malware patterns and suspicious behaviors.
 * 
 * Note: Rules should have LOW false positive rates.
 * Avoid flagging legitimate files (e.g., all PE executables).
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

rule Suspicious_PowerShell_Dropper
{
    meta:
        description = "Detects PowerShell download cradles with hidden execution"
        author = "Sentinel AV"
        threat_level = 3

    strings:
        $iex = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $wc  = "Net.WebClient" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $encoded = "-EncodedCommand" nocase

    condition:
        ($iex and ($dl1 or $dl2 or $wc)) and ($hidden or $bypass or $encoded)
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Detects files containing common ransomware note patterns"
        author = "Sentinel AV"
        threat_level = 4

    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "pay the ransom" nocase
        $ransom5 = "private key" nocase
        $ransom6 = "restore your files" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

    condition:
        3 of ($ransom*) or ($wallet and 2 of ($ransom*))
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Detects scripts that delete Volume Shadow Copies (ransomware behavior)"
        author = "Sentinel AV"
        threat_level = 4

    strings:
        $del_shadow = "vssadmin delete shadows" nocase
        $del_shadow2 = "vssadmin.exe delete shadows" nocase
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
