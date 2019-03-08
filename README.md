# WinRAR ACE vulnerability scanner for Domain

## Description: 

Script in PowerShell to detect vulnerable versions of WinRAR (related to ACE files) in a Windows domain.

CVEs: (CVE-2018-20250) (CVE-2018-20251) (CVE-2018-20252) (CVE-2018-20253)

### Considerations:

- Well configured WinRM on remote machines
- Well configured firewall rules
- Run the script with the Unrestricted or Bypass execution policies from Domain Controller


# Usage: 

 PS E:\Pruebas C# PowerShell> .\DetectWinRARaceVulnDomain.ps1

 PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectWinRARaceVulnDomain.ps1'
