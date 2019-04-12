# WinRAR ACE vulnerability scanner for Domain

## Description: 

Script in PowerShell to detect vulnerable versions of WinRAR (related to ACE files) in a Windows domain.

CVEs: (CVE-2018-20250) (CVE-2018-20251) (CVE-2018-20252) (CVE-2018-20253)

### Considerations:

- Well configured WinRM on remote machines.
- Well configured firewall rules. Allow ping to remote machines from the Domain Controller.
- Run the script with the Unrestricted or Bypass execution policies from Domain Controller.


# Usage: 

 PS E:\Pruebas C# PowerShell> .\DetectWinRARaceVulnDomain.ps1
 
 or
 
 PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectWinRARaceVulnDomain.ps1'
 
 You can try differents methods.
 
 ## Output:

![](https://raw.githubusercontent.com/v3nt4n1t0/DetectWinRARaceVulnDomain.ps1/master/1.PNG)

![](https://raw.githubusercontent.com/v3nt4n1t0/DetectWinRARaceVulnDomain.ps1/master/2.PNG)
