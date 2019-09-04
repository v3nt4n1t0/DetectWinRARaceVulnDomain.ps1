<#
.SYNOPSIS
    WinRAR ACE vulnerability scanner for Domain
    
.DESCRIPTION
    Script in PowerShell to detect vulnerable versions of WinRAR (related to ACE files) in a Windows domain.

    CVEs: (CVE-2018-20250) (CVE-2018-20251) (CVE-2018-20252) (CVE-2018-20253)
    
    
    Considerations: 
        - Well configured WinRM on remote machines
        - Well configured firewall rules
        - Run the script with the Unrestricted or Bypass execution policies from Domain Controller
    
    
.NOTES
    File Name      : DetectWinRARaceVulnDomain.ps1
    Author         : Author: Roberto Berrio (@v3nt4n1t0)
    Website        : https://github.com/v3nt4n1t0

    This software is provided under the BSD 3-Clause License.
    See the accompanying LICENSE file for more information.
    
.LINK
    https://github.com/v3nt4n1t0/DetectWinRARaceVulnDomain.ps1
    
.EXAMPLE
    .\DetectWinRARaceVulnDomain.ps1
    
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectWinRARaceVulnDomain.ps1'
    
.EXAMPLE
    iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/v3nt4n1t0/DetectWinRARaceVulnDomain.ps1/master/DetectWinRARaceVulnDomain.ps1")
#>

$c = Get-ADComputer -Properties IPv4Address -Filter {Enabled -eq $true}
$cred = Get-Credential

echo ""
if($cred){
    foreach ($cname in $c.name ) {
    
        if(test-connection -ComputerName $cname -Count 1 -Quiet){
            try{
            $session = New-PSSession -ComputerName $cname -Credential $cred
            Invoke-Command -Session $session -ScriptBlock{
                $machine = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0] + "," +[Environment]::GetEnvironmentVariable("ComputerName") 
            
                ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {      
            
                    if($_.GetValue("DisplayName") -like "winrar*"){
                    $winrar = $_.GetValue("DisplayName")
                    $winrarSplit = $winrar.Split(" ")
                    $versionWinRAR = $winrarSplit[1]
                    }
                }

                ls HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {
                        if($_.GetValue("DisplayName") -like "winrar*"){
                        $winrar = $_.GetValue("DisplayName")
                        $winrarSplit = $winrar.Split(" ")
                        $versionWinRAR = $winrarSplit[1]
                        }
                }
     
            if(!$winrar){"$machine -> Does not contain WinRAR"}
            elseif($versionWinRAR -lt 5.70){Write-Host -ForegroundColor Red "$machine -> Vulnerable!"}
            else{"$machine -> Non-vulnerable"}
            }
    
            Remove-PSSession -Session $session

            }catch{Write-Host -ForegroundColor Red -BackgroundColor Yellow "$cname is active, but the check can not be performed. Verify that the Administrator credentials are correct, that the remote computer has WinRM actived, or that Firewall rules are not blocking the connection"}
        }
        else{Write-Host -ForegroundColor DarkYellow "$cname does not respond to ping or the machine is off. Check that firewall rules are not blocking the connection"}
    }

Write-Host "`n To fix the vulnerability UPDATE WinRAR to 5.70 or higher`n"

}
else{Write-Host -ForegroundColor Red -BackgroundColor Yellow "`n Administrator credentials are required to run the script`n"}
