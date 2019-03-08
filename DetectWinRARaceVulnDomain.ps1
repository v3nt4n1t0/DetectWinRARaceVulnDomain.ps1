#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Author: Roberto Berrio (@v3nt4n1t0)
# Website: https://github.com/v3nt4n1t0
#
#
# Description: Script in PowerShell to detect vulnerable versions of WinRAR (related to ACE files) in a Windows domain. 
#
# CVEs: (CVE-2018-20250) (CVE-2018-20251) (CVE-2018-20252) (CVE-2018-20253)
# 
# 
# Considerations: 
#
# - Well configured WinRM on remote machines
# - Well configured firewall rules
# - Run the script with the Unrestricted or Bypass execution policies from Domain Controller
#
# Usage: 
#
# PS E:\Pruebas C# PowerShell> .\DetectWinRARaceVulnDomain.ps1
#
# PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectWinRARaceVulnDomain.ps1'
# 
################################################################################################################################################## 


$c = Get-ADComputer -Properties IPv4Address -Filter {Enabled -eq $true}
$cred = Get-Credential
#$vuln = 0
echo ""
if($cred){
foreach ($cname in $c.name ) {
    
    if(test-connection -ComputerName $cname -Count 1 -Quiet){
        try{
        $session = New-PSSession -ComputerName $cname -Credential $cred
        #if($session){
        Invoke-Command -Session $session -ScriptBlock{
            $machine = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0] + "," +[Environment]::GetEnvironmentVariable("ComputerName") 
            ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {      
            
                if($_.GetValue("DisplayName") -like "winrar*"){
                $winrar = $_.GetValue("DisplayName")
                $winrarSplit = $winrar.Split(" ")
                $versionWinRAR = $winrarSplit[1]
                }
                else{
                ls HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {
                        if($_.GetValue("DisplayName") -like "winrar*"){
                        $winrar = $_.GetValue("DisplayName")
                        $winrarSplit = $winrar.Split(" ")
                        $versionWinRAR = $winrarSplit[1]
                        }
                    }
                }
            }

        if(!$winrar){"$machine -> No contiene WinRAR"}
        elseif($versionWinRAR -lt 5.70){
        Write-Host -ForegroundColor Red "$machine -> Vulnerable!"
        #$vuln = $vuln+1
        }
        else{"$machine -> No es vulnerable"}
        }#ScriptBlock
    
        Remove-PSSession -Session $session
        #}else{ Write-Host -ForegroundColor Red "Debe introducir correctamente las credenciales de Administrador"}
        }catch{
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "$cname esta activa, pero no se puede realizar la comprobación. Compruebe que las credenciales de Administrador sean correctas, que el equipo remoto tiene activo WinRM o que ninguna regla del Firewall esté bloqueando la conexión"
        Write-Host -ForegroundColor Red -BackgroundColor Yellow "$cname is active, but the check can not be performed. Verify that the Administrator credentials are correct, that the remote computer has WinRM actived, or that Firewall rules are not blocking the connection"
        }

    }
    else{ 
    Write-Host -ForegroundColor DarkYellow "$cname No responde a ping o esta apagada. Compruebe que ninguna regla del Firewall este bloqueando la conexión."
    Write-Host -ForegroundColor DarkYellow "$cname does not respond to ping or the machine is off. Check that firewall rules are not blocking the connection"
    }
}#foreach

#echo "`n $vuln máquinas vulnerables"

Write-Host "`nPara solucionar la vulnerabilidad ACTUALIZA a WinRAR 5.70 o superior"
Write-Host "To fix the vulnerability UPDATE WinRAR to 5.70 or higher"
}
else{

Write-Host -ForegroundColor Red "Son necesarias las credenciales de Administrador para ejecutar el script"
Write-Host -ForegroundColor Red "Administrator credentials are required to run the script"

}
