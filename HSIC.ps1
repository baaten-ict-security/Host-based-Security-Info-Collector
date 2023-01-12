##########################################################################################################
## HSIC: Host-based Security Info Collector
##
## Powershell script that generates a TXT file with security related information about a specific host.
## RUN WITH ADMINISTRATIVE PRIVILEGES
## 
## Steps:
## 1. Run "Windows PowerShell" app "as Administrator" from Windows start menu
## 2. In PowerShell run "Get-ExecutionPolicy" to view your current PowerShell Execution Policy (Windows default: restricted)
## 3. In PowerShell run "Set-ExecutionPolicy Unrestricted" to be able to run this script.
## 4. Go to the directory containing this script and execute it in PowerShell: ".\HSIC.ps1"
## 5. In PowerShell run "Set-ExecutionPolicy Restricted" to restore the PowerShell Execution Policy to it's original state (might be different than the current default)
##
## Author: Dennis Baaten (Baaten ICT Security)
##########################################################################################################

# Present elevation prompt to run with administrative privileges
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

Clear

# Let user select output directory
$application = New-Object -ComObject Shell.Application
While (!$outputdir) {
    $outputdir = ($application.BrowseForFolder(0, 'Host-based Security Info Collector: where do you want to store HSIC-output.txt?', 0)).Self.Path 
}

$file = 'HSIC-output.txt'

$filename = "$outputdir\$file"
Set-Content -Path $filename -Value "Host-based Security Info Collector"
Add-Content -Path $filename $(Get-Date -Format "dddd dd/MM/yyyy HH:mm K")

# Get Antivirus status
Write-Host "`r`n# Getting Antivirus status"
Add-Content -Path $filename -Value "`r`n###### ANTIVIRUS ######"
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Select displayName, productState, instanceGUID | Out-String -Width 1000 | Add-Content -Path $filename

# Get Windows Firewall status (not third party) 
Write-Host "`r`n# Getting firewall status"
Add-Content -Path $filename -Value "`r`n###### WINDOWS FIREWALL STATUS ######"
(Get-NetFirewallProfile) | Out-String -Width 1000 | Add-Content -Path $filename
# Get Firewall products (including third party)
Add-Content -Path $filename -Value "`r`n###### FIREWALL PRODUCTS ######"
Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct | Select displayName, productState, instanceGUID | Out-String -Width 1000 | Add-Content -Path $filename

# Get Bitlocker status
Write-Host "`r`n# Getting Bitlocker status"
Add-Content -Path $filename -Value "`r`n###### BITLOCKER ######"
manage-bde -status | Add-Content -Path $filename

# Get Operating System status
Write-Host "`r`n# Getting OS information"
Add-Content -Path $filename -Value "`r`n###### OPERATING SYSTEM ######"
(Get-WMIObject win32_operatingsystem) | Select Name | Out-String -Width 1000 | Add-Content -Path $filename

# Get Windows update status
Write-Host "`r`n# Getting Windows Update Status (takes a while)"
Add-Content -Path $filename -Value "`r`n###### WINDOWS UPDATE STATUS ######"
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateupdateSearcher()
$Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
$Updates | Select-Object Title, IsMandatory, IsInstalled | Out-String  -Width 1000 | Add-Content -Path $filename

# Get installed software + versions
Write-Host "`r`n# Getting versions of installed software"
Add-Content -Path $filename -Value "`r`n###### INSTALLED SOFTWARE + VERSION ######"
Get-WmiObject -Class Win32_Product | Select Name, Version | Out-String -Width 1000 | Add-Content -Path $filename

# User status
Write-Host "`r`n# Getting user information"
Add-Content -Path $filename -Value "`r`n###### USER INFORMATION ######"
Get-LocalUser | Select Name, Enabled | Out-String -Width 1000 | Add-Content -Path $filename
Get-LocalGroupMember -Group "Administrators" | Out-String -Width 1000 | Add-Content -Path $filename
[Security.Principal.WindowsIdentity]::GetCurrent().Name | Out-String -Width 1000 | Add-Content -Path $filename

# Finished
Write-Host "`r`n# Finished"
