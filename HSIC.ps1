##########################################################################################################
## HSIC: Host-based Security Info Collector
## Version: 2.6 (20240925)
## Author: Dennis Baaten (Baaten ICT Security)
##
#### DISCRIPTION
## Powershell script that generates a TXT file with security related information about a specific host. 
## Used in a BYOD / unmanaged device context for manually checking Windows system compliance with a specific set of requirements. ISO 27001 proof. 
## Needs to run with administrative privileges.
## 
#### INSTRUCTIONS
## 1. Run "Windows PowerShell" app "as Administrator" from Windows start menu
## 2. In PowerShell run "Get-ExecutionPolicy" to view your current PowerShell Execution Policy (Windows default: restricted)
## 3. In PowerShell run "Set-ExecutionPolicy Unrestricted" to be able to run this script.
## 4. Go to the directory containing this script and execute it in PowerShell: ".\HSIC.ps1"
## 5. In PowerShell run "Set-ExecutionPolicy Restricted" to restore the PowerShell Execution Policy to it's original state (might be different than the current default)
##
#### VERSION HISTORY
## 1.0: 
##    * original version
## 2.0:
##    * some optimizations of the code
##    * added system identification information
##    * do a better job getting relevant user information
## 2.1:
##    * some simplifications
##    * created a workaround for this long existing bug: https://github.com/PowerShell/PowerShell/issues/2996
##    * converted from WMI to CIM cmdlet to circumvent strange issue that occurs on some systems when getting the 'currently logged in users'
## 2.2:	
##    * since this is a script that feeds an interactive commandline: load functions before use.
## 2.3:
##    * added screensaver settings
##    * improved output of current logged in user
## 2.4:
##    * fixed issue with getting 'current logged in users' 
## 2.5:
##    * device identification now shows if system is a laptop or desktop
##    * version of this script is now added to the TXT file
## 2.6:
##    * added web filtering check for browsers: Firefox (Safe Browsing), Chrome (Safe Browsing), Edge (SmartScreen).
##    * fixed bug in laptop/desktop detection
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

# Functions
function Get-LocalAdmins {

    <#
        .SYNOPSIS
        Replacement for non-functional Get-LocalgroupMember, which has an unfixed issue with broad scope of impact.
        Issue here: https://github.com/PowerShell/PowerShell/issues/2996
        Credits:
        @ganlbarone on GitHub for the base code
        @ConfigMgrRSC on Github for the localisation supplement

        .DESCRIPTION
        The script uses ADSI to fetch all members of the local Administrators group.
        MSFT are aware of this issue, but have closed it without a fix.
        It will output the SID of AzureAD objects such as roles, groups and users,
        and any others which cannot be resolved.

        Designed to run from the Intune MDM and thus accepts no parameters.

        .EXAMPLE
        $results = Get-localAdmins
        $results

        The above will store the output of the function in the $results variable, and
        output the results to console

        .OUTPUTS
        System.Management.Automation.PSCustomObject
        Name        MemberType   Definition
        ----        ----------   ----------
        Equals      Method       bool Equals(System.Object obj)
        GetHashCode Method       int GetHashCode()
        GetType     Method       type GetType()
        ToString    Method       string ToString()
        Computer    NoteProperty string Computer=Workstation1
        Domain      NoteProperty System.String Domain=Contoso
        User        NoteProperty System.String User=Administrator
    #>

    [CmdletBinding()]

    $GroupSID='S-1-5-32-544'
    [string]$Groupname = (get-localgroup -SID $GroupSID)[0].Name
    
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$Groupname"
        $admins = $group.Invoke('Members') | ForEach-Object {
            $path = ([adsi]$_).path
            $memberSID = $(Split-Path $path -Leaf)
            $AadObjectID = Convert-AzureAdSidToObjectId -Sid $memberSID -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Computer = $env:COMPUTERNAME
                Domain = $(Split-Path (Split-Path $path) -Leaf)
                User = $(Split-Path $path -Leaf)
                ObjectID = $AadObjectID
            }
        }
    return $admins
    
}

function Convert-AzureAdSidToObjectId {
    <#
    .SYNOPSIS
    Convert a Azure AD SID to Object ID
     
    .DESCRIPTION
    Converts an Azure AD SID to Object ID.
    Author: Oliver Kieselbach (oliverkieselbach.com)
    The script is provided "AS IS" with no warranties.
     
    .PARAMETER Sid
    The SID to convert
    #>
    
    [CmdletBinding()]
    param([String] $Sid)

    $text = $sid.Replace('S-1-12-1-', '')
    $array = [UInt32[]]$text.Split('-')

    $bytes = New-Object 'Byte[]' 16
    [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
    [Guid]$guid = $bytes

    return $guid
}

# Let user select output directory
$application = New-Object -ComObject Shell.Application
While (!$outputdir) {
    $outputdir = ($application.BrowseForFolder(0, 'Host-based Security Info Collector: where do you want to store HSIC-output.txt?', 0)).Self.Path 
}

$runtime = Get-Date -Format "yyyyMMdd_HHmm"
$file = 'HSIC-output-' + $runtime + '.txt'

$filename = "$outputdir\$file"
Set-Content -Path $filename -Value "Host-based Security Info Collector v2.6"
Add-Content -Path $filename $(Get-Date -Format "yyyy/MM/dd HH:mm K")

# System identification
Write-Host "`r`n# Getting System identifiers"
Add-Content -Path $filename -Value "`r`n###### SYSTEM IDENTIFICATION ######"
$env:COMPUTERNAME | Out-String -Width 1000 | Add-Content -Path $filename -NoNewline #System name

$batteries = Get-WmiObject -Class Win32_Battery
if ($batteries) {
    Add-Content -Path $filename -Value "Device is a laptop`r`n"
} else {
    Add-Content -Path $filename -Value "Device is a desktop`r`n"
}

wmic path win32_Processor get DeviceID,Name,ProcessorID,Caption | Out-String -Width 1000 | Add-Content -Path $filename -NoNewline # CPU Info
Get-WmiObject win32_networkadapterconfiguration | Where-Object { $_.MacAddress -ne $null } | Select-Object Description, MacAddress | Out-String -Width 1000 | Add-Content -Path $filename # Get all network adapters with a MacAddress


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

Add-Content -Path $filename -Value "`r`n# All known users:"
Get-LocalUser | Select Name, Enabled | Out-String -Width 1000 | Add-Content -Path $filename

Add-Content -Path $filename -Value "`r`n# Users with Admin privileges:"
Get-LocalAdmins | Out-String -Width 1000 | Add-Content -Path $filename

Add-Content -Path $filename -Value "`r`n# Current logged in users:"
Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "explorer.exe" } | ForEach-Object { $_.GetOwner() } | Select-Object -ExpandProperty User | Out-String -Width 1000 | Add-Content -Path $filename

Add-Content -Path $filename -Value "`r`n# User running this script:"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$userrunningscript = $principal.Identity.Name
$userrunningscript | Out-String -Width 1000 | Add-Content -Path $filename

Add-Content -Path $filename -Value "`r`n# Screensaver settings:"
Get-Wmiobject win32_desktop | Out-String -Width 1000 | Add-Content -Path $filename

# Web filtering
Write-Host "`r`n# Getting browser related information"
Add-Content -Path $filename -Value "`r`n###### BROWSER INFORMATION ######"

Add-Content -Path $filename -Value "`r`n# Browser web filter settings:"
# First create a PowerShell drive for HKU (HKEY_USERS) if not exists
if (-Not (Test-Path -Path "HKU:\"))
{
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | out-null
}

# Get the list of currently logged-in users' processes.
$processes = Get-WmiObject Win32_Process -Filter "Name = 'explorer.exe'"
foreach ($process in $processes) 
{
    # Get the username and domain for each process.
    $usersid = $process.GetOwnerSid() | Select-Object -ExpandProperty Sid
    $username = $process.GetOwner() | Select-Object -ExpandProperty User
    $wmiUser = Get-WmiObject -Query "SELECT * FROM Win32_UserProfile WHERE SID = '$usersid'"
    if ($wmiUser)
    {
        $userDirectory = $wmiUser.LocalPath
        
        # Get the user's profiles location for supported browsers
        $firefoxProfilesLocation = "$userDirectory\AppData\Roaming\Mozilla\Firefox\Profiles"
        $chromeDataPath = "$userDirectory\AppData\Local\Google\Chrome\User Data"
        
        ## Firefox (Safe Browsing)
        if (Test-Path -Path $firefoxProfilesLocation) 
        {
            # Get the list of profile directories
            $profileDirectories = Get-ChildItem $firefoxProfilesLocation -Directory
    
            # Iterate over each profile directory
            foreach ($directory in $profileDirectories)
            {
                # Full path of the prefs.js inside current directory
                $prefsFilePath = Join-Path -Path $directory.FullName -ChildPath "prefs.js" 
            
                if (Test-Path -Path $prefsFilePath)
                {
                    # Read the content of prefs.js
                    $prefsFileContent = Get-Content -Path $prefsFilePath
                    
                    # Check if the safe browsing entry exists and set to false
                    $safeBrowsingMalwareDisabled = $prefsFileContent -match 'user_pref\("browser.safebrowsing.malware.enabled", false\);'
                    $safeBrowsingPhishingDisabled = $prefsFileContent -match 'user_pref\("browser.safebrowsing.phishing.enabled", false\);'
    
                    if ($safeBrowsingMalwareDisabled)
                    {
                        Add-Content -Path $filename -Value "[Firefox] Safe browsing for malware is disabled for `"$username`" in $prefsFilePath"
                    }
                    else
                    {
                        Add-Content -Path $filename -Value "[Firefox] Safe browsing for malware is enabled or not set for `"$username`" in $prefsFilePath"
                    }

                    if ($safeBrowsingPhishingDisabled)
                    {
                        Add-Content -Path $filename -Value "[Firefox] Safe browsing for phishing is disabled for `"$username`" in $prefsFilePath"
                    }
                    else
                    {
                        Add-Content -Path $filename -Value "[Firefox] Safe browsing for phishing is enabled or not set for `"$username`" in $prefsFilePath"
                    }
                }
                else
                {
                    Add-Content -Path $filename -Value "[Firefox] Could not find prefs.js file in for `"$username`" in $directory.FullName"
                }
            } 
        }
        else
        { 
            Add-Content -Path $filename -Value "[Firefox] Could not find a profiles directory for `"$username`" in default location (not installed)"
        }

        ## Chrome (Safe Browsing)
        if (Test-Path -Path $chromeDataPath) 
        {
            $chromeProfileDirs = Get-ChildItem $chromeDataPath -Directory | Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" }

            foreach ($chromeProfileDir in $chromeProfileDirs)
            {
                # Full path of the Preferences file inside current directory
                $chromePrefsFilePath = Join-Path -Path $chromeProfileDir.FullName -ChildPath "Preferences" 

                if (Test-Path -Path $chromePrefsFilePath)
                {
                    # Read the content of prefs.js
                    $chromePrefsFileContent = Get-Content -Path $chromePrefsFilePath -Raw | ConvertFrom-Json
                                                              
                    if ($chromePrefsFileContent.safebrowsing.enabled -eq "False")
                    {
                        Add-Content -Path $filename -Value "[Chrome] Safe browsing is disabled for `"$username`" in $chromePrefsFilePath"
                    }
                    else
                    {
                        Add-Content -Path $filename -Value "[Chrome] Safe browsing is enabled for `"$username`" in $chromePrefsFilePath"
                    }
                }
                else
                {
                    Add-Content -Path $filename -Value "[Chrome] Could not find Preferences file for `"$username`" in $chromeProfileDir"
                }
            }
        }
        else
        { 
            Add-Content -Path $filename -Value "[Chrome] Could not find a profiles directory for `"$username`" in default location (not installed)"
        }


        ## Edge (Microsoft Defender SmartScreen)
        $registrypath = "HKU:\" + $usersid + "\Software\Microsoft\Edge\SmartScreenEnabled"
        $edgeSmartScreenStatus = Get-ItemPropertyValue "$registrypath" -Name "(Default)"

        if ($edgeSmartScreenStatus)
        {
            
            if ($edgeSmartScreenStatus -eq "0")
            {
                Add-Content -Path $filename -Value "[Edge] Safe Browsing is disabled for `"$username`" in registry setting $registrypath"
            }
            else
            {
                Add-Content -Path $filename -Value "[Edge] Safe Browsing is enabled for `"$username`" in registry setting $registrypath"
            }
        }
        else
        {
            Add-Content -Path $filename -Value "[Edge] Registry key for Safe Browsing $registrypath not found"
        }

    }
}
# Finished
Write-Host "`r`n# Finished. Output file stored at:" $filename
