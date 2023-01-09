# Host-based-Security-Info-Collector
Powershell script that generates a TXT file with security related information about a specific host.

Steps:
1. Run "Windows PowerShell" app "as Administrator" from Windows start menu
2. In PowerShell run "Get-ExecutionPolicy" to view your current PowerShell Execution Policy (Windows default: restricted)
3. In PowerShell run "Set-ExecutionPolicy Unrestricted" to be able to run this script.
4. Go to the directory containing this script and execute it in PowerShell: ".\HSIC.ps1"
5. In PowerShell run "Set-ExecutionPolicy Restricted" to restore the PowerShell Execution Policy to it's original state (might be different than the current default)
