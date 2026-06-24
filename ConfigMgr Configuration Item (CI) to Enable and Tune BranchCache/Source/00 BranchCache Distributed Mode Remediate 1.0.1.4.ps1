<# 
   .DISCLAIMER Use at your own risk. Test it. Change it to suit your setup. 
   If it breaks your sh*t we are most definitely NOT to blame. We have alibis.
   
   .SYNOPSIS 
    Remediate Branchcache port and configures that branchcache service

   .DESCRIPTION
    1. Set the required Port Number for P2P transfers
    2. Configure the BranchCache Service for Distributed MOde
    3. Delete the old reservation on port 80 if it's still there
    4. Sets the Cache data TTL value
    5. Configures the BC service to Autostart and starts it
    6. Configures the Windows Firewall
    7. Creates a Logfile in the C:\Windows\Temp folder



    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.1.3
    DATE: 30 March 2021 
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 12/10/2017  :  added check for the old port 80 reservation -  deletes it if exist
    1.0.0.3 : 12/10/2017  :  Sets firewall rules to the correct port - SCCM can create multiple rules which aren't all set by default
    1.0.0.4 : 12/10/2017  :  Consolidated the Port Check and service check into one to reduce errors
    1.0.0.5 : 12/10/2017  :  Added Battery Check 'Serve Peers on Battery' - set to TRUE/FALSE
    1.0.0.6 : 09/06/2018  : Changed the order of things and added a service stop. Also added Cache TTL
    1.0.0.7 : 14/08/2018  : Removes all BC Firewall Rules first - and then re-adds them later. Also removes Hosted Cache Rules.
    1.0.0.8 : 16/08/2018  : Added a check to see if the Windows Firewall is in play - if not - no point fiddling!
    1.0.0.9 : 23/07/2019  : Improved url reservation handling - changed the order a little
    1.0.1.0 : 12/08/2019  : Improved url reservation handling to remove old url if the port is changed
    1.0.1.1 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.1.2 : 5/3/2021    : Added support for non-English languages and added a 'clear event log' step
    1.0.1.3 : 23/3/2021   : Remove Firewall detection as it has proved unreliable

   .LINK
    https://2pintsoftware.com
#>

$Logfile = "C:\Windows\Temp\BCTuner_Main_Remediation.log"

# Delete any existing logfile if it exists
If (Test-Path $Logfile){Remove-Item $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}

Function Write-Log{
	param (
    [Parameter(Mandatory = $true)]
    [string]$Message
   )

   $TimeGenerated = $(Get-Date -UFormat "%D %T")
   $Line = "$TimeGenerated : $Message"
   Add-Content -Value $Line -Path $LogFile -Encoding Ascii

}

# EDIT THIS VARIABLE TO THE PORT THAT YOU WANT BRANCHCACHE TO USE
# THIS SHOULD BE THE SAME AS THE EQUIVALENT IN THE DISCOVERY SCRIPT
#--------------<<<<<
$BCPort = 1337
#--------------<<<<<
# SET THIS VARIABLE TO DETERMINE IF CLIENTS CAN SERVE PEERS WHILE ON BATTERY
# TRUE/FALSE
#-----------------------<<<<<
$ServeOnBattery = "TRUE"
#-----------------------<<<<<

# SET THIS VARIABLE to set the TTL  - this is the time (Days) that BranchCache will keep content in the cache
#-----------------------<<<<<
$TTL = 180
#-----------------------<<<<<

$RegPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers'
$TTLRegPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PeerDist'
$SetBCCommand = {netsh branchcache set service mode=distributed serveonbattery=$ServeOnBattery}
$ShowHttpUrl = netsh http show url
$DeleteResCmd = {netsh http delete urlacl url=$urlToDelete}
$DisableBCCommand = {netsh branchcache set service mode=disabled}

Write-Log "BC Port, Firewall and Service Remediation is Running"

#================================================================
# If Windows Server, add BranchCache feature if not installed
#================================================================

$OSCaption = (Get-WmiObject win32_operatingsystem).caption
If ($OSCaption -like "*Windows Server*"){
    Write-Log "OS is a server, check for BranchCache feature" 
    $Result=Get-WindowsFeature BranchCache

    If($Result.Installed -eq $true){
        Write-Log "BranchCache feature found, all ok, continuing" 
    }
    Else{
        Write-Log "BranchCache feature not found, adding it" 
        Install-WindowsFeature BranchCache
    }
}


#---------------------------------------------------------------------------------------
# Stop BranchCache (Only if installed) 
#---------------------------------------------------------------------------------------
$s = Get-Service -name PeerDistSvc -ErrorAction SilentlyContinue

If ($s){
    Stop-Service $s.name -Force
}

#---------------------------------------------------------------------------------------
# Set the correct BranchCache ListenPort in the registry
#---------------------------------------------------------------------------------------
# If the key doesn't exist - create it, and set the port, job done

if (!(Get-Item -path $RegPath\Connection -ErrorAction SilentlyContinue)){
    Write-Log "Custom BC Port Reg Key didn't exist - remediating"
    New-Item -Path $RegPath -name Connection -force
    New-ItemProperty -Path $RegPath\Connection -Name ListenPort -PropertyType DWORD -Value $BCPort
    New-ItemProperty -Path $RegPath\Connection -Name ConnectPort -PropertyType DWORD -Value $BCPort
}

# If the key already exists, check the ListenPort value and change if required
if((Get-ItemProperty -path $RegPath\Connection -Name ListenPort -ErrorAction SilentlyContinue).ListenPort -ne $BCPort){
    Write-Log "Custom BC ListenPort Reg value exists but is incorrect - remediating"
    Set-ItemProperty -Path $RegPath\Connection -Name ListenPort -Value $BCPort
}

# If the key already exists, check the ConnectPort value and change if required
if((Get-ItemProperty -path $RegPath\Connection -Name ConnectPort -ErrorAction SilentlyContinue).ConnectPort -ne $BCPort){
    Write-Log "Custom BC ConnectPort Reg value exists but is incorrect - remediating"
    Set-ItemProperty -Path $RegPath\Connection -Name ConnectPort -Value $BCPort
}

#---------------------------------------------------------------------------------------
# Set the correct TTL - this is the time (Days) that BranchCache will keep content in the cache
#---------------------------------------------------------------------------------------
# If the key doesn't exist - create it, and set the TTL, job done

if (!(Get-Item -path $TTLRegPath\Retrieval -ErrorAction SilentlyContinue)){
        New-Item -Path $TTLRegPath -name Retrieval -force  
        New-ItemProperty -Path $TTLRegPath\Retrieval -Name SegmentTTL -PropertyType DWORD -Value $TTL  
}
# If the key already exists, check the value and change if required
if(((Get-ItemProperty -path $TTLRegPath\Retrieval -Name SegmentTTL -ErrorAction SilentlyContinue).SegmentTTL) -ne $TTL){
    Set-ItemProperty -Path $TTLRegPath\Retrieval -Name SegmentTTL -Value $TTL  
}

Write-Log "BranchCache TTL Remediation Complete"


#---------------------------------------------------------------------------------------
# Remove existing F/W Rules (if it's enabled) in case they are a mess!
#---------------------------------------------------------------------------------------

    Write-Log "Removing old F/W Rules"

    #Remove Content Retrieval Rules (IN/OUT)
    netsh advfirewall firewall delete rule name="BranchCache Content Retrieval (HTTP-Out)"
    netsh advfirewall firewall delete rule name="BranchCache Content Retrieval (HTTP-In)"

    #Remove Content Discovery Rules (IN/OUT)
    netsh advfirewall firewall delete rule name="BranchCache Peer Discovery (WSD-Out)"
    netsh advfirewall firewall delete rule name="BranchCache Peer Discovery (WSD-In)"


#---------------------------------------------------------------------------------------
# END Remove existing F/W Rules in case they are a mess!
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
# Enable BranchCache distributed mode (this also sets the correct 'Serve Peers on Battery' Mode)
# It will also re-create the F/W Rules
#---------------------------------------------------------------------------------------
Write-Log "Setting BranchCache service to Distributed Mode"
Invoke-Command -ScriptBlock $SetBCCommand

#---------------------------------------------------------------------------------------
# Clear the BC Event Log so that subsequent discoveries don't pickup old events
#---------------------------------------------------------------------------------------
Write-Log "Clearing the Event Log"
Function Clear-WinEvent { 
[CmdletBinding(SupportsShouldProcess=$True)]
Param
([String]$LogName)
Process {
If ($PSCmdlet.ShouldProcess("$LogName", "Clear log file")) 
              {
[System.Diagnostics.Eventing.Reader.EventLogSession]::`
GlobalSession.ClearLog("$LogName")
              } # End of If
        } # End of Process
} # End of creating the function

# Calling the function Clear-WinEvent 
Clear-Host
$BCLog = "Microsoft-Windows-BranchCache/Operational"
Get-WinEvent -ListLog $BCLog
Clear-WinEvent -LogName $BCLog


#---------------------------------------------------------------------------------------
# Set the service to auto-start and start it if not running
#---------------------------------------------------------------------------------------
Set-Service -Name "peerdistsvc" -StartupType automatic
if ((Get-Service -Name PeerDistSvc).Status -ne "Running"){
    Start-Service -Name PeerdistSvc
}

#---------------------------------------------------------------------------------------
# Remove the old existing URL reservation i.e remove any BranchCache url reservation that DOES NOT have the current Port
#---------------------------------------------------------------------------------------

# Checking for old obsolete port reservations - first, select all BranchCache url reservations
$ResList = ($ShowHttpUrl | Select-String -SimpleMatch -Pattern "/116B50EB-ECE2-41ac-8429-9F9E963361B7/")

ForEach($Res in $ResList){

    $a = [regex]::Matches($Res, 'http(.*)')
    If($a -like "http://+:$BCPort*"){
        Write-Log "Not deleting the current URL: $a"
    }
    else{
        $urlToDelete=$a.Value.Trim()
        Invoke-Command -scriptblock $DeleteResCmd | Out-File $Logfile -Append 
    }
 
}
