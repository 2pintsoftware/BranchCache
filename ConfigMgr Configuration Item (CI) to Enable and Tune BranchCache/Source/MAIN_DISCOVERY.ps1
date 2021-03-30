<# 
   .SYNOPSIS 
    Checks Branchcache is Using Desired Port and that the service is running

   .DESCRIPTION
    1. Checks for event 7,8 in the BC event log - means that F/W is blocking BC
    2. Checks that the Branchcache has been configured to use a specificTCP port
    3. Checks  the Branchcache Cache TTL value
    4. Checks that the BranchCache service is set to 'Distributed Caching' mode
    5. Checks the 'serve peers on battery power' capability
    6. Finally - checks that the service is running and is set to AutoStart
    7. If ANY of these checks fail - a status of Non-Compliance is reported 
    8. Creates a Logfile in the C:\Windows\Temp folder


NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.1.3
    DATE: 23 March 2021
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 12/10/2017  : added logging and other minor tweaks
    1.0.0.3 : 08/06/2018  : added some more logic for checking svc auto-start and state..
    1.0.0.4 : 09/06/2018  : consolidated the 'Serve Peers on Battery' and 'Cache TTL' check into this script
    1.0.0.5 : 26/06/2018  : Added BranchCache Firewall Error Event check
    1.0.0.6 : 23/07/2019  : Improved Port compliance checking
    1.0.0.7 : 12/08/2019  : Improved Port checking - added ConnectPort (we were only checking ListenPort before)
    1.0.0.8 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.0.9 : 5/3/2021    : Added support for non-English languages
    1.0.1.0 : 23/3/2021   : Added another check for firewall issues using netsh

   .LINK
    https://2pintsoftware.com
#>

$Logfile = "C:\Windows\Temp\BCTuner_Main_Discovery.log"

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

Write-Log "BC Port, Firewall and Service Check is Running"

# Set this variable to the port number that you wanna check/change - if you want to leave it at the default BC port you MUST set this to 80
# THIS SHOULD BE THE SAME AS THE EQUIVALENT VARIABLE IN THE REMEDIATION SCRIPT
#--------------
$BCPort = 1337
#--------------
# SET THIS VARIABLE TO DETERMINE IF CLIENTS CAN SERVE PEERS WHILE ON BATTERY POWER
#--------------
$ServeOnBattery = "TRUE"
#--------------

# Set this variable to check the cache TTL  - this is the time (Days) that BranchCache will keep content in the cache
#-----------------------
$TTL = 180
#-----------------------


# First we assume the client is compliant
$Compliance = "Compliant"

#================================================================
# If Windows Server, check if BranchCache feature has been added
#================================================================

$OSCaption = (Get-WmiObject win32_operatingsystem).caption
If ($OSCaption -like "*Windows Server*"){
    Write-Log "OS is a server, check for BranchCache feature" 
    $Result=Get-WindowsFeature BranchCache

    If($Result.Installed -eq $true){
        $Compliance = "Compliant"
    }
    Else{
        $Compliance = "Feature Check Non-Compliant"
        Write-Log "Feature Check check - failed" 
        Write-Log "Feature Check Returned - $Compliance"
        Return $Compliance
    }
}



#================================================================
# Check the event log for events 7,8 - meaning that BC+P2P is blocked
#================================================================

$EventLogName = "Microsoft-Windows-BranchCache/Operational"

# Check if the BC evt log exists and returns a result (or evt 7 or 8) - if not - then we are Compliant
$log = try{ 
Get-WinEvent -LogName $EventLogName -ErrorAction Stop | Where-Object {$_.ID -eq 7 -or $_.ID -eq 8} 
          }

catch {
    Write-log "No BC event log found or the log is empty" 
      }


# If no results then we are compliant (either no log found or no results returned)
if (!$log){
    $Compliance = "Compliant"
}
# If the above query returns a result - set the status to Non-Compliant 
Else{
    $Compliance = "Firewall Event Check Non-Compliant"
    Write-Log "BC Firewall Events check - failed" 
    Write-Log "BC Firewall Events Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Firewall Event Check Returned - $Compliance"

#=========================================================
# Next Check that the netsh output for the firewall is ok
#=========================================================

# Call netsh to carry out a match against the status
$ShowStatusAllCommand = {netsh branchcache show status all}
$ShowStatusAll = Invoke-Command -ScriptBlock $ShowStatusAllCommand
$ShowStatusAllMsg = $ShowStatusAll | Out-String
Write-Log "netsh (show status all) output:"
Write-Log $ShowStatusAllMsg

$fw = try{
($ShowStatusAll | Select-String -SimpleMatch -Pattern "Error Executing Action Display Firewall Rule Group Status:")[0].ToString() -match "Could not query Windows Firewall configuration"
         }
catch [Exception]{
    if (($_.Exception -match "You cannot call a method on a null-valued expression") -or ($_.Exception -match "Cannot index into a null array")){
    Write-Log "No Firewall error reported" 
    }
}

# If no results then we are compliant (no firewall error )
if (!$fw){
    $Compliance = "Compliant"
         }
# If the above query returns a result - set the status to Non-Compliant 
Else{
    $Compliance = "Firewall Non-Compliant"
    Write-Log "Firewall not setup correctly " 
    Write-Log "Firewall Check Returned - $Compliance"
    Return $Compliance
    }

Write-Log "BC Firewall netsh Check Returned - $Compliance"

#=========================================================
# Call netsh to carry out a match against the status
#=========================================================
$ShowHttpUrl = netsh http show url
# Checking the port has been set - for both listen and connect ports
$BCUrlRes = $myvar = [bool]($ShowHttpUrl | Select-String -SimpleMatch -Pattern "http://+:$BCPort/116B50EB-ECE2-41ac-8429-9F9E963361B7/")
$BCListenPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ListenPort -ErrorAction SilentlyContinue).ListenPort) -eq $BCPort
$BCConnectPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ConnectPort -ErrorAction SilentlyContinue).ConnectPort) -eq $BCPort

if($BCUrlRes -eq $true -and $BCListenPortReg -eq $true -and $BCConnectPortReg -eq $true){
    $Compliance = "Compliant"
}
else{
    $Compliance = "BranchCache Port Non-Compliant"
    Write-Log "BC Service correct Listening or Connect Port not set"
    Write-Log "BC Port Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Port Check Returned - $Compliance"

#=========================================================
#Next Check that the BranchCache Cache TTL is set correctly
#=========================================================

if((Get-ItemProperty -path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Retrieval' -Name SegmentTTL -ErrorAction SilentlyContinue).SegmentTTL -eq $TTL){
    $Compliance = "Compliant"
}
else{
    $Compliance = "BC Cache TTL Non-Compliant"
    Write-Log "BC Cache TTL not setup correctly"
    Write-Log "BC Cache TTL Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Cache TTL Check Returned - $Compliance"

#=========================================================
# Next Check that the BranchCache service is enabled and set to Distributed Caching
#=========================================================

# Call netsh to carry out a match against the status
$ShowStatusCommand = {netsh branchcache show status}
$ShowStatus = Invoke-Command -ScriptBlock $ShowStatusCommand
$ShowStatusMsg = $ShowStatus | Out-String
WRite-Log "netsh output:"
Write-Log $ShowStatusMsg
# Checking status - if the previous check for BC Cache TTL was Compliant AND the service is setup correctly - we're OK
if((@($ShowStatus | Select-String -SimpleMatch -Pattern "Distributed Caching")[0].ToString() -match "Distributed Caching") -and ($Compliance -eq "Compliant")){

    $Compliance = "Compliant"
}
else{
    $Compliance = "BC Mode Non-Compliant"
    Write-Log "BC Service not setup correctly " 
    Write-Log "BC Svc Distributed Mode Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Svc Distributed Mode Check Returned - $Compliance"

#=========================================================
# Next Check the BranchCache SERVE ON BATTERY is set to your preferred setting
#=========================================================

switch ($ServeOnBattery){
    TRUE {$ServeOnBattery = 1}
    FALSE{$ServeOnBattery = 0}
}

if((Get-ItemProperty -path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Upload' -Name ServePeersOnBatteryPower -ErrorAction SilentlyContinue).ServePeersOnBatteryPower -eq $ServeOnBattery){
    $Compliance = "Compliant"
}
else{   
    $Compliance = "BC Battery Mode Non-Compliant"
    Write-Log "BC Serve Peers on Battery not setup correctly "
    Write-Log "BC Battery Check Mode Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Battery Check Mode Check Returned - $Compliance"

#=========================================================
# Finally check the branchcache service is started and is set to auto-start
#=========================================================
$s = gwmi -Query "Select State, StartMode From Win32_Service Where Name='peerdistsvc'"

if (($s.StartMode -eq "Auto") -and ($s.State -eq "Running")){
    $Compliance = "Compliant"
}
else{
    $Compliance = " BC Svc State Non-Compliant"
    Write-Log "BC Service not set to Autostart " 
    Write-Log "BC Svc startup Check Returned - $Compliance"
    Return $Compliance
}

Write-Log "BC Svc startup Check Returned - $Compliance"
Return $Compliance
