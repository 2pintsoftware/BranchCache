<# 
   .SYNOPSIS 
    Checks Branchcache is Using Desired Port and that the service is running

   .DESCRIPTION
    Checks for event 7,8 in the BC event log - means that F/W is blocking BC
    Checks that the Branchcache has been configured to use a specificTCP port
    Checks  the Branchcache Cache TTL value
    Checks that the BranchCache service is set to 'Distributed Caching' mode
    Checks the 'serve peers on battery power' capability
    Finally - checks that the service is running and is set to AutoStart
    If ANY of these checks fail - a status of Non-Compliance is reported 
    Creates a Logfile in the TEMP folder


NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    VERSION: 1.0.0.7
    DATE: 12/08/2019 
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 added logging and other minor tweaks
    1.0.0.3 : 08/06/2018  : added some more logic for checking svc auto-start and state..
    1.0.0.4 : 09/06/2018  : consolidated the 'Serve Peers on Battery' and 'Cache TTL' check into this script
    1.0.0.5 : 26/06/2018  : Added BranchCache Firewall Error Event check
    1.0.0.6 : 23/07/2019  : Improved Port  compliance checking
    1.0.0.7 : 12/08/2019  : Improved Port  checking - added ConnectPort (we were only checking ListenPort before)

   .LINK
    https://2pintsoftware.com
#>
Function TimeStamp {$(Get-Date -UFormat "%D %T")}  
$Logfile = "$ENV:TEMP\BCTuner_Discovery00.log"
#delete any existing logfile if it exists
If (Test-Path $Logfile){ri $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}
$(TimeStamp) + " : BC Port, Firewall and Service Check is Running   " | Out-File $Logfile -Append


#Set this variable to the port number that you wanna check/change - if you want to leave it at the default BC port you MUST set this to 80
#THIS SHOULD BE THE SAME AS THE EQUIVALENT VARIABLE IN THE REMEDIATION SCRIPT
#--------------
$BCPort = 1337
#--------------
#SET THIS VARIABLE TO DETERMINE IF CLIENTS CAN SERVE PEERS WHILE ON BATTERY POWER
#--------------
$ServeOnBattery = "TRUE"
#--------------

#Set this variable to check the cache TTL  - this is the time (Days) that BranchCache will keep content in the cache
#-----------------------
$TTL = 180
#-----------------------


# First we assume the client is compliant
$Compliance = "Compliant"
#================================================================
# Check the event log for events 7,8 - meaning that BC+P2P is blocked
#================================================================

$EventLogName = "Microsoft-Windows-BranchCache/Operational"
$TSpan = (Get-Date) - (New-TimeSpan -Hour 4)

#check if the BC evt log exists and returns a result (or evt 7 or 8) - if not - then we are Compliant
$log = try { 
Get-WinEvent -LogName "Microsoft-Windows-BranchCache/Operational" | Where-Object {$_.TimeCreated -ge $TSpan -and ($_.ID -eq 7 -or $_.ID -eq 8)}
           }
catch [Exception] {
        if ($_.Exception -match "There is not an event log") {
        $(TimeStamp) + " No BC event log found" | Out-File -FilePath $Logfile -Append -Encoding ascii;
                                                             }
                  }
#if no results then we are compliant (either no log found or no results returned)
if (!$log)
{
$Compliance = "Compliant"
}
#If the above query returns a result - set the status to Non-Compliant 
Else
{
    $Compliance = "Firewall Event Check Non-Compliant"
        $(TimeStamp) + " : BC Firewall Events check - failed" | Out-File $Logfile -Append
        $(TimeStamp) + " : BC Port Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Firewall Event Check Returned - " + $Compliance | Out-File $Logfile -Append


#=========================================================
# Call netsh to carry out a match against the status
#=========================================================
$(TimeStamp) + " : Here's the output of netsh http show url " | Out-File $Logfile -Append
$ShowHttpUrl = netsh http show url
netsh http show url  | Out-File $Logfile -Append
# Checking the port has been set - for both listen and connect ports
$BCUrlRes = $myvar = [bool]($ShowHttpUrl | Select-String -SimpleMatch -Pattern "http://+:$BCPort/116B50EB-ECE2-41ac-8429-9F9E963361B7/")
$BCListenPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ListenPort -ErrorAction SilentlyContinue).ListenPort) -eq $BCPort
$BCConnectPortReg = ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\DownloadManager\Peers\Connection' -Name ConnectPort -ErrorAction SilentlyContinue).ConnectPort) -eq $BCPort

if($BCUrlRes -eq $true -and $BCListenPortReg -eq $true -and $BCConnectPortReg -eq $true)

{
    $Compliance = "Compliant"
}
else
{
    $Compliance = "BranchCache Port Non-Compliant"
        $(TimeStamp) + " : BC Service correct Listening or Connect Port not set" | Out-File $Logfile -Append
        $(TimeStamp) + " : BC Port Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Port Check Returned - " + $Compliance | Out-File $Logfile -Append

#=========================================================
#Next Check that the BranchCache Cache TTL is set correctly
#=========================================================

if( (Get-ItemProperty -path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Retrieval' -Name SegmentTTL -ErrorAction SilentlyContinue).SegmentTTL -eq $TTL)
{
    $Compliance = "Compliant"
}
else
{
    $Compliance = "BC Cache TTL Non-Compliant"
    $(TimeStamp) + " : BC Cache TTL not setup correctly " | Out-File $Logfile -Append
    $(TimeStamp) + " : BC Cache TTL Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Cache TTL Check Returned - " + $Compliance | Out-File $Logfile -Append


#=========================================================
#Next Check that the BranchCache service is enabled and set to Distributed Caching
#=========================================================

# Call netsh to carry out a match against the status
$ShowStatusAllCommand = {netsh branchcache show status all}
$ShowStatusAll = Invoke-Command -ScriptBlock $ShowStatusAllCommand

# Checking status - if the previous check for BC Port number was Compliant AND the service is setup correctly - we're OK
if((@($ShowStatusAll | Select-String -SimpleMatch -Pattern "Service Mode")[0].ToString() -match "= Distributed Caching") -and ($Compliance -eq "Compliant"))
{
    $Compliance = "Compliant"
}
else
{
    $Compliance = "BC Mode Non-Compliant"
    $(TimeStamp) + " : BC Service not setup correctly " | Out-File $Logfile -Append
    $(TimeStamp) + " : BC Svc Distributed Mode Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Svc Distributed Mode Check Returned - " + $Compliance | Out-File $Logfile -Append

#=========================================================
#Next Check the BranchCache SERVE ON BATTERY is set to your preferred setting
#=========================================================

switch ($ServeOnBattery)
{
    TRUE {$ServeOnBattery = "= Enabled"}
    FALSE{$ServeOnBattery = "= Disabled"}
}

if(@($ShowStatusAll | Select-String -SimpleMatch -Pattern "Serve peers on battery power")[0].ToString() -match $ServeOnBattery) 
{
   $Compliance = "Compliant"
}
else
{   
    $Compliance = "BC Battery Mode Non-Compliant"
    $(TimeStamp) + " : BC Serve Peers on Battery not setup correctly " | Out-File $Logfile -Append
    $(TimeStamp) + " : BC Battery Check Mode Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Battery Check Mode Check Returned - " + $Compliance | Out-File $Logfile -Append

#=========================================================
#finally check the branchcache service is started and is set to auto-start
#=========================================================
$s = gwmi -Query "Select State, StartMode From Win32_Service Where Name='peerdistsvc'"

if (($s.StartMode -eq "Auto") -and ($s.State -eq "Running"))
{
    $Compliance = "Compliant"
}
else
{
    $Compliance = " BC Svc State Non-Compliant"
    $(TimeStamp) + " : BC Service not set to Autostart " | Out-File $Logfile -Append
    $(TimeStamp) + " : BC Svc startup Check Returned - " + $Compliance | Out-File $Logfile -Append
    Return $Compliance
}

$(TimeStamp) + " : BC Svc startup Check Returned - " + $Compliance | Out-File $Logfile -Append
Return $Compliance
