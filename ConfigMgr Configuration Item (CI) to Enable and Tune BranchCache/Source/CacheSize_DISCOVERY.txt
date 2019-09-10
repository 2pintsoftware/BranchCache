<# 
   .SYNOPSIS 
    Checks size of branchcache

   .DESCRIPTION
    Checks that the current size of the branch cache is still correct 
     Note  that the default in this script are fairly conservative - so feel free to be more agressive with the cache size!

   .NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    VERSION: 1.0.0.2
    DATE:10/06/2018 
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script 
    1.0.0.2 : 10/06/2018  : Added a bit more logging

   .LINK
    https://2pintsoftware.com
#> 

Function TimeStamp {$(Get-Date -UFormat %T)} 
$Logfile = "$ENV:TEMP\BCTuner_Cache_Discovery00.log"
#delete any existing logfile if it exists
If (Test-Path $Logfile){ri $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}

#=======================================
# Get the free space on the system disk as %
#=======================================
Function Get-FreeSystemDiskspace
{
    # Get the free space from WMI and return as %
    $SystemDrive = Get-WmiObject Win32_LogicalDisk  -Filter "DeviceID='$env:SystemDrive'"
    [int]$ReturnVal = $Systemdrive.FreeSpace*100/$Systemdrive.Size
    return $ReturnVal
}
#==============
# End Function
#==============

#=============================================================================
# Selects the best cache size based on free diskspace - EDIT THE DEFAULTS HERE
#=============================================================================
Function Check-BranchCachesize
{
    param([int]$CurrentFreeSpace)
    begin
    {
        switch($CurrentFreeSpace)
        {
            {$_ -lt 10}{$NewCachePercent = 2} #if less than 10% new cache should be 2%
            {$_ -lt 50 -and $_ -ge 10}{$NewCachePercent = 5} #if less than 50%  but more than 10% new cache should be 5%
            {$_ -ge 50}{$NewCachePercent = 10}#if more than 50% new cache should be 10%
            default{$NewCachePercent = 5}#default value
        }
    Return $NewCachePercent
    }
}
#==============
# End Function
#==============
$(TimeStamp) + " : BC Cache Size Check is Running   " | Out-File $Logfile -Append


# First we assume the client is compliant
$Compliance = "Compliant"

#==============================================================
# Get the size available and then return the cache space needed
#==============================================================
$FreeSpaceAvailable = Get-FreeSystemDiskspace
$CacheSize  = Check-BranchCachesize -CurrentFreeSpace $FreeSpaceAvailable

$(TimeStamp) + " : Free Space Check Returned:   " + $FreeSpaceAvailable + "%" | Out-File $Logfile -Append
$(TimeStamp) + " : Cache size should be:   " + $CacheSize + "%" | Out-File $Logfile -Append

#==============================================================
# Call netsh to carry out a match against the status
#==============================================================
$ShowStatusAllCommand = {netsh branchcache show status all}
$ShowStatusAll = Invoke-Command -ScriptBlock $ShowStatusAllCommand
# Checking cache size has been set
if(@($ShowStatusAll | Select-String -SimpleMatch -Pattern "Maximum Cache Size")[0].ToString() -match "$CacheSize% of hard disk")
{
    $Compliance = "Compliant"
}
else
{
    $Compliance = "Non-Compliant"
}

$(TimeStamp) + " : BC Cache Size Check Returned:   " + $Compliance | Out-File $Logfile -Append
$Compliance