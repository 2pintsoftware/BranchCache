<# 
   .SYNOPSIS 
 Sets the Branchcache Cache size

   .DESCRIPTION
 Sets the Branchcache Cache according to free disk space % so that as disk space reduces the cache can be auto-adjusted
 Note  that the default in this script are fairly conservative - so feel free to be more agressive with the cache size!


   .NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    TUNER VERSION: 1.0.1.3
    DATE:23 March 2021 
    
    CHANGE LOG: 
    1.0.0.0 : 12/10/2017  : Initial version of script
    1.0.0.2 : 10/06/2018  : Added a bit more logging 
    1.0.0.3 : 8/7/2020    : Added support for Windows Server and improved logging
    1.0.0.4 : 5/3/2021    : Slight tweak to cache size calc

   .LINK
    https://2pintsoftware.com
#> 

$Logfile = "C:\Windows\Temp\BCTuner_Cache_Remediation.log"

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

#================================================================================
# Selects the best cache size based on free diskspace - edit these to your preferences
#================================================================================
Function Check-BranchCachesize{
    param([int]$CurrentFreeSpace)
    begin{
        switch($CurrentFreeSpace){
            {$_ -lt 10 -and $_ -ge 5}{$NewCachePercent = 5} #if less than 10% but more than 5% new cache should be 5%
            {$_ -lt 50 -and $_ -ge 10}{$NewCachePercent = 10} #if less than 50%  but more than 10% new cache should be 10%
            {$_ -lt 75 -and $_ -ge 50}{$NewCachePercent = 20}##if less than 75% but more than 50% new cache should be 20%
            {$_ -ge 75}{$NewCachePercent = 50}##if more than 75% new cache should be 50%
            default{$NewCachePercent = 5}#default value
        }
    Return $NewCachePercent
    }
}
#==============
# End Function
#==============

Write-Log "BC Cache Size Remediation is Running"

# Get the size available and then return the cache space needed
$FreeSpaceAvailable = Get-FreeSystemDiskspace
$CacheSize  = Check-BranchCachesize -CurrentFreeSpace $FreeSpaceAvailable

Write-Log "Free Space Check Returned: $FreeSpaceAvailable %" 
Write-Log "Cache size should be: $CacheSize %"
Write-Log "Setting the new cache size"

# Call netsh to set the new cache size
$CacheSizeCmd = {netsh branchcache set cachesize size=$CacheSize percent=TRUE}
Invoke-Command -ScriptBlock $CacheSizeCmd | Out-File $Logfile -Append
Write-Log "BC Cache Size Remediation is Completed"
