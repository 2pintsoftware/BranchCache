<#
.SYNOPSIS
  Get-BCDataCacheReconfigureFromEventLog.ps1

.DESCRIPTION
  Enumerates all items in the eventlog under Microsoft-Windows-BranchCache/Operational with ID 5 to find if the BranchCache DataCache size have been changed

.NOTES
  Version:        1.0
  Author:         MB @ 2Pint Software
  Creation Date:  2023-08-24
  Purpose/Change: Initial script development

.LINK
  https://2pintsoftware.com

#>

$startdate = (Get-date).AddDays(-30)
$events = Get-WinEvent -FilterHashtable @{ Logname='Microsoft-Windows-BranchCache/Operational'; ID=5; StartTime=$startdate}


foreach($event in $events)
{
    [xml]$XMLEvent = $event.ToXml()
    if($XMLEvent.Event.UserData.ConfigChangeEvent)
    {
        $ConfigChangeEvent = $XMLEvent.Event.UserData.ConfigChangeEvent
        if($ConfigChangeEvent.SubKey -eq "CacheMgr\Republication")
        {
            $timeStamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [dateTime]$XMLEvent.Event.System.TimeCreated.SystemTime
            Write-host "$timeStamp : $($ConfigChangeEvent.Subkey) setting $($ConfigChangeEvent.ValueName) was changed to $($ConfigChangeEvent.UInt32)"
        }
    }
}