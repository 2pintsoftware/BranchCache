<#
.SYNOPSIS
    Analyzes BranchCache monitoring logs and provides detailed information about peers and events.

.DESCRIPTION
    This script is designed to help administrators analyze BranchCache monitoring logs. It provides a menu-driven interface to clear logs, disable logs, clear the BranchCache cache, and resolve peer information from log events.

.EXAMPLE
    .\Invoke-BCMonitorAnalyzer.ps1


.NOTES
    Version:        1.0
    Author:         Mattias Benninge @ 2Pint Software
    Creation Date:  2026-06-25
    Purpose/Change: Initial script development
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    #[string]$LogPath
)

$ErrorActionPreference = 'Continue'

function Write-Header {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-SubHeader {
    param([string]$Title)
    Write-Host "`n  --- $Title ---" -ForegroundColor Yellow
}

function Pause-ForUser {
    Write-Host "`nPress Enter to continue..." -ForegroundColor DarkGray
    $null = Read-Host
}

function Get-ComputerNameFromIPv6 {
 param (
    [Parameter(Mandatory = $true)]
    [string]$IPv6Address
)

try {
    # Validate IPv6 format
    if (-not [System.Net.IPAddress]::TryParse($IPv6Address, [ref]$null)) {
        throw "Invalid IP address format: $IPv6Address"
    }

    # Attempt DNS resolution
    $result = Resolve-DnsName -Name $IPv6Address -ErrorAction Stop

    # Filter for PTR (reverse lookup) records
    $hostname = ($result | Where-Object { $_.QueryType -eq 'PTR' }).NameHost

    if ($hostname) {
        Write-Output "Computer name for $IPv6Address is: $hostname"
    }
    else {
        Write-Output "No PTR record found for $IPv6Address."
    }
}
catch {
    Write-Output "Error: $($_.Exception.Message)"
}
   
}

function Clear-BCMonitorLog {
    Write-SubHeader "Clearing and enabling BranchCacheMonitoring/Analytic log"
    wevtutil sl Microsoft-Windows-BranchCacheMonitoring/Analytic /e:false /q:true
    wevtutil cl Microsoft-Windows-BranchCacheMonitoring/Analytic
    wevtutil sl Microsoft-Windows-BranchCacheMonitoring/Analytic /e:true /q:true
    Write-Host "BranchCacheMonitoring/Analytic log cleared and enabled." -ForegroundColor Green
    Write-Host "You can now start the download and generate BC events." -ForegroundColor Green
    Pause-ForUser
    Show-BCMonitorMenu
}

function Disable-BCMonitorLog {
    Write-SubHeader "Disabling BranchCacheMonitoring/Analytic log"
    wevtutil sl Microsoft-Windows-BranchCacheMonitoring/Analytic /e:false /q:true
    Write-Host "BranchCacheMonitoring/Analytic log disabled." -ForegroundColor Green
    Pause-ForUser
    Show-BCMonitorMenu
}

function Clear-BCache {
    Write-SubHeader "Clearing BranchCache Cache"
    Clear-BCCache
    Write-Host "BranchCache cache cleared." -ForegroundColor Green
    Pause-ForUser
    Show-BCMonitorMenu
}

function Get-BCMonitorEventPayload {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $payload = @{}
    [xml]$eventXml = $Event.ToXml()

    if ($eventXml.Event.UserData) {
        foreach ($userNode in $eventXml.Event.UserData.ChildNodes) {
            foreach ($childNode in $userNode.ChildNodes) {
                $payload[$childNode.LocalName] = [string]$childNode.InnerText
            }
        }
    }

    if ($eventXml.Event.EventData) {
        $index = 0
        foreach ($dataNode in $eventXml.Event.EventData.Data) {
            $name = if ([string]::IsNullOrWhiteSpace($dataNode.Name)) {
                "Data$index"
            }
            else {
                [string]$dataNode.Name
            }

            $payload[$name] = [string]$dataNode.InnerText
            $index++
        }
    }

    return $payload
}

function Resolve-BCMonitorPeer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($Endpoint)) {
        return $Cache[$Endpoint]
    }

    $address = $Endpoint
    $port = $null

    if ($Endpoint -match '^\[(?<Address>[^\]]+)\](?::(?<Port>\d+))?$') {
        $address = $matches.Address
        $port = $matches.Port
    }
    elseif ($Endpoint -match '^(?<Address>[^:]+)(?::(?<Port>\d+))?$') {
        $address = $matches.Address
        $port = $matches.Port
    }

    $lookupAddress = $address -replace '%\d+$', ''
    $resolvedName = $null

    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($lookupAddress)
        if ($hostEntry.HostName -and $hostEntry.HostName -ne $lookupAddress) {
            $resolvedName = $hostEntry.HostName
        }
    }
    catch {
        try {
            $dnsResult = Resolve-DnsName -Name $lookupAddress -Type PTR -ErrorAction Stop |
                Where-Object { $_.NameHost } |
                Select-Object -First 1 -ExpandProperty NameHost

            if ($dnsResult) {
                $resolvedName = $dnsResult
            }
        }
        catch {
        }
    }

    $peerInfo = [pscustomobject]@{
        Endpoint     = $Endpoint
        Address      = $address
        LookupAddress = $lookupAddress
        Port         = $port
        ResolvedName = $resolvedName
    }

    $Cache[$Endpoint] = $peerInfo
    return $peerInfo
}

function Analyze-BCMonitorLog {
    param(
        [string]$LogPath
    )

    Write-SubHeader "Analyzing BranchCacheMonitoring data"

    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        Write-Host "Press Enter to analyze the live Microsoft-Windows-BranchCacheMonitoring/Analytic log." -ForegroundColor DarkGray
        Write-Host "Or enter an .evtx path, for example: .\2Pint\BranchCache\BCMon_Examples\BCMonitor_AllPeers_NoLocalCache.evtx" -ForegroundColor DarkGray
        $LogPath = Read-Host "Log path"
    }

    $useLiveLog = [string]::IsNullOrWhiteSpace($LogPath)
    $logLabel = if ($useLiveLog) {
        'Microsoft-Windows-BranchCacheMonitoring/Analytic'
    }
    else {
        $resolvedPath = Resolve-Path -Path $LogPath -ErrorAction SilentlyContinue
        if (-not $resolvedPath) {
            Write-Host "Unable to find log file: $LogPath" -ForegroundColor Red
            Pause-ForUser
            Show-BCMonitorMenu
            return
        }

        $LogPath = $resolvedPath.Path
        $LogPath
    }

    try {
        $rawEvents = if ($useLiveLog) {
            Get-WinEvent -LogName 'Microsoft-Windows-BranchCacheMonitoring/Analytic' -Oldest -ErrorAction Stop
        }
        else {
            Get-WinEvent -Path $LogPath -Oldest -ErrorAction Stop
        }
    }
    catch {
        Write-Host "Failed to read BranchCache events: $($_.Exception.Message)" -ForegroundColor Red
        Pause-ForUser
        Show-BCMonitorMenu
        return
    }

    $interestingEvents = foreach ($event in $rawEvents) {
        if ($event.Id -notin 103, 104, 106, 108, 109, 111, 114, 115) {
            continue
        }

        $payload = Get-BCMonitorEventPayload -Event $event
        $contentId = if ($payload.ContainsKey('StringContentId')) {
            $payload.StringContentId
        }
        else {
            $payload.ContentId
        }

        [pscustomobject]@{
            RecordId      = [long]$event.RecordId
            Id            = [int]$event.Id
            TimeCreated   = $event.TimeCreated
            SegmentId     = $payload.SegmentId
            ContentId     = $contentId
            ContentOffset = if ($payload.ContentOffset) { [long]$payload.ContentOffset } else { $null }
            SegmentOffset = if ($payload.SegmentOffset) { [long]$payload.SegmentOffset } else { $null }
            Bytes         = if ($payload.Bytes) { [int]$payload.Bytes } else { $null }
            BlockId       = if ($payload.BlockId) { [int]$payload.BlockId } else { $null }
            BlockSize     = if ($payload.BlockSize) { [int]$payload.BlockSize } else { $null }
            HostName      = $payload.HostName
            Message       = $event.Message
        }
    }

    if (-not $interestingEvents) {
        Write-Host "No BranchCache monitoring events were found in $logLabel." -ForegroundColor Yellow
        Pause-ForUser
        Show-BCMonitorMenu
        return
    }

    $blockReads = $interestingEvents | Where-Object { $_.Id -eq 106 }
    if (-not $blockReads) {
        Write-Host "No block read events were found in $logLabel." -ForegroundColor Yellow
        Pause-ForUser
        Show-BCMonitorMenu
        return
    }

    $eventsBySegment = @{}
    foreach ($event in $interestingEvents | Where-Object { $_.SegmentId }) {
        if (-not $eventsBySegment.ContainsKey($event.SegmentId)) {
            $eventsBySegment[$event.SegmentId] = [System.Collections.Generic.List[object]]::new()
        }

        $eventsBySegment[$event.SegmentId].Add($event)
    }

    $peerCache = @{}
    $classifiedRecordIds = [System.Collections.Generic.HashSet[long]]::new()
    $packageAnalysis = foreach ($group in $eventsBySegment.GetEnumerator()) {
        $segmentEvents = $group.Value | Sort-Object RecordId
        $segmentReads = $segmentEvents | Where-Object { $_.Id -eq 106 }
        $segmentOrigin = if ($segmentEvents.Id -contains 115) {
            'Peers'
        }
        elseif ($segmentEvents.Id -contains 104) {
            'Source'
        }
        else {
            'Local Cache'
        }

        $segmentPeerEvent = if ($segmentOrigin -eq 'Peers') {
            $segmentEvents | Where-Object { $_.Id -eq 115 } | Select-Object -First 1
        }
        else {
            $null
        }

        $segmentPeerDetails = if ($segmentPeerEvent) {
            Resolve-BCMonitorPeer -Endpoint $segmentPeerEvent.HostName -Cache $peerCache
        }
        else {
            $null
        }

        for ($index = 0; $index -lt $segmentReads.Count; $index++) {
            $readEvent = $segmentReads[$index]
            $null = $classifiedRecordIds.Add([long]$readEvent.RecordId)
            [pscustomobject]@{
                RecordId      = $readEvent.RecordId
                TimeCreated   = $readEvent.TimeCreated
                ContentId     = $readEvent.ContentId
                SegmentId     = $readEvent.SegmentId
                ContentOffset = $readEvent.ContentOffset
                SegmentOffset = $readEvent.SegmentOffset
                Bytes         = $readEvent.Bytes
                Source        = $segmentOrigin
                PeerEndpoint  = if ($segmentPeerDetails) { $segmentPeerDetails.Endpoint } else { $null }
                PeerAddress   = if ($segmentPeerDetails) { $segmentPeerDetails.Address } else { $null }
                ResolvedName  = if ($segmentPeerDetails -and $segmentPeerDetails.ResolvedName) { $segmentPeerDetails.ResolvedName } else { $null }
            }
        }
    }

    $orphanBlockReads = $blockReads | Where-Object { -not $classifiedRecordIds.Contains([long]$_.RecordId) }
    if ($orphanBlockReads) {
        $packageAnalysis += foreach ($readEvent in $orphanBlockReads) {
            $relatedEvents = $interestingEvents | Where-Object {
                $_.RecordId -ge $readEvent.RecordId -and
                $_.RecordId -le ($readEvent.RecordId + 25) -and
                (
                    ($readEvent.ContentId -and $_.ContentId -eq $readEvent.ContentId) -or
                    ($readEvent.SegmentId -and $_.SegmentId -eq $readEvent.SegmentId)
                )
            } | Sort-Object RecordId

            $peerEvent = $relatedEvents | Where-Object { $_.Id -eq 115 -and $_.HostName } | Select-Object -First 1
            $sourceEvent = $relatedEvents | Where-Object { $_.Id -eq 104 } | Select-Object -First 1

            $fallbackSource = if ($peerEvent) {
                'Peers'
            }
            elseif ($sourceEvent) {
                'Source'
            }
            else {
                'Local Cache'
            }

            $peerDetails = if ($peerEvent) {
                Resolve-BCMonitorPeer -Endpoint $peerEvent.HostName -Cache $peerCache
            }
            else {
                $null
            }

            [pscustomobject]@{
                RecordId      = $readEvent.RecordId
                TimeCreated   = $readEvent.TimeCreated
                ContentId     = $readEvent.ContentId
                SegmentId     = $readEvent.SegmentId
                ContentOffset = $readEvent.ContentOffset
                SegmentOffset = $readEvent.SegmentOffset
                Bytes         = $readEvent.Bytes
                Source        = $fallbackSource
                PeerEndpoint  = if ($peerDetails) { $peerDetails.Endpoint } else { $null }
                PeerAddress   = if ($peerDetails) { $peerDetails.Address } else { $null }
                ResolvedName  = if ($peerDetails -and $peerDetails.ResolvedName) { $peerDetails.ResolvedName } else { $null }
            }
        }
    }

    $totalPackages = ($packageAnalysis | Measure-Object).Count
    $timeCreated = $interestingEvents | Where-Object { $_.TimeCreated } | Select-Object -ExpandProperty TimeCreated
    $sourceOrder = 'Source', 'Local Cache', 'Peers'
    $sourceEvidenceAvailable = @{
        'Source' = (($packageAnalysis | Where-Object { $_.Source -eq 'Source' } | Measure-Object).Count -gt 0)
        'Local Cache' = $true
        'Peers' = $true
    }

    $summaryTable = foreach ($source in $sourceOrder) {
        $count = ($packageAnalysis | Where-Object { $_.Source -eq $source } | Measure-Object).Count
        #if ($source -eq 'Source' -and -not $sourceEvidenceAvailable[$source]) {
        #    continue
        #}

        [pscustomobject]@{
            Source         = $source
            Packages       = $count
            PercentOfTotal = if ($totalPackages -gt 0) { [math]::Round(($count / $totalPackages) * 100, 2) } else { 0 }
            Present        = if ($count -gt 0) { 'Yes' } else { 'No' }
        }
    }

    $peerTable = $interestingEvents |
        Where-Object { $_.Id -eq 115 -and $_.HostName } |
        ForEach-Object {
            Resolve-BCMonitorPeer -Endpoint $_.HostName -Cache $peerCache
        } |
        Group-Object Endpoint |
        ForEach-Object {
            $first = $_.Group | Select-Object -First 1
            [pscustomobject]@{
                PackagesReceived = $_.Count
                IPAddress        = $first.Address
                ResolvedName     = if ($first.ResolvedName) { $first.ResolvedName } else { '-' }
                Endpoint         = $first.Endpoint
            }
        } |
        Sort-Object -Property PackagesReceived, IPAddress -Descending

    $contentIds = $packageAnalysis | Where-Object { $_.ContentId } | Select-Object -ExpandProperty ContentId -Unique
    $summaryObject = [pscustomobject]@{
        LogSource         = $logLabel
        StartTime         = ($timeCreated | Measure-Object -Minimum).Minimum
        EndTime           = ($timeCreated | Measure-Object -Maximum).Maximum
        TotalPackages     = $totalPackages
        UniqueContentIds  = $contentIds.Count
        UniqueSegments    = ($packageAnalysis | Select-Object -ExpandProperty SegmentId -Unique).Count
        SummaryBySource   = $summaryTable
        PeerBreakdown     = $peerTable
        PackageBreakdown  = $packageAnalysis
    }

    Write-Host "" 
    Write-Host "Log analyzed : $logLabel" -ForegroundColor Green
    Write-Host "Time range   : $($summaryObject.StartTime) -> $($summaryObject.EndTime)" -ForegroundColor Green
    Write-Host "Content IDs  : $($summaryObject.UniqueContentIds)" -ForegroundColor Green
    Write-Host "Segments     : $($summaryObject.UniqueSegments)" -ForegroundColor Green
    Write-Host "Packages     : $($summaryObject.TotalPackages)" -ForegroundColor Green

    Write-SubHeader "Package source summary"
    Write-Host ($summaryTable | Format-Table -AutoSize | Out-String)

    Write-SubHeader "Peer package breakdown"
    if ($peerTable) {
        Write-Host ($peerTable | Format-Table -AutoSize | Out-String)
    }
    else {
        Write-Host "No packages were retrieved from peers." -ForegroundColor Yellow
    }

    Write-SubHeader "Sample package classifications"
    Write-Host (
        $packageAnalysis |
        Select-Object -First 20 TimeCreated, Source, ContentId, ContentOffset, SegmentOffset, Bytes, PeerAddress, ResolvedName |
        Format-Table -AutoSize |
        Out-String
    )

    $summaryObject

    Pause-ForUser
    Show-BCMonitorMenu
}

function Show-BCMonitorMenu {
    clear-host
    $BCStatus = Get-BCStatus
    # check if Microsoft-Windows-BranchCacheMonitoring/Analytic log is enabled
    $logStatus = (wevtutil gl Microsoft-Windows-BranchCacheMonitoring/Analytic | Select-String "enabled:").ToString().Split(":")[1].Trim()

    do {
        Write-Header "BranchCache Monitor Analysis Menu"
        Write-Host "  Before running Analyze, make sure to have enabled and cleared the BranchCacheMonitoring/Analytic log in the Event Viewer."
        Write-Host ""
        Write-Host "  BranchCacheMonitoring/Analytic log enabled = $logStatus"
        Write-Host "  BranchCache Status = $($BCStatus.BranchCacheServiceStatus)"
        Write-Host "  BranchCache Enabled = $($BCStatus.BranchCacheIsEnabled)"
        Write-Host "  BranchCache Mode = $($BCStatus.ClientConfiguration.CurrentClientMode)"
        Write-Host "  BranchCache Cache Size = $([math]::Round($BCStatus.DataCache.CurrentActiveCacheSize / 1MB, 2)) Mb"
        Write-Host ""
        Write-Host "  1. Clear and enable BranchCacheMonitoring/Analytic log"
        Write-Host "  2. Analyze BranchCacheMonitoring"
        Write-Host "  3. Disable BranchCacheMonitoring/Analytic log"
        Write-Host "  4. Clear BranchCache Cache"
        Write-Host "  Q. Exit"
        $sel = (Read-Host "`n  Selection").Trim().ToLower()
        switch ($sel) {
            '1' { Clear-BCMonitorLog }
            '2' { Analyze-BCMonitorLog }
            '3' { Disable-BCMonitorLog }
            '4' { Clear-BCache }
            'q' { exit 0 }
            default { Write-Host "  Invalid selection." -ForegroundColor Red; Pause-ForUser }
        }
    } while ($true)
}

Show-BCMonitorMenu