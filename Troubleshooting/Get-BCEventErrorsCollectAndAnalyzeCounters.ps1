<#
.SYNOPSIS

    Monitors BranchCache performance metrics, focusing on CPU, memory, disk I/O, and HTTP request data, while correlating 
    these metrics with potential BranchCache errors ("Access is denied," Event ID 13) in the Windows Event Log. 
    The script captures and logs performance data for analysis, particularly in relation to BranchCache issues.

.DESCRIPTION
    Key Functions:
        Parameter Setup: 
            Defines paths, and configures performance counters based on if you want to analyze the data in PS or not for logging via logman.exe.

        Functions: 
            Measurement Functions: (used if -DisableAnalyzeInPS is NOT specified)
                Update-PerformanceMeasurements: Tracks HTTP requests, CPU load, disk read/write per second, logging min, max, and timestamps
                Find-TimestampMatch: Compares error timestamps from event log with performance data within a 2-second margin.

            Logging function:
                Write-Log: Default logging to $PSScriptRoot\scriptname_TIMESTAMP.log. Script parameter -Verbose will also output to console.

        Performance counters:
            Creates a data collector set to collect data points related to server load and BranchCache requests. 
            Updates every 1 second, outputs to blg files maximum 4GB

        Event Log Monitoring:
            Monitors the Event Log for specific BranchCache-errors, stopping data collection upon detection or after timing out.

        Optional Log Analysis:
            Converts .blg files to .csv for easier analysis.
            Detects spikes based on CPU, memory, and disk thresholds, logging relevant results.
            Collects information from functions Update-PerformanceMeasurements and Find-TimestampMatch
             For the PS analyzis, only CPU,Disk,Memory and HTTP requests are analyzed.
    
                Correlation Analysis:
                    Matches error timestamps with peak performance metrics, highlighting correlations in the output.


.PARAMETERS
    -LogmanBinFolder
        Define where logman/performance monitor should save the BLG -file. Default: C:\PerfLogs\BC-DP-troubleshooting

    -CSVfolder
        If analyzing results from logman in PS, BLG is converted to a CSV. Define path for CSV, default: C:\PerfLogs\BC-DP-troubleshooting\CSV-converted

    -TimeoutForLogmanJob
        How long do you allow the Logman/performance monitor job to run in minutes, default: 180 (3 hours)

    -BCEventsHistoryStartDate
        If you want to check for historic BC Events...don't know why you would want to do that in this scenario. Default: NOW

    -DisableAnalyzeInPS
        Defines if you don't want the results from logman to be analyzed by the script. If not used BLG from logman will be converted to CSV,
        CSV analyzed collecting Max/min/average load on counters, and try to find correlations between heavy load and BC errors from Event Log.

    -DebugInPSISE
        When debugging in ISE, enable to reset all variables between each run. Default, $false

    -Verbose
        By default the script writes a log to $PSScriptRoot, add -Verbose to also output to console. Default: $false


.NOTES
  Version:        1.0
  Author:         2Pint Software, Niklas Larsson
  Creation Date:  2024-11-15
  Purpose/Change: 1.0 Initial script development
                    

.EXAMPLE
   #RECOMMENDED
   #Start collecting performance counters for memory, CPU, HTTP requests, disk read/writes, check for BranchCache errors in event log, stop the
   #performance counters when finding BC-error or timing out after 180 minutes, convert data to CSV, analyze data in CSV. Log the results to file and console
   .\Get-BCEventErrorsCollectAndAnalyzeCounters.ps1 -Verbose

    #Start collecting performance counters for memory, CPU, HTTP requests, disk read/writes, check for BranchCache errors in event log, stop the
    #performance counters when finding BC-error or timing out after 180 minutes, convert data to CSV, analyze data in CSV. Log the results to file
   .\Get-BCEventErrorsCollectAndAnalyzeCounters.ps1

   #Start collecting more performance counters, check for BranchCache errors in event log, stop the performance counters when finding BC-error or 
   #timing out after 5 minutes. Does not analyze the output, leaving it to you to analyze manually in Performance Monitor
   .\Get-BCEventErrorsCollectAndAnalyzeCounters.ps1 -DisableAnalyzeInPS -TimeoutForLogmanJob 5

   #Start collecting more performance counters, check for BranchCache errors in event log, stop the performance counters when finding BC-error or 
   #timing out after 5 minutes. Does not analyze the output, leaving it to you to analyze manually in Performance Monitor. Collects historic BC Errors
   #from March 2024. I don't know why anyone would ever do this in this script. Just don't.
   .\Get-BCEventErrorsCollectAndAnalyzeCounters.ps1 -DisableAnalyzeInPS -TimeoutForLogmanJob 5 -BCEventsHistoryStartDate "2024-03-01 13:30:00"

#>
#Requires -RunAsAdministrator

#region --------------------------------------------------[Script Parameters]------------------------------------------------------
Param (
    [string]$LogmanBinFolder = "C:\PerfLogs\BC-DP-troubleshooting",
    [string]$CSVfolder = "C:\PerfLogs\BC-DP-troubleshooting\CSV-converted",
    [string]$TimeoutForLogmanJob = "180",
    [DateTime]$BCEventsHistoryStartDate = (Get-Date).AddMinutes(-0), #Used when fetching BC event errors
    [switch]$DisableAnalyzeInPS,
    [switch]$DebugInPSISE,
    [switch]$Verbose
)

#endregion

#Capture the baseline of existing variables. Used when debugging in ISE
if ($DebugInPSISE) {
$baselineVariables = (Get-Variable).Name
}

#region Functions

#region Logging: Functions used for Logging, do not edit!
Function Start-Log {
    [CmdletBinding()]
    param (
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [string]$FilePath
    )

    try {
        if (!(Test-Path $FilePath)) {
            ##Create the log file
            New-Item $FilePath -Type File | Out-Null
        }
  
        ##Set the global variable to be used as the FilePath for all subsequent Write-Log
        ##calls in this session
        $global:ScriptLogFilePath = $FilePath
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

Function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
  
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )    
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
  
    if ($MyInvocation.ScriptName) {
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    }
    else {
        #if the script havn't been saved yet and does not have a name this will state unknown.
        $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "Unknown", $LogLevel
    }
    $Line = $Line -f $LineFormat

    If ($Verbose) {
        switch ($LogLevel) {
            2 { $TextColor = "Yellow" }
            3 { $TextColor = "Red" }
            Default { $TextColor = "Gray" }
        }
        Write-Host -nonewline -f $TextColor "$Message`r`n" 
    }

    #Make sure the logfile do not exceed the $maxlogfilesize
    if (Test-Path $ScriptLogFilePath) { 
        if ((Get-Item $ScriptLogFilePath).length -ge $maxlogfilesize) {
            If (Test-Path "$($ScriptLogFilePath.Substring(0,$ScriptLogFilePath.Length-1))_") {
                Remove-Item -path "$($ScriptLogFilePath.Substring(0,$ScriptLogFilePath.Length-1))_" -Force
            }
            Rename-Item -Path $ScriptLogFilePath -NewName "$($ScriptLogFilePath.Substring(0,$ScriptLogFilePath.Length-1))_" -Force
        }
    }

    Add-Content -Value $Line -Path $ScriptLogFilePath -Encoding UTF8

}
#endregion



#Function to update performance measurements
function Update-PerformanceMeasurements {
    param(
        [string]$metricType,
        [string]$timestamp,
        [float]$value,
        [float]$value2 = $null  # Optional second value, used for DiskWrite in DiskMeasurement
    )

    switch ($metricType) {
        'HTTP' {
            if ($script:minHTTPrequests -eq $null -or $value -lt $script:minHTTPrequests) { 
                $script:minHTTPrequests = $value
                $script:minHTTPrequestsTimestamp = $timestamp
            }
            if ($script:maxHTTPrequests -eq $null -or $value -gt $script:maxHTTPrequests) {
                $script:maxHTTPrequests = $value
                $script:maxHTTPrequestsTimestamp = $timestamp
            }
            $script:sumHTTPrequests += $value
            $script:countHTTPrequests++
        }
        'CPU' {
            if ($script:minCPU -eq $null -or $value -lt $script:minCPU) { 
                $script:minCPU = $value 
            }
            if ($script:maxCPU -eq $null -or $value -gt $script:maxCPU) {
                $script:maxCPU = $value
                $script:maxCPUTimestamp = $timestamp
            }
            $script:sumCPU += $value
            $script:countCPU++
        }
        'MemoryPercentage' {
            if ($script:minMemoryInUse -eq $null -or $value -lt $script:minMemoryInUse) { 
                $script:minMemoryInUse = $value 
            }
            if ($script:maxMemoryInUse -eq $null -or $value -gt $script:maxMemoryInUse) {
                $script:maxMemoryInUse = $value
                $script:maxMemoryInUseTimestamp = $timestamp
            }
            $script:sumMemoryInUse += $value
            $script:countMemoryInUse++
        }
        'MemoryReads' {
            if ($script:minMemoryReads -eq $null -or $value -lt $script:minMemoryReads) { 
                $script:minMemoryReads = $value 
            }
            if ($script:maxMemoryReads -eq $null -or $value -gt $script:maxMemoryReads) {
                $script:maxMemoryReads = $value
                $script:maxMemoryReadsTimestamp = $timestamp
            }
            $script:sumMemoryReads += $value
            $script:countMemoryReads++
        }
        'DiskMeasurement' {
            #DiskRead metrics update
            if ($script:minDiskRead -eq $null -or $value -lt $script:minDiskRead) { 
                $script:minDiskRead = $value 
            }
            if ($script:maxDiskRead -eq $null -or $value -gt $script:maxDiskRead) {
                $script:maxDiskRead = $value
                $script:maxDiskReadTimestamp = $timestamp
            }
            $script:sumDiskRead += $value
            $script:countDiskRead++

            #DiskWrite metrics update, using value2
            if ($value2 -ne $null) {
                if ($script:minDiskWrite -eq $null -or $value2 -lt $script:minDiskWrite) { 
                    $script:minDiskWrite = $value2 
                }
                if ($script:maxDiskWrite -eq $null -or $value2 -gt $script:maxDiskWrite) {
                    $script:maxDiskWrite = $value2
                    $script:maxDiskWriteTimestamp = $timestamp
                }
                $script:sumDiskWrite += $value2
                $script:countDiskWrite++
            }
        }
    }
}


#Function to match two different timestamps with a margin of X seconds
function Find-TimestampMatch {
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$referenceTimestamp,    # The timestamp to match against

        [Parameter(Mandatory = $true)]
        [datetime[]]$timestamps,          # Array of timestamps to check

        [int]$marginInSeconds = 2         # Margin in seconds for comparison (default: 2 seconds)
    )

    #Find timestamps within the specified margin
    $matches = $timestamps | Where-Object { ($_ - $referenceTimestamp).TotalSeconds -as [int] -le $marginInSeconds -and ($_ - $referenceTimestamp).TotalSeconds -ge -$marginInSeconds }

    #Display results
    if ($matches) {
        return "Match(es) found within $marginInSeconds second margin at: $matches"
    } else {
        #return "No correlation found between BCError timestamp and Max value timestamp."
    }
}
#endregion Functions

#region Variables

$maxlogfilesize = 5Mb
try {
  $Verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
}
catch {}

#Variables for checking EventLog for BC Errors
$message = 'Access is denied'
$id = 13

#Used when analyzing CSVs. If running PS-analyze on same machine as performance counters, don't touch! Otherwise, specify hostname of source machine (CM DP)
$hostname = "\\$($env:COMPUTERNAME)"
#endregion Variables

#-----------------------------------------------------------[Execution]------------------------------------------------------------
#Default logging to $PSScriptRoot\scriptname_TIMESTAMP.log, change if needed.
Start-Log -FilePath "$($PSScriptRoot)\$([io.path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name))_$((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss')).log"


#Logic to set AnalyzeInPS to true by default unless DisableAnalyzeInPS is specified
if ($null -eq $AnalyzeInPS -and -not $DisableAnalyzeInPS) {
    $AnalyzeInPS = $true
} elseif ($DisableAnalyzeInPS) {
    $AnalyzeInPS = $false
}

#Create output dir for logman if not present
$LogmanBinFolder = "$LogmanBinFolder\$((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss'))"
if (-not (Test-Path $LogmanBinFolder)) {
    $createdFolder = New-Item -ItemType Directory -Path $LogmanBinFolder -Force
    if ($createdFolder) {
        Write-Log "Created folder $LogmanBinFolder"
    }
}

#Create the perfmon job. Fetch alot more counters if not analyzing the results in PS.
if ($AnalyzeInPS) {
$logmanCommand = 'logman.exe create counter BC-Perf-Counter-Log -f bin -v mmddhhmm -max 4096 -c "\Memory\Available MBytes" "\Memory\% Committed Bytes In Use" "\Memory\Pages/sec" "\Network Interface(*)\Packets/sec" "\PhysicalDisk(_Total)\Disk Reads/sec" "\PhysicalDisk(_Total)\Disk Writes/sec" "\Processor Information(_Total)\% Processor Time" "\BranchCache Kernel Mode\Total HTTP Requests" -si 00:00:01 -o "$LogmanBinFolder\BC-Perf-Counter-Log"'
#$logmanCommand = 'logman.exe create counter BC-Perf-Counter-Log -f bin -v mmddhhmm -max 4096 -c "\Cache\*" "\Memory\*" "\Objects\*" "\Network Interface(*)\*"  "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\LogicalDisk(*)\*" "\Processor Information(*)\*" "\System\*" "\BranchCache Kernel Mode\*" -si 00:00:01 -o "$LogmanBinFolder\BC-Perf-Counter-Log"'
}
else {
$logmanCommand = 'logman.exe create counter BC-Perf-Counter-Log -f bin -v mmddhhmm -max 4096 -c "\Cache\*" "\Memory\*" "\Objects\*" "\Network Interface(*)\*"  "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\LogicalDisk(*)\*" "\Processor Information(*)\*" "\System\*" "\BranchCache Kernel Mode\*" -si 00:00:01 -o "$LogmanBinFolder\BC-Perf-Counter-Log"'
}
$output = Invoke-Expression $logmanCommand
if ($output -match "The command completed successfully.") { Write-Log "Created Performance counter successfully." }
elseif($output -match "Data Collector already exists.") {
    Write-Log "Data Collector already exists, cleaing up at $((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss'))."
    $logmanDeleteCommand = 'logman.exe delete BC-Perf-Counter-Log'
    $deleteoutput = Invoke-Expression $logmanDeleteCommand -ErrorAction SilentlyContinue
    $output = $null
    $output = Invoke-Expression $logmanCommand
 
    if ($output -match "The command completed successfully.") { Write-Log "Started Performance counter job successfully at $((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss'))." }
    else { throw "Failed to start Performance counter job, error: $output" } 
} else 
{ throw "Failed to create Performance counter, error: $output" }

#Save the initial cumulative counter value for HTTP requests
$initialTotalHTTPrequests = (Get-Counter '\BranchCache Kernel Mode\Total HTTP Requests').CounterSamples.CookedValue
$previousTotalHttpRequests = $initialTotalHTTPrequests  #Start with the initial value

#Save the initial % Committed Bytes In Use
$initialComittedMemoryInUseInPercentage = [math]::Round((Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples.CookedValue, 2)

#Save the initial number of BC hash TMP files (should definitely be 0)
$BCFolder = (Get-BCHashCache).CacheFileDirectoryPath
$initialTMPfiles = Get-ChildItem -Path $BCFolder -Filter *.tmp -Recurse

#Start the perfmon job
$logmanCommand = 'logman.exe start BC-Perf-Counter-Log'
$output = Invoke-Expression $logmanCommand
if ($output -match "The command completed successfully.") { Write-Log "Started Performance counter job successfully at $((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss'))." } else { throw "Failed to start Performance counter job, error: $output" }

#Stop the job when you have collected some data. Either after a timeout or automatically when we've found the correct error in the eventlog
$timeout = New-TimeSpan -Minutes $TimeoutForLogmanJob
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log "Checking for BranchCache errors (EventID $id with message: $message) from $($BCEventsHistoryStartDate)"
Write-Log "If not finding any BranchCache errors, job will timeout after $($TimeoutForLogmanJob) minutes"
Do {
    Start-Sleep -Seconds 30
    $AllEntries = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-BranchCache/Operational';id=$id; StartTime=$BCEventsHistoryStartDate} -ErrorAction SilentlyContinue | Where-Object {($_.Message.Contains($message))}
    
    #Below is used when testing, when there's no BC errors available and hard to trigger these events. Instead looking for Security events, never a dull moment in that log
    #$AllEntries = Get-WinEvent -FilterHashtable @{Logname='Security'; StartTime=$BCEventsHistoryStartDate} -ErrorAction SilentlyContinue
}
Until (($AllEntries.Count -gt 0) -or ($stopwatch.elapsed -gt $timeout))

if ($AllEntries) {
    Write-Log -LogLevel 2 -Message "Found error in EventLog. Running for 1 more minute, then stopping the counter job"
    Start-Sleep -Seconds 60
    $AllEntries = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-BranchCache/Operational';id=$id; StartTime=$BCEventsHistoryStartDate} -ErrorAction SilentlyContinue | Where-Object {($_.Message.Contains($message))}

    #Below is used when testing, when there's no BC errors available and hard to trigger these events. Instead looking for Security events, never a dull moment in that log
    #$AllEntries = Get-WinEvent -FilterHashtable @{Logname='Security'; StartTime=$BCEventsHistoryStartDate} -ErrorAction SilentlyContinue
    Write-Log "Job had a total runtime of $($stopwatch.elapsed)"

    #Stop the perfmon job
    $logmanCommand = 'logman.exe stop BC-Perf-Counter-Log'
    $output = Invoke-Expression $logmanCommand
    if ($output -match "The command completed successfully.") { Write-Log "Stopped Performance counter job successfully." } else { throw "Failed to stop Performance counter job, error: $output" }

    #Get number of BC hash TMP files after finding errors in event log
    $finalTMPfiles = Get-ChildItem -Path $BCFolder -Filter *.tmp -Recurse
    
    $BCErrorTimeStamps = $AllEntries | ForEach-Object { ($_.TimeCreated).ToString("yyyy-MM-dd HH.mm.ss") }
    $BCErrorTimeStampsFormatted = $BCErrorTimeStamps -join ", "
    $BCErrorTimeStampsFormattedDateTime = $AllEntries | ForEach-Object { [datetime]::ParseExact($_.TimeCreated.ToString("yyyy-MM-dd HH.mm.ss"), "yyyy-MM-dd HH.mm.ss", $null) }


    }

if ($stopwatch.elapsed -gt $timeout) {
        Write-Log -LogLevel 2 -Message "Searching for errors in event log timed out after $($timeout.TotalMinutes) minutes. Stopping the counter job"

        #Stop the perfmon job
        $logmanCommand = 'logman.exe stop BC-Perf-Counter-Log'
        $output = Invoke-Expression $logmanCommand
        if ($output -match "The command completed successfully.") { Write-Log "Stopped Performance counter job successfully." } else { throw "Failed to stop Performance counter job, error: $output" }
        }

$finalTotalHTTPrequests = (Get-Counter '\BranchCache Kernel Mode\Total HTTP Requests').CounterSamples.CookedValue
$totalHTTPrequestsProcessed = $finalTotalHTTPrequests - $initialTotalHTTPrequests

$logmanCommand = 'logman.exe delete BC-Perf-Counter-Log'
$output = Invoke-Expression $logmanCommand
if ($output -match "The command completed successfully.") { Write-Log "Deleted Performance counter job successfully." } else { Write-Log "Failed to delete Performance counter job, error: $output" }

#Save the final % Committed Bytes In Use
$finalComittedMemoryInUseInPercentage = [math]::Round((Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples.CookedValue, 2)

#region Analyze
#Everything below is optional, if you want to analyze the logs in Powershell
if ($AnalyzeInPS) {

    Write-Log ("#" * 100)
    Write-Log "Now time to process and analyze the results"

#region CSVprep
    #Create CSVfolder if not already present
    $CSVfolder = "$CSVfolder\$((Get-Date).ToString('yyyy-MM-dd_HH.mm.ss'))"
    if (-not (Test-Path $CSVfolder)) {
        $createdFolder = New-Item -ItemType Directory -Path $CSVfolder -Force
        $createdSingleFileFolder = New-Item -ItemType Directory -Path "$CSVfolder\SingleFile" -Force
        if ($createdFolder) {
            Write-Log "Created folder $CSVfolder"
        }
    }

    #Convert the BLG to CSV
    $blgFiles = Get-ChildItem -Path $LogmanBinFolder -Filter "*.blg"
    foreach ($blgFile in $blgFiles) {
        #Extract the base name of the current .blg file
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($blgFile.FullName)
    
        #Define the output CSV file name
        $outputCsvFile = Join-Path -Path "$CSVfolder\SingleFile" -ChildPath "$baseName.csv"
    
        #Use relog to convert .blg to .csv
        relog $blgFile.FullName -f csv -o $outputCsvFile | Out-Null

        Write-Log "Converted $($blgFile.Name) to $outputCsvFile"
    }

    #Start working with the CSV
    $csvFile = Get-ChildItem -Path "$CSVfolder\SingleFile" -Filter "*.csv"
    $csvFileSizeInMB = [math]::Round(($csvFile| Measure-Object -Property Length -Sum).Sum / 1MB, 1)

    #Break it up in to smaller chunks, 30 minutes of data per CSV. Using streamer instead of Import-CSV to save memory
    if ($csvFileSizeInMB -ge 200) {
        Write-Log "CSV currently weighin in at $($csvFileSizeInMB)MB. To save memory, we'll split it up to smaller CSVs"
        $rowsPerFile = 1800  #Number of rows per CSV file (1 second per row)
        $reader = [System.IO.StreamReader]::new($($csvFile.FullName))

        #Read the header (first line) and save it
        $header = $reader.ReadLine()

        #Initialize variables for split files
        $fileCount = 1
        $currentRows = @()

        #Skip the first line of data
        $firstDataLineSkipped = $false

        #Process the file line-by-line
        while ($null -ne ($line = $reader.ReadLine())) {
            #Skip the first data line
            if (-not $firstDataLineSkipped) {
                $firstDataLineSkipped = $true
                continue  #Skip this first data line
            }

            #Accumulate the rest of the rows
            $currentRows += $line

            #If we have reached the specified number of rows, write to a new file
            if ($currentRows.Count -ge $rowsPerFile) {
                #Output file name
                $outputFolder = $CSVfolder
                $outputFile = "$outputFolder\part_$fileCount.csv"

                #Write the header and the current rows to the file
                $header | Out-File -FilePath $outputFile -Force
                $currentRows | Out-File -FilePath $outputFile -Append -Force

                Write-Output "Created $outputFile with $($currentRows.Count) rows"

                #Increment file count and reset current rows
                $fileCount++
                $currentRows = @()
            }
        }

        #Process remaining rows if any
        if ($currentRows.Count -gt 0) {
            $outputFile = "$outputFolder\part_$fileCount.csv"
            $header | Out-File -FilePath $outputFile -Force
            $currentRows | Out-File -FilePath $outputFile -Append -Force
            Write-Output "Created $outputFile with remaining rows"
        }

        #Save the % Committed Bytes In Use when working with the CSVs
        $CSVprocessingComittedMemoryInUseInPercentage = [math]::Round((Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples.CookedValue, 2)
        #Close the reader
        $reader.Close()

        Write-Log "Removing the big CSV, only keeping the split up ones"
        Remove-Item $outputCsvFile
    }
    else {
        $CSVfolder = "$CSVfolder\SingleFile"
    }
    $csvFiles = Get-ChildItem -Path "$CSVfolder" -Filter "*.csv" | Sort-Object LastWriteTime
#endregion CSVprep

#region CSVanalyze
    #Threshold values for identifying spikes, only output to console. Not taken in to consideration otherwise.
    $cpuThreshold = 70
    $diskReadThreshold = 1000
    $diskWriteThreshold = 1000
    $memThreshold = 500  #Available memory in MB

    #Process each CSV file
    foreach ($file in $csvFiles) {
        $logData = Import-Csv -Path $file.FullName 

        #Analyze for spikes
        $logData | ForEach-Object {
            #Get the timestamp
            $timestampProperty = $_.PSObject.Properties | Where-Object { $_.Name -like "(PDH-CSV 4.0) *" }
            if ($timestampProperty) {
                $timestamp = $timestampProperty.Value
                $timestamp = (Get-Date $timestamp -Format "yyyy-MM-dd HH.mm.ss.fff")
            } else {
                $timestamp = "Unknown"
            }

            #Build the counter names with the hostname
            $cpuUsageCounter = "${hostname}\Processor Information(_Total)\% Processor Time"

            $availableMemoryCounter = "${hostname}\Memory\Available MBytes"
            $comittedMemoryInUseInPercentageCounter = "${hostname}\Memory\% Committed Bytes In Use"
            $MemoryPagesPerSecCounter = "${hostname}\Memory\Pages/sec"
        
            $diskReadsCounter = "${hostname}\PhysicalDisk(_Total)\Disk Reads/sec"
            $diskWritesCounter = "${hostname}\PhysicalDisk(_Total)\Disk Writes/sec"
        
            $HTTPrequestsCounter = "${hostname}\BranchCache Kernel Mode\Total HTTP Requests"

            #Get the performance data
            $cpuUsage = if (-not [string]::IsNullOrWhiteSpace($_.$cpuUsageCounter)) { [float]$_.($cpuUsageCounter) } else { 0 }
            $cpuUsageRounded = [math]::Round($cpuUsage, 2)

            $availableMemory = if (-not [string]::IsNullOrWhiteSpace($_.$availableMemoryCounter)) { [float]$_.($availableMemoryCounter) } else { 0 }
            $comittedMemoryInUseInPercentage = if (-not [string]::IsNullOrWhiteSpace($_.$comittedMemoryInUseInPercentageCounter)) { [float]$_.($comittedMemoryInUseInPercentageCounter) } else { 0 }
            $comittedMemoryInUseInPercentageRounded = [math]::Round($comittedMemoryInUseInPercentage, 2)
            $MemoryPagesPerSec = if (-not [string]::IsNullOrWhiteSpace($_.$MemoryPagesPerSecCounter)) { [float]$_.($MemoryPagesPerSecCounter) } else { 0 }
        
            $diskReads = if (-not [string]::IsNullOrWhiteSpace($_.$diskReadsCounter)) { [float]$_.($diskReadsCounter) } else { 0 }
            $diskWrites = if (-not [string]::IsNullOrWhiteSpace($_.$diskWritesCounter)) { [float]$_.($diskWritesCounter) } else { 0 }
        
            $HTTPrequests = if (-not [string]::IsNullOrWhiteSpace($_.$HTTPrequestsCounter)) { [float]$_.($HTTPrequestsCounter) } else { 0 }


            #Check for spikes
            if ($cpuUsageRounded -gt $cpuThreshold) {
                Write-Log "High CPU spike at $($timestamp): $($cpuUsageRounded)%"
            }

            if ($availableMemory -lt $memThreshold) {
                Write-Log "Low Memory at $($timestamp): $availableMemory MB"
            }

            if ($diskReads -gt $diskReadThreshold) {
                Write-Log "High Disk Reads at $($timestamp): $diskReads reads/sec"
            }

            if ($diskWrites -gt $diskWriteThreshold) {
                Write-Log "High Disk Writes at $($timestamp): $diskWrites writes/sec"
            }

            #region CPUUsageAnalyze
            Update-PerformanceMeasurements -metricType 'CPU' -timestamp $timestamp -value $cpuUsageRounded
            #endregion CPUUsageAnalyze

            #region MemoryUsageAnalyze
            Update-PerformanceMeasurements -metricType 'MemoryPercentage' -timestamp $timestamp -value $comittedMemoryInUseInPercentageRounded
            Update-PerformanceMeasurements -metricType 'MemoryReads' -timestamp $timestamp -value $MemoryPagesPerSec
            #endregion MemoryUsageAnalyze

            #region DiskLoadAnalyze
            Update-PerformanceMeasurements -metricType 'DiskMeasurement' -timestamp $timestamp -value $diskReads -value2 $diskWrites
            #endregion DiskLoadAnalyze

            #region HTTPRequestsAnalyze
            #Get current HTTP request count
            $currentTotalHTTPrequests = $HTTPrequests
            #Calculate the difference in HTTP requests since the last iteration
            $requestDiff = $currentTotalHTTPrequests - $previousTotalHTTPrequests
            #Only update measurements if the difference is valid (non-zero)
            #if ($requestDiff -gt 0) {
                Update-PerformanceMeasurements -metricType 'HTTP' -timestamp $timestamp -value $requestDiff
            #}
            #Update the previous HTTP value to the current one for the next iteration
            $previousTotalHttpRequests = $currentTotalHttpRequests
            #endregion HTTPRequestsAnalyze
        }
    }

    $averageHTTPrequests = $sumHTTPrequests / $countHTTPrequests

    #Variables to use for Timestamp Matching
    $maxHTTPrequestsTimestampDateTime = [datetime]::ParseExact("$maxHTTPrequestsTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)
    $maxCPUTimestampDateTime = [datetime]::ParseExact("$maxCPUTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)
    $maxMemoryInUseDateTime = [datetime]::ParseExact("$maxMemoryInUseTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)
    $maxMemoryReadsDateTime = [datetime]::ParseExact("$maxMemoryReadsTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)
    $maxDiskReadTimestampDateTime = [datetime]::ParseExact("$maxDiskReadTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)
    $maxDiskWriteTimestampDateTime = [datetime]::ParseExact("$maxDiskWriteTimestamp", "yyyy-MM-dd HH.mm.ss.fff", $null)

    Write-Log ("#" * 100)
    if ($BCErrorTimeStamps) {
        Write-Log "BCErrors identified on these occasion(s): $BCErrorTimeStampsFormatted"
        Write-Log "When starting, we found $($initialTMPfiles.count) TMP files in $($BCFolder)"
        Write-Log "After seeing BCErrors in event log, we found $($finalTMPfiles.count) TMP files in $($BCFolder)"
        }
    else {Write-Log "No BCErrors detected before timing out"}


    if ($BCErrorTimeStamps) {$MatchHTTPTimeStamp = Find-TimestampMatch -referenceTimestamp $maxHTTPrequestsTimestampDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2}
    Write-Log ("#" * 100)
        Write-Log "Final HTTP Requests Results:"
        Write-Log "Min HTTP requests per second: $minHTTPrequests"
        Write-Log "Max HTTP requests per second: $maxHTTPrequests"
        Write-Log "Min Value Timestamp: $minHTTPrequestsTimestamp"
        Write-Log "Max Value Timestamp: $maxHTTPrequestsTimestamp"
        if ($MatchHTTPTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max HTTP request timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchHTTPTimeStamp"
        }

    Write-Log "Average HTTP requests per second: $averageHTTPrequests"
    Write-Log "Total number of HTTP requests during this session: $totalHTTPrequestsProcessed"
    Write-Log ("#" * 100)

    #Log results for CPU load
    if ($countCPU -gt 0) {
        if ($BCErrorTimeStamps) {$MatchCPUTimeStamp = Find-TimestampMatch -referenceTimestamp $maxCPUTimestampDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2}
        $averageCPU = $sumCPU / $countCPU
        Write-Log "Final CPU Load Results:"
        Write-Log "Min CPU Load: $minCPU%"
        Write-Log "Max CPU Load: $maxCPU%"
        Write-Log "Max CPU Load Timestamp: $maxCPUTimestamp"
        if ($MatchCPUTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max CPU Load timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchCPUTimeStamp"
        }
        Write-Log "Average CPU Load: $averageCPU%"
        Write-Log ("#" * 100)
    } else {
        Write-Log "No CPU load data was recorded during the monitoring period."
        Write-Log ("#" * 100)
    }

    #Log results for Memory usage
    if ($countMemoryInUse -gt 0) {
        if ($BCErrorTimeStamps) {
            $MatchMemoryInUseTimeStamp = Find-TimestampMatch -referenceTimestamp $maxMemoryInUseDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2
            $MatchMemoryReadsTimeStamp = Find-TimestampMatch -referenceTimestamp $maxMemoryReadsDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2
            }
        $averageMemoryUsage = $sumMemoryInUse / $countMemoryInUse
        $averageMemoryReadsPerSec = $sumMemoryReads / $countMemoryReads
        Write-Log "Final Memory(RAM) Results:"
        Write-Log "Min Memory Usage: $minMemoryInUse%"
        Write-Log "Max Memory Usage: $maxMemoryInUse%"
        Write-Log "Min Memory Reads/sec: $minMemoryReads"
        Write-Log "Max Memory Reads/sec: $maxMemoryReads"
        Write-Log "Max Memory Usage Timestamp: $maxMemoryInUseTimestamp"
        Write-Log "Max Memory Reads/sec Timestamp: $maxMemoryReadsTimestamp"
        if ($MatchMemoryInUseTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max Memory Usage timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchMemoryInUseTimeStamp"
        }
        if ($MatchMemoryReadsTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max Memory Reads timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchMemoryReadsTimeStamp"
        }
        Write-Log "Memory Usage before starting job: $initialComittedMemoryInUseInPercentage%"
        Write-Log "Memory Usage when completed job: $finalComittedMemoryInUseInPercentage%"
        if ($CSVprocessingComittedMemoryInUseInPercentage){Write-Log "Memory Usage when processing CSVs: $CSVprocessingComittedMemoryInUseInPercentage%"}
        Write-Log "Average Memory Usage: $averageMemoryUsage%"
        Write-Log "Average Memory Reads/sec: $averageMemoryReadsPerSec"
        Write-Log ("#" * 100)
    } else {
        Write-Log "No Memory usage data was recorded during the monitoring period."
        Write-Log ("#" * 100)
    }

    #Log results for disk read/write times
    if ($countDiskRead -gt 0) {
        if ($BCErrorTimeStamps) {$MatchDiskReadTimeStamp = Find-TimestampMatch -referenceTimestamp $maxDiskReadTimestampDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2}
        $averageDiskRead = $sumDiskRead / $countDiskRead
        Write-Log "Final Disk Read Time Stats (Disk Reads/sec):"
        Write-Log "Min Disk Reads/sec: $minDiskRead"
        Write-Log "Max Disk Reads/sec: $maxDiskRead"
        Write-Log "Max Disk Reads/sec Timestamp: $maxDiskReadTimestamp"
        if ($MatchDiskReadTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max Disk Reads/s timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchDiskReadTimeStamp"
        }
        Write-Log "Average Disk Reads/sec: $averageDiskRead"
        Write-Log ("#" * 100)
    }

    if ($countDiskWrite -gt 0) {
        if ($BCErrorTimeStamps) {$MatchDiskWriteTimeStamp = Find-TimestampMatch -referenceTimestamp $maxDiskWriteTimestampDateTime -timestamps $BCErrorTimeStampsFormattedDateTime -marginInSeconds 2}
        $averageDiskWrite = $sumDiskWrite / $countDiskWrite
        Write-Log "Final Disk Write Time Stats (Disk Writes/sec):"
        Write-Log "Min Disk Writes/sec: $minDiskWrite"
        Write-Log "Max Disk Writes/sec: $maxDiskWrite"
        Write-Log "Max Disk Writes/sec Time Timestamp: $maxDiskWriteTimestamp"
        if ($MatchDiskWriteTimeStamp) {
            Write-Log -LogLevel 2 -Message "Found a correlation between Max Disk Writes/s timestamp and BCError timestamp!"
            Write-Log -LogLevel 2 -Message "$MatchDiskWriteTimeStamp"
        }
        Write-Log "Average Disk Writes/sec: $averageDiskWrite"
        Write-Log ("#" * 100)
    }
#endregion CSVanalyze

}#endregion Analyze
else {
Write-Log "Monitoring completed. Review the results in perfmon"
}


if ($DebugInPSISE) {
#Use below for when debugging in ISE
#Clear all user-defined variables added after the baseline capture
#Define a list of automatic variables to keep
$automaticVariables = @(
    'input', 'MaximumAliasCount', 'MaximumDriveCount', 'MaximumErrorCount',
    'MaximumFunctionCount', 'MaximumVariableCount', 'MyInvocation', 'null',
    'PSBoundParameters', 'PSCommandPath', 'PSScriptRoot', 'args', 'automaticVariables'
)
Get-Variable | Where-Object { $baselineVariables -notcontains $_.Name -and ($_.Options -band [System.Management.Automation.ScopedItemOptions]::ReadOnly) -eq 0 -and ($_.Options -band [System.Management.Automation.ScopedItemOptions]::Constant) -eq 0 -and ($automaticVariables -notcontains $_.Name)} | Remove-Variable -Scope Local -Force
}
