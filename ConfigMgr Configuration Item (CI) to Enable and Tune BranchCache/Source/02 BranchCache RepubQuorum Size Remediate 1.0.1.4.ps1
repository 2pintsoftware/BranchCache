$LogPath = "C:\Windows\Temp"
$Logfile = "$LogPath\SetBranchCacheRepubQuorumSize.log"

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

# Updating registry to set RepubQuorumSize
Write-Log -Message "Updating registry to set RepubQuorumSize"
$RegistryKey = "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\DiscoveryManager" 
Write-Log -Message "Creating registry key: $RegistryKey"
$Result = New-Item -Path $RegistryKey -ItemType Directory -Force
$Result.Handle.Close()

$RegistryValue = "RepubQuorumSize"
$RegistryValueType = "DWord"
$RegistryValueData = 100
Write-Log -Message "Creating registry value: $RegistryValue, value type: $RegistryValueType, value data: $RegistryValueData"
$Result = New-ItemProperty -Path $RegistryKey -Name $RegistryValue -PropertyType $RegistryValueType -Value $RegistryValueData -Force

# Cleanup (to prevent access denied issue unloading the registry hive)
Remove-Variable Result
Get-Variable Registry* | Remove-Variable
[gc]::collect()

# Stop and Start the BranchCache service 
# Using sc.exe for service since it's more reliable than the PowerShell service cmdlets
$ServiceName = "PeerDistSvc"
sc.exe stop $ServiceName 
Start-Sleep -Seconds 5
sc.exe start $ServiceName 

Write-Host "check status of $ServiceName"
sc.exe Query $ServiceName 
