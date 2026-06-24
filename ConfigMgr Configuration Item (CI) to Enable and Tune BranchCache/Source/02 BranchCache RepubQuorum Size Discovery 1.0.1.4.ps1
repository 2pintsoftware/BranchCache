$RegistryKey = "HKLM:\SOFTWARE\Policies\Microsoft\PeerDist\DiscoveryManager" 
$RegistryValue = "RepubQuorumSize"

$Result = Get-ItemProperty -Path $RegistryKey -Name $RegistryValue -ErrorAction SilentlyContinue

If ($Result.RepubQuorumSize -eq 100) {
    Return $True
}
Else {
    Return $False
}
