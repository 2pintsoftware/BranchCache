# Check P2P efficiency for the last three downloaded file via the Event Log
$Events = Get-WinEvent -FilterHashTable @{ LogName="*Bits*"; ID=60} | foreach {
$_ | Add-Member -MemberType NoteProperty -Name name -Value $_.Properties[1].Value;
$_ | Add-Member -MemberType NoteProperty -Name url -Value $_.Properties[3].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTotal -Value $_.Properties[8].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTransferred -Value $_.Properties[9].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTransferredFromPeer -Value $_.Properties[12].Value -PassThru;
} 
$events | Sort-Object TimeCreated -Descending | Select -First 3 TimeCreated, url, bytesTotal, bytesTransferred, bytesTransferredFromPeer
