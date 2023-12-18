$DownloadPath = "C:\BCTemp"
New-Item -Path $DownloadPath -ItemType Directory -Force

$Cred = Get-Credential
$URL = "http://dp01.corp.viamonstra.com:80/SMS_DP_SMSPKG$/PS1001EB/sccm?/10GB-W11-X64-22H2-Enterprise.wim"

# Download the file
$Job = Start-BitsTransfer -Source $URL -Destination $DownloadPath  -Asynchronous -Authentication Ntlm -Credential $Cred 
while (($Job.JobState -eq "Transferring") -or ($Job.JobState -eq "Connecting")) {
    If ($Job.JobState -eq "Connecting"){
        Write-Host "BITS Job state is: $($Job.JobState)"
    }
    If ($Job.JobState -eq "Transferring"){
        Write-Host "BITS Job state is: $($Job.JobState). $($Job.BytesTransferred) bytes transferred of $($Job.BytesTotal) total"
    }

    Start-Sleep -second 1
} 
Switch($Job.JobState){
    "Transferred" {
        Write-Host "BITS Job state is: $($Job.JobState). $($Job.BytesTransferred) bytes transferred of $($Job.BytesTotal) total"
        Complete-BitsTransfer -BitsJob $Job
        }
    "Error" {$Job | Format-List } # List the errors.
    default {Write-Host "Default action"} #  Perform corrective action.
}


# Check P2P efficiency via the Event Log
$Events = Get-WinEvent -FilterHashTable @{ LogName="*Bits*"; ID=60; Data="$URL" } | foreach {
$_ | Add-Member -MemberType NoteProperty -Name name -Value $_.Properties[1].Value;
$_ | Add-Member -MemberType NoteProperty -Name url -Value $_.Properties[3].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTotal -Value $_.Properties[8].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTransferred -Value $_.Properties[9].Value;
$_ | Add-Member -MemberType NoteProperty -Name bytesTransferredFromPeer -Value $_.Properties[12].Value -PassThru;
} 
$events | Sort-Object TimeCreated -Descending | Select -First 1 TimeCreated, url, bytesTotal, bytesTransferred, bytesTransferredFromPeer