#pulls all the event 13 from the BC event log and spits out the URL of the guilty content
#then tries to verify the CI using BCMon


if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Function TimeStamp {$(Get-Date -UFormat "%D %T")}  
$Logfile = "$PSScriptRoot\BCEventChecker.log"
#delete any existing logfile if it exists
If (Test-Path $Logfile){ri $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}

#Query the BranchCache Event log

$AllEntries = try { 
Get-WinEvent -LogName "Microsoft-Windows-BranchCache/Operational" | Where-Object {$_.ID -eq 13}
           }
catch [Exception] {
        if ($_.Exception -match "There is not an event log") {
        $(TimeStamp) + " No BranchCache Event Log found, exiting" | Out-File -FilePath $Logfile -Append -Encoding ascii;
        Exit 0
                                                             }
                  }

If (!$AllEntries){$(TimeStamp) + " No BranchCache Event ID 13 found, exiting" | Out-File -FilePath $Logfile -Append -Encoding ascii;
                  Exit 0
                  }


      Foreach ($evt in $AllEntries){ 
        $event = [xml]$evt.ToXml()
  $url = $event.Event.UserData.PublishFailedEvent.ContentId
  #create the URL from the hex content ID
  $id = -join (
  
    $url | Select-String ".." -AllMatches | 

        ForEach-Object Matches | 

            ForEach-Object {
            If ([string]$_ -eq "00") {}
            Else{[char]+"0x$_"}
            }
               )

#then check with BCMon
$(TimeStamp) + " : Checking URL - " + $id | Out-File $Logfile -Append

$BCMonCommand = {.\BCMon.exe /VerifyCI $id}
$BCMonResult = Invoke-Command -ScriptBlock $BCMonCommand

$(TimeStamp) + " : BCMon Returned - " + $BCMonResult | Out-File $Logfile -Append
