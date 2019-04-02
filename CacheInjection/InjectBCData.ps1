<# 
   .SYNOPSIS 
    Takes the content of a folder and injects it into the local BranchCache Cache

   .DESCRIPTION
   Takes the content from a target folder, and injects each file into the BranchCache cache
   Only injects files over 64k


   .NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    VERSION: 1.0.0.4
    07/03/2019 
    
    CHANGE LOG: 
    1.0.0.1 : 02/01/2019  : Initial version of script - after fixing all the bugs in the AH version of course.. :) 
    1.0.0.2 : 05/03/2019  : Added the /BufferSize switch as this makes a BIG difference to CPU usage.. 
    1.0.0.3 : 06/03/2019  : Cleaned up all the PW hard codes, changed sleep logic and input parameters
    1.0.0.4 : 07/03/2019  : Added optional progressbar and force returncode of 0 at the end
    1.0.0.5 : 02/04/2019  : Improved logic for server secret to allow dodgy characters

    .USAGE .\InjectBCData.ps1
    -Path (mandatory) Path to the folder containing the files that you want to inject
    -ServerSecret (mandatory) this is the server secret of the BranchCache SERVER (a DP if you are using SCCM)
                              it's in the reg  - HKLM\SOFTWARE\Microsoft\SMS\DP - BranchCacheKey
    -Recurse Default $true - do you want to include files in subfolders?
    -GenerateV1 Default $False - on a Windows 10 client you can serve content to Win7 clients if you set this to $true
                                 as we can generate Windows 7 hashes BUT it requires DOUBLE the disk space in the cache
    -DeleteSourceFiles Default $False - delete source files once injected
    -Logfile - Defaults to the current folder, make sure you set this if the media is read only
    -BufferSize - Default 8000 (Bytes) - Sets the buffersize for feeding the BC API
                                       - 8000 is a 'safe' setting, avoiding excessing CPU usage. 16000 or higher results in higher CPU/Disk use.

    -UseTmpForCI default $true - set this to $true to use the %TMP% folder for CI creation, use for read only media
    -SleepBase default 1000    - pause between the creation of files to keep CPU utilization down, the default value of 1000 is typically enough, set to 0 to disable.
    -ShowProgress default $false - set to $true to use the ConfigMgr task sequence progressbar, can only be used in a Task Sequence


    .EXAMPLE
      -Path .. -Logfile %tmp%\inject.log -ServerSecret %SERVERSECRET% -BufferSize 128000 -UseTmpForCI $true -SleepBase 0 # Use this command line for read only media TS injections

   .LINK
    https://2pintsoftware.com
#>
    [CmdletBinding()]
    Param(
        [Parameter()][bool]$GenerateV1=$False,
        [Parameter()][bool]$Recurse=$true,
        [Parameter()][ValidateSet("SilentlyContinue", "Continue")][string]$DebugPreference,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter()][bool]$DeleteSourceFiles=$false,
        [Parameter()][string]$Logfile = "$PSScriptRoot\BCInjector.log",
        [Parameter(Mandatory=$true)][string]$ServerSecret,
        [Parameter()][int64]$BufferSize=8000,
        [Parameter()][bool]$UseTmpForCI=$false,
        [Parameter()][int]$SleepBase = 1000,
        [Parameter()][bool]$ShowProgress=$false
    )
    #Uncomment this if you want to do some timing
    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()


#=======================================
# Injector FUNCTIONS
#=======================================
Function TimeStamp {$(Get-Date -UFormat %T)} 


Function StringToBytes 
{  
    [CmdletBinding()]
    Param(
		[ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$strInput
    )
    
    $strInput = $strInput.Replace("-","");
    $strInput = $strInput.Replace(":","");
    $bytes = [System.Byte[]]::CreateInstance([System.Byte],$strInput.Length/2);

    [int] $i = 0;  
    [int] $x = 0;  

    while ($strInput.Length -gt $i)  
    {  
        $lngDecimal = [System.Convert]::ToInt32($strInput.Substring($i, 2), 16);  
        $bytes[$x] = [System.Convert]::ToByte($lngDecimal);  
        $i = $i + 2;  
        ++$x;  
    }  
    
    return $bytes;  
} 


Function New-CI
{
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Length -gt 64kb)})]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$FilePath,
		[ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$CIPath,
		[Parameter(Mandatory=$false)][ValidateSet("V1", "V2")][string]$CIVersion,
        [int]$MsecSleepBase = 1000
    )
    
    Begin
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}
        
    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"
        #Inserted a sleep to try to lower CPU hit when processing


		$Guid = [guid]::NewGuid();
		
		$args = @("/PublishCI", "/InputDataFile", "$FilePath","/ContentID","$Guid", "/OutputCIFile", "$CIPath", "/CIVersion", "$CIVersion", "/Quiet")

		Write-Debug "Executing $exe with arguments $args"

    	#Genereate the CI with BranchCacheTool.exe
		&$exe $args

        $(TimeStamp) + " : Finished Generation of CI file: $CIPath " | Out-File $Logfile -Append
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Generation of file: $CIPath"
        
        $fileprop = Get-ItemProperty -Path $FilePath
        if($MsecSleepBase -gt 0)
        {
            [int]$millisec_sleep_base = $MsecSleepBase;
            [int]$sleep_add_per_file_size = $fileprop.Length / 1024 /1024 * 5;
            [int]$sleeptime_msec = $millisec_sleep_base + $sleep_add_per_file_size;
        
            Write-Verbose "$($MyInvocation.MyCommand.Name):: Sleeping for: $sleeptime_msec milliseconds"
            Start-Sleep -Milliseconds $sleeptime_msec
        }


        return $CIPath
    }
        
    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: CI Function ended"}
}

function Add-BCData
{
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Length -gt 64kb)})]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$FilePath,
		[ValidateNotNullOrEmpty()]
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Length -gt 0)})]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$CIPath
    )

	    Begin
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}
        
    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath with CI: $CIPath"
        $(TimeStamp) + " : Processing file: $Filepath with CI: $CIPath" | Out-File $Logfile -Append       
		if(Test-Path -Path $CIPath)
		{
			$CIContent = Get-Item -Path $CIPath
			if($CIContent.Length -gt 0)
			{
				#We have data in both files, inject it
				$args = @("/AddData","/BufferSizeBytes", $Buffersize, "/InputDataFile", "$FilePath", "/InputCIFile", "$CIPath", "/Quiet")
				
				Write-Debug "Executing $exe with arguments $args"
				&$exe $args
				
			}
			else
			{
                $(TimeStamp) + " : Warning! Missing file data in CI! $CIPath" | Out-File $Logfile -Append
				Write-Warning "Missing file data in $CIPath"
			}
		}
		$(TimeStamp) + " : Finished Processing file: $FilePath" | Out-File $Logfile -Append    
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"
        
    }
        
    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}
}

function InjectData
{
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Length -gt 64kb)})]
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string]$FilePath,
		[Parameter()][bool]$DeleteCI = $true,
		[Parameter()][bool]$DeleteFile = $true,
		[Parameter()][bool]$GenerateV1 = $false,
		[Parameter()][bool]$UseTmpForCI = $false,
        [Parameter()][int]$SleepBase = 1000
    )
    
    Begin
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}
        
    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"

		#Genereate the CI with BranchCacheTool.exe

        if($UseTmpForCI -eq $true)
        {
            $CIGuid = [guid]::NewGuid();
            $CIPath = "$env:tmp" + "\$CIGuid" + ".ci";
        }
		else
        {
            $CIPath = $FilePath + ".ci";
        }
		
		if(($GenerateV1 -eq $true) -or (($GenerateV1 -eq $False) -and ($V2Capable -eq $False)))
		{
			$CIVersion = "V1";
		}
		else
		{
			$CIVersion = "V2"
		}
        $(TimeStamp) + " : CI Version is $CIVersion" | Out-File $Logfile -Append
        Write-Debug "CI Version is $CIVersion"
		$CIPath = $CIPath + ".$CIVersion"
		Write-Debug "Calling function New-CI -FilePath $FilePath -CIPath $CIPath -MsecSleepBase $SleepBase"

		$return = New-CI -FilePath $FilePath -CIPath $CIPath -CIVersion $CIVersion -MsecSleepBase $SleepBase
		
		Write-Debug "We have a CI path, now we verify the file: $CIPath"

		if(Test-Path -Path $CIPath)
		{
			$CIContent = Get-Item -Path $CIPath
			if($CIContent.Length -gt 0)
			{
				Write-Debug "We have a CI, now we generate the data from the CI: $CIPath"
				Add-BCData -FilePath $FilePath -CIPath $CIPath
                $(TimeStamp) + " : Injected $FilePath into the BranchCache Cache, delete the CI:$DeleteCI" | Out-File $Logfile -Append
				Write-Output "Injected $FilePath into the BranchCache Cache, delete the CI:$DeleteCI"

				If ($DeleteCI){Write-Debug "Delete the CI file: $CIPath"
                               Remove-Item $CIPath}
				If ($DeleteFile){Write-Debug "Delete the file: $FilePath"
                                 Remove-Item $FilePath}
			}
			else
			{
                $(TimeStamp) + " : Missing file data in $CIPath" | Out-File $Logfile -Append
				Write-Warning "Missing file data in $CIPath"
			}
		}
		else
		{
            $(TimeStamp) + " : Warning!Missing CI file: $CIPath" | Out-File $Logfile -Append
			Write-Warning "Missing CI file: $CIPath"
		}
		    
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"
        
    }
        
    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}
}

if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent}

$exe = "$PSScriptRoot\BranchCacheTool.exe"
$netsh = "$Env:windir\System32\netsh.exe"

If (Test-Path $Logfile){ri $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}
If (!(Test-Path $Logfile)){New-Item -ItemType File -Force -Path $Logfile -ErrorAction SilentlyContinue -Confirm:$false}



#check OS version - if Win10 we can do V2 content
$V2Capable = $false
$OS = [Environment]::OSVersion
if(($OS.Version.Major -gt 6) -or (($OS.Version.Major -eq 6) -and ($OS.Version.Minor -ge 2)))
{
	$V2Capable = $true
}

#Check for BranchCacheTool.exe as we need that
$checkEXE = Get-Item -Path $exe -ErrorAction SilentlyContinue

   if(!$checkEXE.Exists)
   {
        $(TimeStamp) + " : Fail -  seems BranchCacheTool.exe is missing" | Out-File $Logfile -Append
		Write-Error "Fail -  seems BranchCacheTool.exe is missing"
		Return
   }

Write-Debug "Made it so far! Target Content Path is: $Path";

#Check the path to the content is valid
if(!(Test-Path -Path $Path))
{
    $(TimeStamp) + " : Error - Target Folder does not exist!" | Out-File $Logfile -Append
	Write-Error "Error - Target Folder does not exist!"
	Return
}
else
{
	Write-Debug "Content folder exists...let's continue"
}

#======================================
# SET The Server Secret to same as the CM DP
# And backup the old one - this will be reset once the migration is complete
#=======================================
$netsh = "$Env:windir\System32\netsh.exe"
if($ServerSecret -ne "")
{
    $(TimeStamp) + " : Reading the current BranchCache secret key" | Out-File $Logfile -Append
	Write-Debug "Reading the current BranchCache secret key"
	
    $secrethex = [System.BitConverter]::ToString((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\SecurityManager\Restricted\' -Name Seed).Seed).Replace("-","")
    $OldKey = StringToBytes($secrethex);
        
    $(TimeStamp) + " : Changing the Server Secret for the injection to: $ServerSecret" | Out-File $Logfile -Append
	Write-Debug "Changing the Server Secret for the injection to: $ServerSecret"
    $NewKey = StringToBytes($ServerSecret);
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\SecurityManager\Restricted\' -Name Seed -Value ([byte[]]$NewKey);
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\SecurityManager\Restricted\' -Name SeedBackup -Value ([byte[]]$OldKey);
}


#=======================================
# End Server Secret Setup
#=======================================

#Now we can get the files to process (note slightly different cmd depending on OS version)
If ($recurse -eq $true) {$action = 'Recurse'
$params = @{ $action = $true }}
Else {$action = 'Recurse'
$params = @{ $action = $false }}


$directory = Get-Item $Path
If ($V2Capable){$files = $directory | Get-ChildItem -File @params}
Else
#W7 version - Get-ChildItem doesn't support the -file parameter
{$files = $directory | Get-ChildItem @params | Where-Object { !$_.PSIsContainer }}

#check that there is actual content - if not - quit
if($files.Length -gt 0)
{
	Write-Debug " Adding files:"
	$(TimeStamp) + " : Adding Files of size:   " + $files.Length | Out-File $Logfile -Append 
}
else
{
	Write-Warning "No data to inject! Exiting"
	 $(TimeStamp) + " : No data to inject! Exiting" | Out-File $Logfile -Append 
	Return
} 

#=====================
# UI Progress
#=====================
$UseTSPrg = $false;

if($ShowProgress -eq $true)
{
    try
    {
        $TSPrg = New-Object -ComObject Microsoft.SMS.TSProgressUI
        try
        {
            $TsEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment
            $UseTSPrg = $true;
        }
        catch
        {
            throw "Unable to connect to the Task Sequence Environment! Please verify you are in a running Task Sequence Environment.`n`nErrorDetails:`n$_"
        }
    
    }
    catch
    {
        throw "Unable to connect to the Task Sequence Progress UI! Please verify you are in a running Task Sequence Environment. Please note: TSProgressUI cannot be loaded during a prestart command.`n`nErrorDetails:`n$_"
    }
}



#=====================
#Main lifting of files
#=====================
#If we are on Win10 but $GenerateV1 is set to $true we will gen a V1 hash for each file
#!!!This doubles the disk requirement!!!
If ($DeleteSourceFiles -eq $true) {$action = 'DeleteFile'
$params = @{ $action = $true }}
Else {$action = 'DeleteFile'
$params = @{ $action = $false }}
$Step = 0;
[UInt32]$Steps = $files.Length;
[UInt64]$V2DataInjected = 0;
[UInt64]$V1DataInjected = 0;

Try
{
    if(($GenerateV1 -eq $true) -and ($V2Capable -eq $true))
    {
	    Write-Debug "We are also generating Version 1 content, lets start with that"
        foreach ($file in $files)
        {
            $Step++;
            If($file.Length -gt 64kb)
            {
        
                if(($UseTSPrg -eq $true) -and ($ShowProgress -eq $true))
                {
                    $TSPrg.ShowActionProgress( $TsEnv.Value("_SMSTSOrgName"), $TsEnv.Value("_SMSTSPackageName"), $TsEnv.Value("_SMSTSCustomProgressDialogMessage"),$TsEnv.Value("_SMSTSCurrentActionName"), [Convert]::ToUInt32( $TsEnv.Value("_SMSTSNextInstructionPointer")), [Convert]::ToUInt32($TsEnv.Value("_SMSTSInstructionTableSize")),`
                    "Injecting file $Step of $Steps : $file (Size: " + ($file.Length/1MB).ToString(".00") +" MB)",`
                    $Step,`
                    $files.Length)                    
                }

                $File.fullname | InjectData -DeleteFile $DeleteSourceFiles  -GenerateV1 $true -DeleteCI $true -UseTmpForCI $UseTmpForCI -SleepBase $SleepBase
                $V1DataInjected = $V1DataInjected + $File.Length;
                              
           } 
            #Else {ri $File.fullname -Force -ErrorAction SilentlyContinue -Confirm:$false}
        }
	    #we don't delete the source file in this pass as we might still need it
    }
}
Catch 
{
      $(TimeStamp) + "BranchCache Inject Error: " + (Write-Error -Message $_) | Out-File -FilePath $Logfile -Append -Encoding ascii
      Return
}

Try
{
    #This generates V1 for Win7 and Gen2 for Gen2 Capable ones
    Write-Debug "Generating Version 1 or 2 content, depending on OS Ver"
    foreach ($file in $files)
    {
        $Step++;
        If($file.Length -gt 64kb)
        {
            if(($UseTSPrg -eq $true) -and ($ShowProgress -eq $true))
            {
                $TSPrg.ShowActionProgress( $TsEnv.Value("_SMSTSOrgName"), $TsEnv.Value("_SMSTSPackageName"), $TsEnv.Value("_SMSTSCustomProgressDialogMessage"),$TsEnv.Value("_SMSTSCurrentActionName"), [Convert]::ToUInt32( $TsEnv.Value("_SMSTSNextInstructionPointer")), [Convert]::ToUInt32($TsEnv.Value("_SMSTSInstructionTableSize")),`
                "Injecting file $Step of $Steps : $file (Size: " + ($file.Length/1MB).ToString(".00") +" MB)",`
                $Step,`
                $files.Length)                    
            }

            $File.fullname | InjectData -DeleteFile $DeleteSourceFiles -DeleteCI $true -UseTmpForCI $UseTmpForCI -SleepBase $SleepBase
            $V2DataInjected = $V2DataInjected + $File.Length;
        } 
        #Else {ri $File.fullname -Force -ErrorAction SilentlyContinue -Confirm:$false}
    }
}
Catch 
{
      $(TimeStamp) + "BranchCache Inject Error: " + (Write-Error -Message $_) | Out-File -FilePath $Logfile -Append -Encoding ascii
      Write-Debug "BranchCache Inject Error: " + (Write-Error -Message $_)
      Return
}

 
#============================================
#reset the server secret to the original value
#============================================
if($ServerSecret -ne "")
{
    $(TimeStamp) + "  :Resetting the Server Secret after the injection "| Out-File -FilePath $Logfile -Append
	Write-Output "Resetting the Server Secret after the injection: $PassPhrase"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\SecurityManager\Restricted\' -Name Seed -Value ([byte[]]$OldKey);	
    #&$netsh @("BranchCache", "Set","key","passphrase=$PassPhrase")

}



$stopwatch.Stop()
$totalSecs =  [math]::Round($stopwatch.Elapsed.TotalSeconds,0)
write-host "Completed in $TotalSecs Seconds, injecting $V1DataInjected bytes of V1 content and $V2DataInjected bytes of V2 content"
return 0;
