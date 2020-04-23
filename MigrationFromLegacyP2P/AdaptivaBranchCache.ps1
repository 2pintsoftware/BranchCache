<# 
   .SYNOPSIS 
    Check Free Disk Space, Size of Adaptiva Content etc and import into BranchCache

   .DESCRIPTION
   Checks the size of the Adaptiva Content Library and removes unwanted content
   Check Free Disk Space
   Configures BC & the BranchCache Cache size
   Imports content from \AdaptivaCache into BranchCache
   Removes Adaptiva Client
   Installs SCCM to new site  


   .NOTES
    AUTHOR: 2Pint Software
    EMAIL: support@2pintsoftware.com
    VERSION: 1.0.1.1
    DATE:23/04/2020
    
    CHANGE LOG: 
    1.0.0.0 : 02/01/2019  : Initial version of script 
    1.0.0.1 : 09/01/2019  : Added Adaptiva 1Site uninstall 
    1.0.0.2 : 18/01/2019  : Added extra logging + .NET Framework check
    1.0.0.3 : 23/01/2019  : Inserted a sleep in the CI Function to try to lower CPU hit
    1.0.0.4 : 24/01/2019  : Changed the space calculation and added 'delete as we go' for the content
    1.0.0.5 : 13/02/2019  : Added reg key removal which was preventing SCCM site re-assignment/ change logfile location to c:\adidas
    1.0.0.6 : 15/02/2019  : Removed StifleR Client install
    1.0.0.7 : 15/02/2019  : Now removes unwanted files first - including SUP over 90 days, and then checks Content IDs agains a whitelist
    1.0.0.8 : 19/03/2019  : Changed the Unzip function - now does unzip and delete (if no errorlevel)
    1.0.0.9 : 20/03/2019  : Fixed a bug with - Content Whitelist import
    1.0.1.0 : 28/03/2019  : Fixed a bug with x86 clients not uninstalling Adaptiva client
	1.0.1.1 : 23/04/2020  : Fast job to cleanup up messy indent from fast work in ISE
   .LINK
    https://2pintsoftware.com
#> 
#=======================================
# SETUP VARIABLES
#=======================================
#delete any existing logfile if it exists
$Logfile = "C:\adidas\AdaptivaBranchCache.log"
If (Test-Path $Logfile){ri $Logfile -Force -ErrorAction SilentlyContinue -Confirm:$false}
If (!(Test-Path $Logfile)){New-Item -ItemType File -Force -Path $Logfile -ErrorAction SilentlyContinue -Confirm:$false}
if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent}

If($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
	$uninstallexe = "$ENV:ProgramFiles (x86)\Adaptiva\AdaptivaClient\bin\AdaptivaClientSetup.exe"
}
Else
{
	$uninstallexe = "$ENV:ProgramFiles\Adaptiva\AdaptivaClient\bin\AdaptivaClientSetup.exe"
}


$uninstallargs = "-uninstall"

#CM Client Package ID 
$CMClientPkgID="CP100019"#<<< Set This
$TempFolder="C:\2pstemp"
$CMClientFolder="C:\2pstemp\CMClient"
If (!(Test-Path $CMClientFolder)){New-Item -ItemType Directory -Force -Path $CMClientFolder}

$ServerSecret="Lh2<RpdAGtJkls*0loWw#lgurHMo7*7RkyIU"#<<< Set This -  get it from the CM DP HKLM\SOFTWARE\Microsoft\SMS\DP - BranchCacheKey
#=======================================
# Pre-Flight Checks
#=======================================
#Check .NET Framework version is 4.6.2 or higher - if not - exit
If ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 394802 -eq $False)
{
	$(TimeStamp) + " : This System does not have .NET Framework 4.6.2 or higher installed. Exiting" | Out-File $Logfile -Append
	Write-Error "This System does not have .NET Framework 4.6.2 or higher installed. Exiting"
	Exit 1
}
#=======================================
# END Pre-Flight Checks
#=======================================

#=======================================
# FUNCTIONS
#=======================================
Function TimeStamp {$(Get-Date -UFormat %T)} 

function UnZip($fileToUnzip, $destination)
{
	#rename the file to .zip and then replace .content with .zip in the variable
	Rename-Item -Path $fileToUnzip -NewName ([io.path]::ChangeExtension($fileToUnzip, '.zip'))
	$fileToUnzip = $fileToUnzip -replace ".content" ,".zip" 

	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($fileToUnzip)
	foreach($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item)
	}
	If ($?) {ri $fileToUnzip -ErrorAction SilentlyContinue -Force}
}



#=======================================
# BranchCache Injector Function
#=======================================
Function BCInjector
{
[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)][bool]$GenerateV1=$true,
        [Parameter(Mandatory=$false)][ValidateSet("SilentlyContinue", "Continue")][string]$DebugPreference,
        [Parameter(Mandatory=$false)][string]$Path="C:\2PSTemp\Content",
        [Parameter(Mandatory=$false)][bool]$DeleteSourceFiles=$true
    )

	$Recurse=$true
	[System.Threading.Thread]::CurrentThread.Priority = 'Lowest'

	$exe = "$PSScriptRoot\BranchCacheTool.exe"
	# $debugpreference = "Continue"
	$netsh = "$Env:windir\System32\netsh.exe"
	$Logfile = "C:\adidas\BranchCacheInjector.log"


	#=======================================
	# Injector FUNCTIONS
	#=======================================

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
		[Parameter(Mandatory=$false)][ValidateSet("V1", "V2")][string]$CIVersion
    )
    
    Begin
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}
        
    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"
        #Inserted a sleep to try to lower CPU hit
        Start-Sleep -s 2

		$Guid = [guid]::NewGuid();
		
		$args = @("/PublishCI", "/InputDataFile", "$FilePath", "/ContentID","$Guid", "/OutputCIFile", "$CIPath", "/CIVersion", "$CIVersion", "/Quiet")

		Write-Debug "Executing $exe with arguments $args"

		#Genereate the CI with BranchCacheTool.exe
		&$exe $args

		#[/CIVersion {V1|V2}] [/BufferSizeBytes <Number of bytes>] [/OutputCSVFile <File path>] [/Quiet] [/Verbose]
        $(TimeStamp) + " : Finished Generation of CI file: $CIPath " | Out-File $Logfile -Append
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Generation of file: $CIPath"
        return $CIPath
    }
        
    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}
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
				#We have data in both filess, inject it
				$args = @("/AddData", "/InputDataFile", "$FilePath", "/InputCIFile", "$CIPath", "/Quiet")
				
				Write-Debug "Executing $exe with arguments $args"
				&$exe $args
				
				#[/BufferSizeBytes <Number of bytes>] [/OutputCSVFile <File path>] [/Quiet] [/Verbose]
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
		[Parameter()][bool]$GenerateV1 = $false
    )
    
    Begin
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}
        
    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"

		#Genereate the CI with BranchCacheTool.exe

		$CIPath = $FilePath + ".ci";
		
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
		Write-Debug "Calling function New-CI -FilePath $FilePath -CIPath $CIPath"

		$return = New-CI -FilePath $FilePath -CIPath $CIPath -CIVersion $CIVersion
		
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
				Write-Debug "Delete the CI file: $CIPath"
				If ($DeleteCI){Remove-Item $CIPath}
                Write-Debug "Delete the file: $CIPath"
				If ($DeleteFile){Remove-Item $FilePath}
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
	#=======================================
	# Injector FUNCTIONS - END
	#=======================================

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

	Write-Debug "Made it so far! Path is: $Path";

	#Check the path to the content is valid
	if(!(Test-Path -Path $Path))
	{
		$(TimeStamp) + " : Error - Target Folder does not exist!" | Out-File $Logfile -Append
		Write-Error "Error - Target Folder does not exist!"
		Return
	}
	else
	{
		Write-Debug "Content folder exists..."
	}

	#Get the files to process (note slightly different cmd depending on OS version)
	$directory = Get-Item $Path
	If ($V2Capable){$files = $directory | Get-ChildItem -File -Recurse}
	Else
	#W7 version - Get-ChildItem doesn't support the -file parameter
	{$files = $directory | Get-ChildItem -Recurse | Where-Object { !$_.PSIsContainer }}

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
	#Main lifting of files
	#=====================
	#If we are on Win10 but $GenerateV1 is set to $true we will gen a V1 hash for each file
	#This doubles the disk requirement
	Try
	{
	if(($GenerateV1 -eq $true) -and ($V2Capable -eq $true))
	{
		Write-Debug "We are also generating Version 1 content, lets start with that"
		foreach ($file in $files){
		If(($file.Length -gt 64kb) -and ($file.Length -le $FreeSpaceOnC)){$File.fullname | InjectData -DeleteFile $true -GenerateV1 $true -DeleteCI $true
																		   Start-Sleep -s 2} # added a sleep here to try to avoid CPU stress
		Else {ri $File.fullname -Force -ErrorAction SilentlyContinue -Confirm:$false}
		}
		#we don't delete the source file in this pass as we might still need it
	}
	}
	Catch {
		  $(TimeStamp) + "BranchCache Inject Error: " + (Write-Error -Message $_) | Out-File -FilePath $Logfile -Append -Encoding ascii
		  Return
		  }
	Try
	{
	#This generates V1 for Win7 and Gen2 for Gen2 Capable ones
	Write-Debug "Generating Version 1 or 2 content, depending on OS Ver"
	foreach ($file in $files){
		If($file.Length -gt 64kb){$File.fullname | InjectData -DeleteFile $true -DeleteCI $true
								 Start-Sleep -s 2} # added a sleep here to try to avoid CPU stress
		Else {ri $File.fullname -Force -ErrorAction SilentlyContinue -Confirm:$false}
		}
	}
	Catch {
		  $(TimeStamp) + "BranchCache Inject Error: " + (Write-Error -Message $_) | Out-File -FilePath $Logfile -Append -Encoding ascii
		  Return
		  }

}


#=======================================
# END - FUNCTIONS
#=======================================


#==========================================================================================================================
# MAIN STARTS HERE
#==========================================================================================================================
#Stop the AdaptivaClient Svc
$(TimeStamp) + " : Stopping the Adaptiva Client Service " | Out-File $Logfile -Append
$s = Get-Service -name 'adaptivaclient' -ErrorAction SilentlyContinue
#Stop AdaptivaClient 
If ($s){
	Stop-Service $s.name -Force
}
#if for some reason the service didn't stop correctly - force it.
If (!$s?) {get-process adaptivaclient* | stop-process -Force}
#END Stop AdaptivaClient Svc

#=======================================
# Enable BranchCache and set the cache size
# 
#=======================================
#check OS version - if Win10 we can do V2 content and also use BranchCache PS cmdlets
$V2Capable = $false
$OS = [Environment]::OSVersion
if(($OS.Version.Major -gt 6) -or (($OS.Version.Major -eq 6) -and ($OS.Version.Minor -ge 2)))
{
	$V2Capable = $true
}
$SetBCCommand = {netsh branchcache set service mode=distributed}
$SetBCCacheSizeCommand = {netsh branchcache set cachesize $CacheSize}

$(TimeStamp) + " : Setting BranchCache service to Distributed Mode " | Out-File $Logfile -Append
Invoke-Command -ScriptBlock $SetBCCommand

$AdaptivaCache="C:\adaptivacache"
$AdaptivaContentSizeInBytes = 0
#Remove the .content files that we don't need to migrate
foreach ($file in (get-childitem $AdaptivaCache\* -Include *OSInstallPkg*,*DriverPkg*,*ImgPkg*, *policy*, *workflow*)) {ri $file -ErrorAction SilentlyContinue -Force}
#Remove the SUP files older than 3 months
$AgeLimit = (Get-Date).AddDays(-90)
foreach ($file in (get-childitem $AdaptivaCache\* -Include *SMSSUP*| Where-Object {$_.LastwriteTime -lt $AgeLimit})) {ri $file -ErrorAction SilentlyContinue -Force}
#Now we can get the total amount of content to migrate
foreach ($file in (get-childitem $AdaptivaCache\* -Include *.content)) {$AdaptivaContentSizeInBytes += $file.length}

$(TimeStamp) + " : Adaptiva Content to migrate is $AdaptivaContentSizeInBytes Bytes" | Out-File $Logfile -Append
Write-Debug "Adaptiva Cache Content is $AdaptivaContentSizeInBytes Bytes"
# Get the free space on C: from WMI
$SystemDrive = Get-WmiObject Win32_LogicalDisk  -Filter "DeviceID='C:'"
$FreeSpaceOnC = $Systemdrive.FreeSpace

Write-Debug "Free Disk space on C: is $FreeSpaceOnC Bytes"
$SkipImport=$False
If (!(Test-Path $adaptivacache)){$SkipImport=$True
$(TimeStamp) + " : Adaptiva Cache not found - skipping import of content" | Out-File $Logfile -Append}

#If ($FreeSpaceOnC -lt 10737418240)
#{$(TimeStamp) + " : Less than 10GB on this system - Skipping Content import" | Out-File $Logfile -Append
#Write-warning "Less than 10GB on this system - Skipping import"
#$SkipImport=$True
#set cache size to half of free space
#$CacheSize = $FreeSpaceOnC/2 
#}
#If Windows 10 + Plenty of diskspace (2 X AdaptivaCache + 10GB) we can do V1 and 2 content
If ($V2Capable -eq $True){
	If(((($AdaptivaContentSizeInBytes *2) + 10737418240)) -lt $FreeSpaceOnC)
		{$CacheSize = $FreeSpaceOnC-10737418240
		$GenV1 = $True}
	ElseIf (($AdaptivaContentSizeInBytes + 10737418240) -lt $FreeSpaceOnC) 
		{$CacheSize = $AdaptivaContentSizeInBytes
		$GenV1 = $False}
	Else {$CacheSize=($FreeSpaceOnC * 0.9)
		$GenV1 = $False}
}
Else
{
	$CacheSize=($FreeSpaceOnC * 0.9)
	$GenV1 = $False
}

$(TimeStamp) + " : Setting BC Cache to $CacheSize" | Out-File $Logfile -Append
Write-Debug "Setting BC Cache to $CacheSize"
Invoke-Command -ScriptBlock $SetBCCacheSizeCommand


#=======================================
# SET The Server Secret to same as the CM DP
# And backup the old one - this will be reset once the migration is complete
#=======================================
$netsh = "$Env:windir\System32\netsh.exe"
if($ServerSecret -ne "")
{
    $(TimeStamp) + " : Reading the current BranchCache secret key" | Out-File $Logfile -Append
	Write-Debug "Reading the current BranchCache secret key"
	$OldKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\SecurityManager\Restricted" -Name Seed
	$PassPhrase = [System.Text.Encoding]::Unicode.GetString($OldKey.Seed)
    $(TimeStamp) + " : Changing the Server Secret for the injection to: $ServerSecret" | Out-File $Logfile -Append
	Write-Debug "Changing the Server Secret for the injection to: $ServerSecret"
    &$netsh @("BranchCache", "set","key","passphrase=$ServerSecret")
}
#=======================================
# End Server Secret Setup
#=======================================
#=======================================
# Output Some BranchCache Stats
#=======================================

If ($V2Capable -eq $True) {
	$BCDataCache = Get-BCDataCache
	$CurrentActiveCacheSizeAsMB = [math]::truncate($BCDataCache.CurrentActiveCacheSize/1MB);
	$CurrentSizeOnDiskAsMB = [math]::truncate($BCDataCache.CurrentSizeOnDiskAsNumberOfBytes/1MB);
	$(TimeStamp) + " : Before Import: We have $CurrentActiveCacheSizeAsMB MB in Cache taking up a total of $CurrentSizeOnDiskAsMB MB on disk." | Out-File $Logfile -Append
	Write-Output "Before: We have $CurrentActiveCacheSizeAsMB MB in Cache taking up a total of $CurrentSizeOnDiskAsMB MB on disk."
}

$TargetFolder = "c:\2pstemp\content"
If (!(Test-Path $TargetFolder)){New-Item -ItemType Directory -Force -Path $TargetFolder}

Try{
	If ($SkipImport -eq $False)
	
	{
		#load the content Whitelist
		$ContentWhiteList = import-csv -Path "$PSScriptRoot\ContentWhitelist.csv"
	}
Catch {
      $(TimeStamp) + "Error Importing Whitelist: " + (Write-Error -Message $_) | Out-File -FilePath $Logfile -Append -Encoding ascii
      Exit 1
      }


	foreach ($file in (get-childitem $AdaptivaCache\* -Include *.content |Sort-Object LastWriteTime -Descending)){
	#Start with a clean target folder
	If (Test-Path $TargetFolder){ri $TargetFolder\* -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false}
	$(TimeStamp) + "Processing Content: " + $file.Name | Out-File -FilePath $Logfile -Append

	Switch -Wildcard ($file.Name)
	{
	#skip the SCCM Client package we don't need it
	*$CMClientPkgID*{Write-Debug "Skipping CM Client Package:  $file"
					 ;break
					}

	App$*  {Write-Debug "Processing App:  $file"
	#Check the content ID against the whitelist - if not found - just delete it
	If($ContentWhiteList.Where({$PSItem.ContentID -eq ($file.Name).Substring(4,8)})){

      unzip $file.FullName $TargetFolder
      If (Test-Path $TargetFolder\AdaptivaSecureHash.xml){ri $TargetFolder\AdaptivaSecureHash.xml -Force -ErrorAction SilentlyContinue -Confirm:$false}
      Write-Debug "Launching the BCInjector"
      BCInjector -GenerateV1 $GenV1
      }
      Else{ri $file -ErrorAction SilentlyContinue -Force
      Write-Debug "Content is not on the Whitelist - so we nuked it"}
      }

	SmsPkg$* {
		Write-Debug "Processing Package: $file"
		#Check the content ID against the whitelist - if not found - just delete it
	If($ContentWhiteList.Where({$PSItem.ContentID -eq ($file.Name).Substring(7,8)})){
		  unzip $file.FullName $TargetFolder
		  If (Test-Path $TargetFolder\AdaptivaSecureHash.xml){ri $TargetFolder\AdaptivaSecureHash.xml -Force -ErrorAction SilentlyContinue -Confirm:$false}
		  Write-Debug "Launching the BCInjector"
		  BCInjector -GenerateV1 $GenV1
      }
      Else{
		  ri $file -ErrorAction SilentlyContinue -Force
		  Write-Debug "Content is not on the Whitelist - so we nuked it"}
      }
SmsSup* {Write-Debug "Processing SUP:  $file"
         unzip $file.FullName $TargetFolder
         If (Test-Path $TargetFolder\AdaptivaSecureHash.xml){ri $TargetFolder\AdaptivaSecureHash.xml -Force -ErrorAction SilentlyContinue -Confirm:$false}
         Write-Debug "Launching the BCInjector"
         BCInjector -GenerateV1 $GenV1
         }


default {
Write-Debug "Unknown Item! - Skipping..."
$(TimeStamp) + "Unknown File - Skipping: " + $file.Name | Out-File -FilePath $Logfile -Append
}

}

}

}
finally
{

}

#skip import
#============================================
#reset the server secret to the original value
#============================================
if($ServerSecret -ne "")
{
    $(TimeStamp) + "  :Resetting the Server Secret after the injection "| Out-File -FilePath $Logfile -Append
	Write-Output "Resetting the Server Secret after the injection: $PassPhrase"
	&$netsh @("BranchCache", "Set","key","passphrase=$PassPhrase")
}
#============================================
#Output some BranchCache Statistics
#============================================
If ($V2Capable -eq $True) {
	$BCDataCache = Get-BCDataCache
	$CurrentActiveCacheSizeAsMB = [math]::truncate($BCDataCache.CurrentActiveCacheSize/1MB);
	$CurrentSizeOnDiskAsMB = [math]::truncate($BCDataCache.CurrentSizeOnDiskAsNumberOfBytes/1MB);
	$(TimeStamp) + "  :After: We have $CurrentActiveCacheSizeAsMB MB in Cache taking up a total of $CurrentSizeOnDiskAsMB MB on disk. "| Out-File -FilePath $Logfile -Append
	Write-Output "After: We have $CurrentActiveCacheSizeAsMB MB in Cache taking up a total of $CurrentSizeOnDiskAsMB MB on disk."
	Write-Warning "Please note that some of these figures might be inaccurate as data is flushed in and out of the cache, also there is a delay factor."
}
#=========================
#Remove the Adaptiva Client
#=========================
Try
{
	$(TimeStamp) + "  :Removing the Adaptiva Client "| Out-File -FilePath $Logfile -Append
	If (Test-Path $uninstallexe)
	{
		start-process $uninstallexe  -arg $uninstallargs -Wait
	}
}
Catch
{
	$(TimeStamp) + "  :The Adaptiva Client is not installed or there was an error "| Out-File -FilePath $Logfile -Append
	Exit 1
}

#=========================
#END Remove the Adaptiva Client
#=========================

#Cleanup the temp folders
If (Test-Path $TempFolder){Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false}

ri $AdaptivaCache -Recurse -ErrorAction SilentlyContinue -Force
