<#
.SYNOPSIS
    This script is used to enable, disable, and get BranchCache information about packages in the environment

    When run in Gather Mode - The script returns a count of the packages/programs that are NOT branchCache enabled.
    
    When run in Enable mode - The script enables packages/programs for BranchCache.

    When run in Disable mode the script disables packages/programs for BranchCachee.

.DESCRIPTION
    This script is used to enable, disable, and get BranchCache information about applications in the environment
     
.NOTES
    This script is used to enable, disable, and get BranchCache information about applications in the environment
    Just edit the Sitecode, mode, and optional application name (wild card is supported)

    This script was mostly 'stolen with pride' from examples all over the place but specific thanks to @NickolajA, @david_obrien and @merlin_with_a_j !
    
    Use at your own risk - and test it first!

    Be aware that updating deployments will trigger a policy update.

    FileName: Set-BranchCache-Packages.ps1
    Authors: Phil Wilcock, Jordan Benzing, and Johan Arwidmark
    Contact: @2PintSoftware
    Created: 2019-07-02
    Modified: 2019-07-02

    Version - 0.0.0 - (UNKNOWN)
    Version - 0.1.0 - (03-JULY-2019)
        COMPLETED: Converted to obtain site code dynamically
        COMPLETED: Converted to use a progress bar to display status
        BUGFIXED: Fixed it so that we stopped resetting the location for EVERY program we change
        COMPLETED: Add a disable option?
    Version 0.1.1 - (07-JULY-2019)
        COMPLETED: Add unique package selection
    Version 0.1.2 - (15-JULY-2019)
        BUGFIXED:- Fixed packages that meet the criteria wildcard to display properly for enable/DISABLE
        

    

.PARAMETER SiteServer
    This parameter is a string and is designed to only accept the name of the ConfigMgr site server. This information is
    then used to gather the other required information. 

.PARAMETER Mode
    This parameter is a string parameter and requires you to pick from a validation set. The available modes are:
        Gather - Only returns the information about the not BranchCache enabled software updates
        Enable - Enables the updates that are not using it.
        Disable - Disables all of them. 

.EXAMPLE
    .\Set-BranchCache-Packages.PS1 -siteServer "ServerName" -Mode Enable

    This example would gather all deployments that are not BranchCache enabled and then enable them. 

.EXAMPLE
     .\Set-BranchCache-Packages.PS1 -siteServer "ServerName" -Mode Gather

     This example would gather all of the package deployments that are not currently BranchCache enabled. 

.EXAMPLE
    .\Set-BranchCache-Packages.PS1 -siteServer "ServerName"

    This example would gather all of the package deployments that are not currently BranchCache enabled.

.EXAMPLE
     .\Set-BranchCache-Packages.PS1 -siteServer "ServerName" -Mode Enable

     This example would enable branchache on ALL package deployments CAUTION enabling this. 

#>

[cmdletbinding()]
param(
    [Parameter(HelpMessage = "Please enter the name of your site server" , Mandatory = $true )]
    [string]$SiteServer,
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for all packages. By Default we only return the BranchCache enabled packages.",Mandatory = $false)]
    [ValidateSet('Enable','Gather','Disable')]
    [string]$Mode = "Gather",
    [Parameter(HelpMessage = "This option allows you to enable BranchCache for a specific package.",Mandatory = $false)]
    [string]$PackageName
)

begin{
#Region helperfunctions
    function Get-CMModule
    #This function gets the configMgr module
    {
        [CmdletBinding()]
        param()
        Try
        {
            Write-Verbose "Attempting to import SCCM Module"
            #Retrieves the fcnction from ConfigMgr installation path. 
            Import-Module (Join-Path $(Split-Path $ENV:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$false
            Write-Verbose "Succesfully imported the SCCM Module"
        }
        Catch
        {
            Throw "Failure to import SCCM Cmdlets."
        } 
    }
    
    function Test-ConfigMgrAvailable
    #Tests if ConfigMgr is availble so that the SMSProvider and configmgr cmdlets can help. 
    {
        [CMdletbinding()]
        Param
        (
            [Parameter(Mandatory = $false)]
            [bool]$Remediate
        )
            try
            {
                if((Test-Module -ModuleName ConfigurationManager -Remediate:$true) -eq $false)
                #Checks to see if the Configuration Manager module is loaded or not and then since the remediate flag is set automatically imports it.
                { 
                    throw "You have not loaded the configuration manager module please load the appropriate module and try again."
                    #Throws this error if even after the remediation or if the remediation fails. 
                }
                write-Verbose "ConfigurationManager Module is loaded"
                Write-Verbose "Checking if current drive is a CMDrive"
                if((Get-location -Verbose:$false).Path -ne (Get-location -PSProvider 'CmSite' -Verbose:$false).Path)
                #Checks if the current location is the - PS provider for the CMSite server. 
                {
                    Write-Verbose -Message "The location is NOT currently the CMDrive"
                    if($Remediate)
                    #If the remediation field is set then it attempts to set the current location of the path to the CMSite server path. 
                        {
                            Write-Verbose -Message "Remediation was requested now attempting to set location to the the CM PSDrive"
                            Set-Location -Path (((Get-PSDrive -PSProvider CMSite -Verbose:$false).Name) + ":") -Verbose:$false
                            Write-Verbose -Message "Succesfully connected to the CMDrive"
                            #Sets the location properly to the PSDrive.
                        }
    
                    else
                    {
                        throw "You are not currently connected to a CMSite Provider Please Connect and try again"
                    }
                }
                write-Verbose "Succesfully validated connection to a CMProvider"
                return $true
            }
            catch
            {
                $errorMessage = $_.Exception.Message
                write-error -Exception CMPatching -Message $errorMessage
                return $false
            }
    }
    
    function Test-Module
    #Function that is designed to test a module if it is loaded or not. 
    {
        [CMdletbinding()]
        Param
        (
            [Parameter(Mandatory = $true)]
            [String]$ModuleName,
            [Parameter(Mandatory = $false)]
            [bool]$Remediate
        )
        If(Get-Module -Name $ModuleName)
        #Checks if the module is currently loaded and if it is then return true.
        {
            Write-Verbose -Message "The module was already loaded return TRUE"
            return $true
        }
        If((Get-Module -Name $ModuleName) -ne $true)
        #Checks if the module is NOT loaded and if it's not loaded then check to see if remediation is requested. 
        {
            Write-Verbose -Message "The Module was not already loaded evaluate if remediation flag was set"
            if($Remediate -eq $true)
            #If the remediation flag is selected then attempt to import the module. 
            {
                try 
                {
                        if($ModuleName -eq "ConfigurationManager")
                        #If the module requested is the Configuration Manager module use the below method to try to import the ConfigMGr Module.
                        {
                            Write-Verbose -Message "Non-Standard module requested run pre-written function"
                            Get-CMModule
                            #Runs the command to get the COnfigMgr module if its needed. 
                            Write-Verbose -Message "Succesfully loaded the module"
                            return $true
                        }
                        else
                        {
                        Write-Verbose -Message "Remediation flag WAS set now attempting to import module $($ModuleName)"
                        Import-Module -Name $ModuleName
                        #Import  the other module as needed - if they have no custom requirements.
                        Write-Verbose -Message "Succesfully improted the module $ModuleName"
                        Return $true
                        }
                }
                catch 
                {
                    Write-Error -Message "Failed to import the module $($ModuleName)"
                    Set-Location $StartingLocation
                    break
                }
            }
            else {
                #Else return the fact that it's not applicable and return false from the execution.
                {
                    Return $false
                }
            }
        }
    }
#endregion HelperFunctions

#region LogFunctions

Function Start-Log
#Set global variable for the write-log function in this session or script.
{
         [CmdletBinding()]
         param (
         #[ValidateScript({ Split-Path $_ -Parent | Test-Path })]
         [string]$FilePath
          )
         try
              {
                    if(!(Split-Path $FilePath -Parent | Test-Path))
                    {
                         New-Item (Split-Path $FilePath -Parent) -Type Directory | Out-Null
                    }
                    #Confirm the provided destination for logging exists if it doesn't then create it.
                    if (!(Test-Path $FilePath))
                         {
                             ## Create the log file destination if it doesn't exist.
                             New-Item $FilePath -Type File | Out-Null
                         }
                         ## Set the global variable to be used as the FilePath for all subsequent write-log
                         ## calls in this session
                         $global:ScriptLogFilePath = $FilePath
              }
         catch
         {
               #In event of an error write an exception
             Write-Error $_.Exception.Message
         }
}
     
Function Write-Log
#Write the log file if the global variable is set
{
          param (
         [Parameter(Mandatory = $true)]
         [string]$Message,
         [Parameter()]
         [ValidateSet(1, 2, 3)]
          [string]$LogLevel=1,
          [Parameter(Mandatory = $false)]
         [bool]$writetoscreen = $true   
        )
         $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
         $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
         $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
          $Line = $Line -f $LineFormat
          [system.GC]::Collect()
         Add-Content -Value $Line -Path $global:ScriptLogFilePath
          if($writetoscreen)
          {
             switch ($LogLevel)
             {
                 '1'{
                     Write-Verbose -Message $Message
                     }
                 '2'{
                     Write-Warning -Message $Message
                     }
                 '3'{
                     Write-Error -Message $Message
                     }
                 Default {
                 }
             }
         }
          if($writetolistbox -eq $true)
          {
             $result1.Items.Add("$Message")
         }
}
     
function set-DefaultLogPath
{
          #Function to set the default log path if something is put in the field then it is sent somewhere else. 
          [CmdletBinding()]
          param
          (
               [parameter(Mandatory = $false)]
               [bool]$defaultLogLocation = $true,
               [parameter(Mandatory = $false)]
               [string]$LogLocation
          )
          if($defaultLogLocation)
          {
               $LogPath = Split-Path $script:MyInvocation.MyCommand.Path
               $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
               Start-Log -FilePath $($LogPath + "\" + $LogFile)
          }
          else 
          {
               $LogPath = $LogLocation
               $LogFile = "$($($script:MyInvocation.MyCommand.Name).Substring(0,$($script:MyInvocation.MyCommand.Name).Length-4)).log"		
               Start-Log -FilePath $($LogPath + "\" + $LogFile)
          }
}
  
#endregion LogFunctions
}

process{
    set-DefaultLogPath
    Write-Log -Message "Now starting all logs for the duration of the script" -LogLevel 1
    $StartingLocation = Get-Location
    Write-Log -Message "Set the starting location and stored it to return" -LogLevel 1
    Write-Log -Message "Set the bit value to validate if BranchCache is enabled or not" -LogLevel 1
    $BitValue = 65536 #0x00010000
    Write-Log -Message "Now Confirming that ConfigMgr is available and if it's not we will error out" -LogLevel 1
    if(!(Test-ConfigMgrAvailable -Remediate:$true)){
    Write-Log -Message "We were unable to load the ConfigMgr Cmdlets and unable to connect to the CM provider will now exit." -LogLevel 3
    Set-Location -Path $StartingLocation
    break  
    }

    if($Mode -ieq "Gather"){
        Write-Log -Message "The GATHER option or the default was selected" -LogLevel 1
        Write-Log -Message "Now retrieving the CMPackaged deployments and sorting them"
        if($PackageName){
            Write-Log -Message "You have selected to only return a specific package"
            $Package = Get-CMPackage -Verbose:$False -Name $PackageName -fast
            if($Package -eq $null){
                Write-Log -Message "The package was not found now exiting" -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
            foreach ($object in $Package) {
                write-log -Message "Found $($Object.Name) with ID - $($Object.PackageID)"
            }
            $Advertisements = $Package | foreach-object{Get-CMPackageDeployment -Verbose:$false -PackageID $_.PackageID | Sort-Object $_.PackageID}
            if($Advertisements -eq $null){
                Write-Log -Message "You have selected a package that does not have any applicable advertisements now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        if(!($PackageName)){
            Write-Log -Message "You have selected to return all packages with deployments" -LogLevel 1
            $Packages = Get-CMPackage -Verbose:$False -fast
            $Advertisements = Get-CMPackageDeployment -Verbose:$false | Sort-Object $_.PackageID
            if($Advertisements -eq $null){
                Write-Log -Message "You have there are no packages that have applicable advertisments now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        
        Write-Log -Message "Generating a list to store all of the retrived information to..."
        $list = New-Object System.Collections.ArrayList($null)
        Write-Log -Message "Now starting to process and analze all $($Advertisements.Count) deployments..."
        ForEach ($Advertisement in $Advertisements) {
            [int]$currentItem = [array]::indexof($Advertisements,$Advertisement)
            Write-Log -Message "Now processing $($CurrentItem + 1)/$($Advertisements.Count) - $($Advertisement.ProgramName)"
            $Info = [ordered]@{
                BranchCacheState = ($Advertisement.AdvertFlags -band $BitValue)/$BitValue
                PackageID = $Advertisement.PackageID
                ProgramName = $Advertisement.ProgramName
                PackageName = $((Get-CMPackage -PackageID $Advertisement.PackageID -fast -Verbose:$False).Name)
            }
            $Object = New-Object PSObject -Property $Info
            $list.add($Object) | Out-Null
            if($object.BranchCacheState -eq '0'){
                Write-Log -message "The PackageID: $($object.packageID) - with PackageName: $($Object.PackageName) has a program $($Object.ProgramName) that is not enabled for BranchCache"
            }
            if($object.BranchCacheState -eq '1'){
                Write-Log -message "The PackageID: $($object.packageID) - with PackageName: $($Object.PackageName) has a program $($Object.ProgramName) is enabled for BranchCache"
            }
            
        }
        Write-Log -Message "Total of $($List.Count) Package Deployments" -LogLevel 1 
        write-log -Message "$($Count = ($List | Where-Object {$_.BranchCacheState -eq '0'}).Count; if($Count -eq $null){$Count = "1";$Count}else{$Count}) Deployments are NOT BranchCache enabled"
        Write-Log -Message "$($Count = ($List | Where-Object {$_.BranchCacheState -eq '1'}).Count; if($Count -eq $null){$Count = "1";$Count}else{$count}) Deployments ARE Enabled"
        Write-Log -Message "Total number of packages with content: $(($Packages | Where-Object {$_.pkgsourceFlag -eq 2} | Measure-Object).Count)"
        Write-Log -Message "Total number of packages without content: $(($Packages | Where-Object {$_.pkgsourceFlag -eq 1} | Measure-Object).Count)"
        Write-Log -Message "Finalized the information now returning the objects that need to be processed to the screen."
        Write-OutPut -InputObject $($list | Where-Object {$_.BranchCacheState -eq '0'})
        Set-Location -Path $StartingLocation
    }

    if($Mode -ieq "Enable"){ 
        if($PackageName){
            Write-Log -Message "You have selected to only return a specific package"
            $Package = Get-CMPackage -Verbose:$False -Name $PackageName -fast
            if($Package -eq $null){
                Write-Log -Message "The package was not found now exiting" -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
            foreach ($object in $Package) {
                write-log -Message "Found $($Object.Name) with ID - $($Object.PackageID)"
            }
            $PackageDeployments = $Package | foreach-object{Get-CMPackageDeployment -Verbose:$false -PackageID $_.PackageID | Where-Object {$(($_.AdvertFlags -band $BitValue)/$BitValue) -ne '1'}}
            if($PackageDeployments -eq $null){
                Write-Log -Message "You have selected a package that does not have any applicable advertisements now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        if(!($PackageName)){
            
            Write-Log -Message "You have selected to return all packages with deployments" -LogLevel 1
            $PackageDeployments = Get-CMPackage -Verbose:$False -fast | Where-Object {$_.pkgsourceFlag -eq 2} | foreach-object {Get-CMPackageDeployment -Verbose:$false -PackageID $_.PackageID | Where-Object {$(($_.AdvertFlags -band $BitValue)/$BitValue) -ne '1'}}
            if($PackageDeployments -eq $null){
                Write-Log -Message "You have there are no packages that have applicable advertisments now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        if($PackageDeployments){
            ForEach ($a in $PackageDeployments){
                [int]$currentItem = [array]::indexof($PackageDeployments,$a)
                Write-Progress -Activity "Enabling Packages for BranchCache" -Status "Currently Enabling - $($a.ProgramName) - ($($CurrentItem + 1) of $($PackageDeployments.Count)) $([math]::round((($currentItem + 1)/($PackageDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($PackageDeployments.Count + 1)) * 100)
                Write-Log -Message "Working on Package $($CurrentItem + 1)/$($PackageDeployments.Count): $($a.PackageID) Program:  $($a.ProgramName)" -LogLevel 1 
                Set-CMPackageDeployment -CollectionID $a.CollectionID -PackageID $a.packageID -StandardProgramName $a.ProgramName  -AllowSharedContent $True -Verbose:$false
            }
        }
        else{
            Write-Log -Message "No deployments to process" -LogLevel 2
        }
    }
    
    if($Mode -ieq "Disable"){ 
        Write-Log -Message "Now retriving all of the package deployments in configuration manager" -LogLevel 1
        if($PackageName){
            Write-Log -Message "You have selected to only return a specific package"
            $Package = Get-CMPackage -Verbose:$False -Name $PackageName -fast
            if($Package -eq $null){
                Write-Log -Message "The package was not found now exiting" -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
            foreach ($object in $Package) {
                write-log -Message "Found $($Object.Name) with ID - $($Object.PackageID)"
            }
            $PackageDeployments = $Package | foreach-object {Get-CMPackageDeployment -Verbose:$false -PackageID $_.PackageID | Where-Object {$(($_.AdvertFlags -band $BitValue)/$BitValue) -ne '0'}}
            if($PackageDeployments -eq $null){
                Write-Log -Message "You have selected a package that does not have any applicable advertisements now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        if(!($PackageName)){
            Write-Log -Message "You have selected to return all packages with deployments" -LogLevel 1
            $PackageDeployments = Get-CMPackage -Verbose:$False -fast | Where-Object {$_.pkgsourceFlag -eq 2} | foreach-object {Get-CMPackageDeployment -Verbose:$false -PackageID $_.PackageID | Where-Object {$(($_.AdvertFlags -band $BitValue)/$BitValue) -ne '0'}}
            if($PackageDeployments -eq $null){
                Write-Log -Message "You have there are no packages that have applicable advertisments now exiting..." -LogLevel 3
                Set-Location -Path $StartingLocation
                break
            }
        }
        if($PackageDeployments){
                ForEach ($a in $PackageDeployments){
                    [int]$currentItem = [array]::indexof($PackageDeployments,$a)
                    Write-Progress -Activity "DISABLING Packages for BranchCache" -Status "Currently DISABLING - $($a.ProgramName) - ($($CurrentItem + 1) of $($PackageDeployments.Count)) $([math]::round((($currentItem + 1)/($PackageDeployments.Count + 1)),2) * 100)% " -PercentComplete $([float](($currentItem + 1)/($PackageDeployments.Count + 1)) * 100)
                    Write-Log -Message "Working on Package $($CurrentItem + 1)/$($PackageDeployments.Count): $($a.PackageID) Program:  $($a.ProgramName)" -LogLevel 1 
                    Set-CMPackageDeployment -CollectionID $a.CollectionID -PackageID $a.packageID -StandardProgramName $a.ProgramName  -AllowSharedContent $false -Verbose:$false
                }
        }
        else{
            Write-Log -Message "No deployments to process" -LogLevel 2
        }
    }
    Set-Location -Path $StartingLocation
}