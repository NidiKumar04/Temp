<#
.SYNOPSIS
    MCB: BIOS/UEFI settings procedure
.DESCRIPTION
    This script handles the VW Group Client BIOS/UEFI settings procedure
    for several OEMs. This script and its parameters are linked
    in the PlatformModule (PFM.xml).
.PARAMETER Phase
    Identifies the phase in which the BIOS settings are to be applied.
.PARAMETER DefaultPwd
    The name of the task sequence variable containing the BIOS/UEFI password used to perform the changes.
.PARAMETER OldPwd
    The name of the task sequence variable containing the old BIOS/UEFI password(s) used to perform the changes.
.INPUTS
    System.String
.OUTPUTS
    System.Int32
.EXAMPLE
    .\Apply.ps1 -Phase "PE" -DefaultPwd "Cust_BiosPwdDefault" -OldPwd "Cust_BiosPwdOld"
.NOTES
    2024-07-29 Marco Kautzsch (HCL):
        - Exone renamed to EXTRAComputer
    2023-10-25 Marco Kautzsch (HCL):
        - Lenovo model detection extended to WMI "SystemFamily" property to get readable model names
        - Lenovo XML file names are now a combination of [Manufacturer]_[SystemFamily]_[first 3 chars of Model].xml
        - Lenovo password handling optimized (on password change the old password is still needed to change the BIOS settings until reboot) 
    2023-06-21 Marco Kautzsch (HCL):
        - Script revised to create timestamp based BIOS config export files to avoid overwriting (RFC: 3700)
    2022-02-28 Marco Kautzsch (BOS):
        - Disable Dell HAPI Environment handling/installation, because new CCTK does not need HAPI
    2021-04-23 Marco Kautzsch (BOS):
        - Determination of the file name of the Dell settings adapted to the other manufacturers
    2020-10-14 Marco Kautzsch (BOS):
        - Changed BIOS password variable handling to Base64 strings (RFC: 3077)
    2019-12-06 Marco Kautzsch (BOS):
        - Removed Windows 7 BitLocker handling (out of support)
        - Unused error code variables removed
    2018-10-09 Marco Kautzsch (BOS):
        - Panasonic implemented
    2018-08-30 Marco Kautzsch (BOS):
        - Pre- & PostConfig export optimized
    2018-06-15 Marco Kautzsch (BOS):
        - Getac implemented
    2018-02-07 Marco Kautzsch (BOS):
        - Initial release
#>


PARAM
(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$Phase,

    [Parameter(Mandatory=$false, Position=1)]
    [string]$DefaultPwd = "TEST1234",

    [Parameter(Mandatory=$false, Position=2)]
    [string]$OldPwd = "B787A380dc10" #B787A380dc10
)

BEGIN
{
    #region VARIABLE DECLARATION
    
    #Write-Log -Message "Initializing the script execution (Phase: $($Phase))" -Type 1 -Info $MyInvocation

    #region --- Script Basics

    [string]$Script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    [string]$Script:ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Definition

    [string]$Script:ModulesPath = Join-Path $Script:ScriptPath "modules"


    [string]$Script:SupportPath = Join-Path $Script:ScriptPath "support"
    #Write-Log -Message "Support path <$($Script:SupportPath)>" -Type 1 -Info $MyInvocation

    [string]$Script:SettingsPath = Join-Path $Script:ScriptPath "settings"
    #Write-Log -Message "Settings path <$($Script:SettingsPath)>" -Type 1 -Info $MyInvocation

    if (-not $Global:LogFile) {
    $Global:LogFile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\BIOS_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }

    [string]$Script:LogPath = [System.IO.Path]::GetDirectoryName($Global:LogFile)
    #Write-Log -Message "Log path <$($Script:LogPath)>" -Type 1 -Info $MyInvocation

    [string]$Script:PreConfigSnapshot = Join-Path $Script:LogPath "PreConfigSnapshot.txt"
	[string]$Script:PostConfigSnapshot = Join-Path $Script:LogPath "PostConfigSnapshot.txt"

    [string]$TimeStamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

    [switch]$Script:IsWinPE = Test-Path "HKLM:\SYSTEM\ControlSet001\Control\MiniNT"
        
    [string]$XmlSettingNode = "/settings/os"

    #endregion --- Script Basics
    
    #region --- Error Codes

    ## Default Script Error Codes
    [int]$Script:ERR_SUCCESS = 0
    [int]$Script:ERR_REBOOT_REQUIRED = 3010
    
    #endregion --- Error Codes

	#endregion VARIABLE DECLARATION
}

PROCESS
{
    try
    {
        #region DATA PREPARATION

        . "$(Join-Path $Script:ModulesPath 'Common.ps1')"
        . "$(Join-Path $Script:ModulesPath 'BitLocker.ps1')"

        Write-Log -Message "Loading general script extensions from <$($Script:ModulesPath)>" -Type 1 -Info $MyInvocation

        Write-Log -Message "Initializing the script execution (Phase: $($Phase))" -Type 1 -Info $MyInvocation
        Write-Log -Message "Modules path <$($Script:ModulesPath)>" -Type 1 -Info $MyInvocation
        Write-Log -Message "Support path <$($Script:SupportPath)>" -Type 1 -Info $MyInvocation
        Write-Log -Message "Settings path <$($Script:SettingsPath)>" -Type 1 -Info $MyInvocation
        Write-Log -Message "Log path <$($Script:LogPath)>" -Type 1 -Info $MyInvocation

        Write-Log -Message "Collecting operating system information" -Type 1 -Info $MyInvocation
	    $SystemInfo = Get-SystemInformation
	    Write-Log -Message "Operating system caption <$($SystemInfo.OSCaption) ($($SystemInfo.OSArchitecture))>" -Type 1 -Info $MyInvocation
	    Write-Log -Message "Operating system version <$($SystemInfo.OSVersion)>" -Type 1 -Info $MyInvocation
        Write-Log -Message "Installed on <$($SystemInfo.OSInstallDate)>" -Type 1 -Info $MyInvocation
        Write-Log -Message "Last boot on <$($SystemInfo.OSLastBootDate)>" -Type 1 -Info $MyInvocation
	    Write-Log -Message "Power Shell version <$($SystemInfo.PSVersion)>" -Type 1 -Info $MyInvocation
	    Write-Log -Message "Computername <$($SystemInfo.ComputerName)>" -Type 1 -Info $MyInvocation

        if ($Script:IsWinPE.IsPresent) {
            Write-Log -Message "Script is running in WinPE <$($SystemInfo.PECaption) ($($SystemInfo.PEArchitecture))>" -Type 1 -Info $MyInvocation
        }

        Write-Log -Message "Collecting device information" -Type 1 -Info $MyInvocation
	    $DeviceInfo = Get-DeviceInformation
	    Write-Log -Message "Manufacturer <$($DeviceInfo.Manufacturer)>" -Type 1 -Info $MyInvocation
	    Write-Log -Message "Model <$($DeviceInfo.Model)>" -Type 1 -Info $MyInvocation
        if ($DeviceInfo.Manufacturer -ieq "LENOVO") {
            Write-Log -Message "System Family <$($DeviceInfo.SystemFamily)>" -Type 1 -Info $MyInvocation
        }

        Write-Log -Message "Collecting BIOS information" -Type 1 -Info $MyInvocation
        $BiosInfo = Get-BiosVersion -Manufacturer $DeviceInfo.Manufacturer
	    Write-Log -Message "Current BIOS version <$($BiosInfo.DisplayVersion)>" -Type 1 -Info $MyInvocation

        Write-Log -Message "Loading manufacturer specific script extensions from <$($Script:ModulesPath)>" -Type 1 -Info $MyInvocation
        . "$(Join-Path $Script:ModulesPath `"$($DeviceInfo.Manufacturer)BiosSettings.ps1`")"

        $Script:SupportPath = Join-Path $Script:SupportPath $DeviceInfo.Manufacturer
        Write-Log -Message "Manufacturer specific support path <$($Script:SupportPath)>" -Type 1 -Info $MyInvocation

        $Script:SettingsPath = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)\$($Phase)"
        Write-Log -Message "Manufacturer specific settings path <$($Script:SettingsPath)>" -Type 1 -Info $MyInvocation

        #endregion DATA PREPARATION
        
        #region BITLOCKER PREPARATION

        Write-Log -Message "Collecting BitLocker protection informations." -Type 1 -Info $MyInvocation
        $BitLockerVolumeData = Get-BitLockerVolumeInfo

        #endregion BITLOCKER PREPARATION

        #region BITLOCKER SUSPEND

        if ($BitLockerVolumeData.ConversionStatus -gt 0)
        {
            Write-Log -Message "Suspending BitLocker protection on <$($env:SystemDrive)>." -Type 1 -Info $MyInvocation
            if (!(Suspend-BitLockerVolume -DriveLetter $env:SystemDrive)) {
                throw "Failed to suspend BitLocker protection on <$($env:SystemDrive)>."
            }
            Write-Log -Message "BitLocker protection on <$($env:SystemDrive)> successfully suspended." -Type 1 -Info $MyInvocation
        } else {
	        Write-Log -Message "System drive <$($env:SystemDrive)> is not BitLocker encrypted." -Type 1 -Info $MyInvocation
	    }

        #endregion BITLOCKER SUSPEND

        #region SETTINGS PROCEDURE

        Write-Log -Message "Preparing the script execution" -Type 1 -Info $MyInvocation

        switch ($DeviceInfo.Manufacturer.ToUpper())
        {
            "DELL"
            {
                #region --- Settings Preparation

                ## The Dell Precision Rack 7910/7920 is a server and needs the DTK (Syscfg.exe) to manage the settings
                if ($DeviceInfo.Model -match "Precision Rack 7910" -or $DeviceInfo.Model -match "Precision 7920 Rack")
                {
				    [string]$BiosSettingsFileGlobal = Join-Path $Script:SettingsPath "DTK\_Global.ini"
                    [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "DTK\$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).ini"

				    [string]$DellConfigExecutable = Join-Path $Script:SupportPath "DTK\$($SystemInfo.OSArchitecture)\syscfg.exe"
				    [string]$Script:DellConfigErrorCodes = Join-Path $Script:SupportPath "DTK\SyscfgErrorCodes.txt"
				    [string]$DellConfigLogFile = Join-Path $Script:LogPath "Dell_DTK_$($Phase)_$($Timestamp).log"
                }
                else {
                    [string]$BiosSettingsFileGlobal = Join-Path $Script:SettingsPath "DCC\_Global.cctk"
                    [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "DCC\$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).cctk"

                    [string]$DellConfigExecutable = Join-Path $Script:SupportPath "DCC\$($SystemInfo.OSArchitecture)\cctk.exe"
				    [string]$Script:DellConfigErrorCodes = Join-Path $Script:SupportPath "DCC\cctkerrorcodes.xml"
				    [string]$DellConfigLogFile = Join-Path $Script:LogPath "Dell_DCC_$($Phase)_$($Timestamp).log"
                }
                
                #endregion --- Settings Preparation
                
                #region --- Export Current Configuration

                Write-Log -Message "Save the current BIOS/UEFI configuration to <$($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).ini"))>." -Type 1 -Info $MyInvocation
                $ExportPreConfig = Export-BiosSettingsToFile -Executable $DellConfigExecutable -FilePath $($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).ini"))

                if ($ExportPreConfig.IsError) {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Export Current Configuration
                
                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
                    if (!($DeviceInfo.Model -match "Precision Rack 7910") -and !($DeviceInfo.Model -match "Precision 7920 Rack"))
                    {
				        Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
				        $RtnSetPassword = Set-BiosPassword -Executable $DellConfigExecutable -OldPasswords $OldPwd -NewPassword $DefaultPwd
				
				        if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                        } else {
                            Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                        }
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Global Configuration
                if (Test-Path $BiosSettingsFileGlobal)
                {
                    Write-Log -Message "Start applying the global BIOS configuration." -Type 1 -Info $MyInvocation
                    if ($DeviceInfo.Model -match "Precision Rack 7910" -or $DeviceInfo.Model -match "Precision 7920 Rack") {
                        $RtnSetGlobalSettings = Set-BiosSettings -BiosSettingsFile $BiosSettingsFileGlobal -Executable $DellConfigExecutable -LogFile $DellConfigLogFile
                    } else {
                        $RtnSetGlobalSettings = Set-BiosSettings -BiosSettingsFile $BiosSettingsFileGlobal -BiosPassword $DefaultPwd -Executable $DellConfigExecutable -LogFile $DellConfigLogFile
                    }

                    if ($RtnSetGlobalSettings.IsError) {
                        throw $RtnSetGlobalSettings.LogEntry
                    } else {
                        Write-Log -Message $RtnSetGlobalSettings.LogEntry -Type 1 -Info $MyInvocation
                    }
                }
                #endregion --- Set Global Configuration

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                    if ($DeviceInfo.Model -match "Precision Rack 7910" -or $DeviceInfo.Model -match "Precision 7920 Rack") {
                        $RtnSetModelSettings = Set-BiosSettings -BiosSettingsFile $BiosSettingsFileModel -Executable $DellConfigExecutable -LogFile $DellConfigLogFile
                    } else {
				        $RtnSetModelSettings = Set-BiosSettings -BiosSettingsFile $BiosSettingsFileModel -BiosPassword $DefaultPwd -Executable $DellConfigExecutable -LogFile $DellConfigLogFile
				    }				    

                    if ($RtnSetModelSettings.IsError) {
					    throw $RtnSetModelSettings.LogEntry
				    } else {
                        Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Model Configuration

                #region --- Export New Configuration

                Write-Log -Message "Save the new BIOS/UEFI configuration to <$($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).ini"))>." -Type 1 -Info $MyInvocation
                $ExportPostConfig = Export-BiosSettingsToFile -Executable $DellConfigExecutable -FilePath $($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).ini"))

                if ($ExportPostConfig.IsError) {
                    Write-Log -Message $ExportPostConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPostConfig.LogEntry -Type 1 -Info $MyInvocation
                }
		
                #endregion --- Export New Configuration
            }
            "EXTRACOMPUTER"
            {
                #region --- Settings Preparation
                                
                [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).xml"

                [string]$ExtraComputerConfigExecutable = Join-Path $Script:SupportPath "BiosSet.exe"
				[string]$ExtraComputerConfigLogFile = Join-Path $Script:LogPath "ExtraComputer_$($Phase)_$($Timestamp).log"
                
                #endregion --- Settings Preparation

                #region --- Export Current Configuration

                Write-Log -Message "Save the current BIOS/UEFI configuration to <$($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).xml"))>." -Type 1 -Info $MyInvocation
                $ExportPreConfig = Export-BiosSettingsToFile -Executable $ExtraComputerConfigExecutable -FilePath $($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).xml"))

                if ($ExportPreConfig.IsError) {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Export Current Configuration

                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
				    Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
				    $RtnSetPassword = Set-BiosPassword -Executable $ExtraComputerConfigExecutable -OldPasswords $OldPwd -NewPassword $DefaultPwd
				
				    if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                    $RtnSetModelSettings = Set-BiosSettings -BiosSettingsFile $BiosSettingsFileModel -BiosPassword $DefaultPwd -Executable $ExtraComputerConfigExecutable

                    if ($RtnSetModelSettings.IsError) {
					    throw $RtnSetModelSettings.LogEntry
				    } else {
                        Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Model Configuration

                #region --- Export New Configuration

                Write-Log -Message "Save the new BIOS/UEFI configuration to <$($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).xml"))>." -Type 1 -Info $MyInvocation
                $ExportPostConfig = Export-BiosSettingsToFile -Executable $ExtraComputerConfigExecutable -FilePath $($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).xml"))

                if ($ExportPostConfig.IsError) {
                    Write-Log -Message $ExportPostConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPostConfig.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Export New Configuration
            }
            "GETAC"
            {   
                #region --- Settings Preparation

				[string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).xml"
                
                ## Generate model specific configuration
                if (Test-Path $BiosSettingsFileModel)
                {
					Write-Log -Message "Generate the list of model specific settings to set on the current device." -Type 1 -Info $MyInvocation
					
                    if ($Phase -ne "WIN") {
                        $ListOfModelBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileModel -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -OldPasswords $OldPwd
				    } else {
                        $ListOfModelBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileModel -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -OldPasswords $DefaultPwd
                    }
                    
					if ($ListOfModelBiosSettingsToSet.IsError) {
						throw $ListOfModelBiosSettingsToSet.LogEntry
					} else {
                        Write-Log -Message $ListOfModelBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Settings Preparation

                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
                    Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
				    $RtnSetPassword = Set-BiosPassword -OldPasswords $OldPwd -NewPassword $DefaultPwd

				    if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    if ($ListOfModelBiosSettingsToSet -and $ListOfModelBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                        $RtnSetModelSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfModelBiosSettingsToSet.Result -BiosPassword $DefaultPwd
    
                        if ($RtnSetModelSettings.IsError) {
                            throw $RtnSetModelSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }
                #endregion --- Set Model Configuration
            }
            "HP"
            {
                #region --- Settings Preparation

                [string]$BiosSettingsFileGlobal = Join-Path $Script:SettingsPath "_Global.xml"
                [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).xml"
    
                ## Read current configuration
                Write-Log -Message "Get the possible settings and their current values." -Type 1 -Info $MyInvocation
                $ListOfBiosSettings = Get-BiosSettings
    
                if ($ListOfBiosSettings.IsError) {
                    throw $ListOfBiosSettings.LogEntry
                } else {
                    Write-Log -Message $ListOfBiosSettings.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Settings Preparation
    
                #region --- Export Current Configuration

                Write-Log -Message "Save the current BIOS/UEFI configuration to <$($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($TimeStamp).txt"))>." -Type 1 -Info $MyInvocation
                $ExportPreConfig = Export-BiosSettingsToFile -BiosSettings $ListOfBiosSettings.Result[1] -FilePath $Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($TimeStamp).txt")

                if ($ExportPreConfig.IsError) {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 1 -Info $MyInvocation
                }
    
                #endregion --- Export Current Configuration

                #region --- Generate Global Configuration

                if (Test-Path $BiosSettingsFileGlobal)
                {
                    Write-Log -Message "Generate the list of global settings to set on the current device." -Type 1 -Info $MyInvocation
                    $ListOfGlobalBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileGlobal -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -ListOfPossibleBiosSettings $ListOfBiosSettings.Result[0] -ListOfCurrentBIOSSettings $ListOfBiosSettings.Result[1]
    
                    if ($ListOfGlobalBiosSettingsToSet.IsError) {
                        throw $ListOfGlobalBiosSettingsToSet.LogEntry
                    } else {
                        Write-Log -Message $ListOfGlobalBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Generate Global Configuration

                #region --- Generate Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    Write-Log -Message "Generate the list of model specific settings to set on the current device." -Type 1 -Info $MyInvocation
                    $ListOfModelBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileModel -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -ListOfPossibleBiosSettings $ListOfBiosSettings.Result[0] -ListOfCurrentBIOSSettings $ListOfBiosSettings.Result[1]
    
                    if ($ListOfModelBiosSettingsToSet.IsError) {
                        throw $ListOfModelBiosSettingsToSet.LogEntry
                    } else {
                        Write-Log -Message $ListOfModelBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Generate Model Configuration

                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
                    Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
                    $RtnSetPassword = Set-BiosPassword -OldPasswords $OldPwd -NewPassword $DefaultPwd

                    if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Global Configuration

                if (Test-Path $BiosSettingsFileGlobal)
                {
                    if ($ListOfGlobalBiosSettingsToSet -and $ListOfGlobalBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the global BIOS configuration." -Type 1 -Info $MyInvocation
                        $RtnSetGlobalSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfGlobalBiosSettingsToSet.Result -BiosPassword $DefaultPwd
    
                        if ($RtnSetGlobalSettings.IsError) {
                            throw $RtnSetGlobalSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetGlobalSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No global BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Global Configuration

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    if ($ListOfModelBiosSettingsToSet -and $ListOfModelBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                        $RtnSetModelSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfModelBiosSettingsToSet.Result -BiosPassword $DefaultPwd

                        if ($RtnSetModelSettings.IsError) {
                            throw $RtnSetModelSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No model BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }
                #endregion --- Set Model Configuration

                #region --- Export New Configuration

                Write-Log -Message "Get the current BIOS/UEFI configuration." -Type 1 -Info $MyInvocation
                $ListOfNewBiosSettings = Get-BiosSettings
    
                if ($ListOfNewBiosSettings.IsError) {
                    Write-Log -Message $ListOfNewBiosSettings.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ListOfNewBiosSettings.LogEntry -Type 1 -Info $MyInvocation
                }

                if (!$ListOfNewBiosSettings.IsError)
                {
                    Write-Log -Message "Save new BIOS/UEFI configuration to <$($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($TimeStamp).txt"))>." -Type 1 -Info $MyInvocation
                    $ExportPostConfig = Export-BiosSettingsToFile -BiosSettings $ListOfNewBiosSettings.Result[1] -FilePath $Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($TimeStamp).txt")

                    if ($ExportPostConfig.IsError) {
                        Write-Log -Message $ExportPostConfig.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $ExportPostConfig.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Export New Configuration
            }
            "LENOVO"
            {
                #region --- Settings Preparation

                [string]$BiosSettingsFileGlobal = Join-Path $Script:SettingsPath "_Global.xml"
                [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)_$($DeviceInfo.SystemFamily -replace '\s+', [char]0x005F)_$($DeviceInfo.Model.Substring(0, [Math]::Min($DeviceInfo.Model.Length, 3))).xml"
    
                ## Read current configuration
                Write-Log -Message "Get the possible settings and their current values." -Type 1 -Info $MyInvocation
                $ListOfBiosSettings = Get-BiosSettings
    
                if ($ListOfBiosSettings.IsError) {
                    throw $ListOfBiosSettings.LogEntry
                } else {
                    Write-Log -Message $ListOfBiosSettings.LogEntry -Type 1 -Info $MyInvocation
                }
    
                #endregion --- Settings Preparation

                #region --- Export Current Configuration

                Write-Log -Message "Save the current BIOS/UEFI configuration to <$($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt"))>." -Type 1 -Info $MyInvocation
                $ExportPreConfig = Export-BiosSettingsToFile -BiosSettings $ListOfBiosSettings.Result[1] -FilePath $Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt")

                if ($ExportPreConfig.IsError) {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 1 -Info $MyInvocation
                }
    
                #endregion --- Export Current Configuration

                #region --- Generate Global Configuration

                if (Test-Path $BiosSettingsFileGlobal)
                {
                    Write-Log -Message "Generate the list of global settings to set on the current device." -Type 1 -Info $MyInvocation
                    $ListOfGlobalBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileGlobal -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -ListOfPossibleBiosSettings $ListOfBiosSettings.Result[0] -ListOfCurrentBIOSSettings $ListOfBiosSettings.Result[1]
    
                    if ($ListOfGlobalBiosSettingsToSet.IsError) {
                        throw $ListOfGlobalBiosSettingsToSet.LogEntry
                    } else {
                        Write-Log -Message $ListOfGlobalBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Generate Global Configuration

                #region --- Generate Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    Write-Log -Message "Generate the list of model specific settings to set on the current device." -Type 1 -Info $MyInvocation
                    $ListOfModelBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileModel -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -ListOfPossibleBiosSettings $ListOfBiosSettings.Result[0] -ListOfCurrentBIOSSettings $ListOfBiosSettings.Result[1]
    
                    if ($ListOfModelBiosSettingsToSet.IsError) {
                        throw $ListOfModelBiosSettingsToSet.LogEntry
                    } else {
                        Write-Log -Message $ListOfModelBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Generate Model Configuration

                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
                    Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
                    $RtnSetPassword = Set-BiosPassword -OldPasswords $OldPwd -NewPassword $DefaultPwd

                    if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Global Configuration

                if (Test-Path $BiosSettingsFileGlobal)
                {
                    if ($ListOfGlobalBiosSettingsToSet -and $ListOfGlobalBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the global BIOS configuration." -Type 1 -Info $MyInvocation
                        if ($Phase -ne "WIN") {
                            $RtnSetGlobalSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfGlobalBiosSettingsToSet.Result -BiosPassword $RtnSetPassword.Result
                        } else {
                            $RtnSetGlobalSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfGlobalBiosSettingsToSet.Result -BiosPassword $DefaultPwd
                        }
    
                        if ($RtnSetGlobalSettings.IsError) {
                            throw $RtnSetGlobalSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetGlobalSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No global BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Global Configuration

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    if ($ListOfModelBiosSettingsToSet -and $ListOfModelBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                        if ($Phase -ne "WIN") {
                            $RtnSetModelSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfModelBiosSettingsToSet.Result -BiosPassword $RtnSetPassword.Result
                        } else {
                            $RtnSetModelSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfModelBiosSettingsToSet.Result -BiosPassword $DefaultPwd
                        }
    
                        if ($RtnSetModelSettings.IsError) {
                            throw $RtnSetModelSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No model BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Model Configuration

                #region --- Export New Configuration

                Write-Log -Message "Get the current BIOS/UEFI configuration." -Type 1 -Info $MyInvocation
                $ListOfNewBiosSettings = Get-BiosSettings
    
                if ($ListOfNewBiosSettings.IsError) {
                    Write-Log -Message $ListOfNewBiosSettings.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ListOfNewBiosSettings.LogEntry -Type 1 -Info $MyInvocation
                }

                if (!$ListOfNewBiosSettings.IsError)
                {
                    Write-Log -Message "Save new BIOS/UEFI configuration to <$($Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt"))>." -Type 1 -Info $MyInvocation
                    $ExportPostConfig = Export-BiosSettingsToFile -BiosSettings $ListOfNewBiosSettings.Result[1] -FilePath $Script:PostConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt")

                    if ($ExportPostConfig.IsError) {
                        Write-Log -Message $ExportPostConfig.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $ExportPostConfig.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Export New Configuration
            }
            "PANASONIC"
            {   
                #region --- Settings Preparation

                [string]$BiosSettingsFileModel = Join-Path $Script:SettingsPath "$($DeviceInfo.Manufacturer)_$($DeviceInfo.Model -replace '\s+', [char]0x005F).xml"                
                [string]$PanasonicWMIExecutable = Join-Path $Script:SupportPath "$($SystemInfo.OSArchitecture)\Setup_SetBIOS.bat"

                #endregion --- Settings Preparation

                #region --- Panasonic WMI Provider

                Write-Log -Message "Install the Panasonic WMI Provider to manage the BIOS/UEFI with WMI." -Type 1 -Info $MyInvocation
                $RtnInstallProvider = Execute-WMIProvider -Install -Executable $PanasonicWMIExecutable
    
                if ($RtnInstallProvider.IsError) {
                    throw $RtnInstallProvider.LogEntry
                } else {
                    Write-Log -Message $RtnInstallProvider.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Panasonic WMI Provider

                #region --- Export Current Configuration

                Write-Log -Message "Get the settings and their current values." -Type 1 -Info $MyInvocation
                $ListOfBiosSettings = Get-BiosSettings -OldPasswords $OldPwd
    
                if ($ListOfBiosSettings.IsError) {
                    throw $ListOfBiosSettings.LogEntry
                } else {
                    Write-Log -Message $ListOfBiosSettings.LogEntry -Type 1 -Info $MyInvocation
                }
    
                Write-Log -Message "Save the current BIOS/UEFI configuration to <$($Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt"))>." -Type 1 -Info $MyInvocation
                $ExportPreConfig = Export-BiosSettingsToFile -BiosSettings $ListOfBiosSettings.Result -FilePath $Script:PreConfigSnapshot.Replace(".txt", "_$($Phase)_$($Timestamp).txt")

                if ($ExportPreConfig.IsError) {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 2 -Info $MyInvocation
                } else {
                    Write-Log -Message $ExportPreConfig.LogEntry -Type 1 -Info $MyInvocation
                }

                #endregion --- Export Current Configuration

                #region --- Generate Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    Write-Log -Message "Generate the list of model specific settings to set on the current device." -Type 1 -Info $MyInvocation
                    $ListOfModelBiosSettingsToSet = Get-RequiredBiosSettings -XmlBiosSettingsFile $BiosSettingsFileModel -XmlBiosSettingNode "$($XmlSettingNode)[@caption='$($SystemInfo.OSFamily)']/setting" -CurrentBiosSettings $ListOfBiosSettings.Result
        
                    if ($ListOfModelBiosSettingsToSet.IsError) {
                        throw $ListOfModelBiosSettingsToSet.LogEntry
                    } else {
                        Write-Log -Message $ListOfModelBiosSettingsToSet.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Generate Model Configuration

                #region --- Set BIOS Password

                if ($Phase -ne "WIN") {
                    Write-Log -Message "Try to set the default BIOS password." -Type 1 -Info $MyInvocation
                    $RtnSetPassword = Set-BiosPassword -OldPasswords $OldPwd -NewPassword $DefaultPwd

                    if ($RtnSetPassword.IsError) {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 2 -Info $MyInvocation
                    } else {
                        Write-Log -Message $RtnSetPassword.LogEntry -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set BIOS Password

                #region --- Set Model Configuration

                if (Test-Path $BiosSettingsFileModel)
                {
                    if ($ListOfModelBiosSettingsToSet -and $ListOfModelBiosSettingsToSet.Result.Count -gt 0) {
                        Write-Log -Message "Start applying the model specific BIOS configuration." -Type 1 -Info $MyInvocation
                        $RtnSetModelSettings = Set-BiosSettings -ListOfBiosSettingsToSet $ListOfModelBiosSettingsToSet.Result -BiosPassword $DefaultPwd
    
                        if ($RtnSetModelSettings.IsError) {
                            throw $RtnSetModelSettings.LogEntry
                        } else {
                            Write-Log -Message $RtnSetModelSettings.LogEntry -Type 1 -Info $MyInvocation
                        }
                    } else {
                        Write-Log -Message "No BIOS settings need to be changed." -Type 1 -Info $MyInvocation
                    }
                }

                #endregion --- Set Model Configuration
            }
        }
        
        #endregion SETTINGS PROCEDURE   

        # Write registry markers
        $RegPath = "HKLM:\SOFTWARE\Intune\BIOSScript"
        if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

        # Settings applied successfully (we're here, no exceptions thrown)
        Set-ItemProperty -Path $RegPath -Name "BIOSSettingsApplied" -Value 1 -Type DWORD

        # Check if password was set (only for Phase != "WIN")
        if ($Phase -ne "WIN") {
            if ($RtnSetPassword -and !$RtnSetPassword.IsError) {
                Set-ItemProperty -Path $RegPath -Name "BIOSPasswordSet" -Value 1 -Type DWORD
            } else {
                Set-ItemProperty -Path $RegPath -Name "BIOSPasswordSet" -Value 0 -Type DWORD
            }
        }

        # Last run timestamp
        Set-ItemProperty -Path $RegPath -Name "LastRunTime" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String

        exit $Script:ERR_SUCCESS

    }
    catch
    {
        $ErrorObject = Get-ErrorObject $_
        foreach ($Message in $ErrorObject.ErrorMessages) {
            Write-Log -Message $Message -Type 3 -Info $MyInvocation
        }
    
        # Write failure markers
        $RegPath = "HKLM:\SOFTWARE\Intune\BIOSScript"
        if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
        Set-ItemProperty -Path $RegPath -Name "BIOSSettingsApplied" -Value 0 -Type DWORD
        Set-ItemProperty -Path $RegPath -Name "LastRunTime" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
    
        exit $ErrorObject.ErrorCode
    }
}
END { }
