#region ################################################# CHANGELOG #################################################
#
# NAME ....: LenovoBiosSettings.ps1
# VERSION .: 1.1.0
# AUTHOR ..: Kautzsch, Marco (EXTERN: BOS)
# COMMENT .: Module that holds extensions/functions to manage the BIOS/UEFI of supported Lenovo devices.
#
# CHANGELOG:
# 1.1.0 2024-04-23 - Lenovo WMI interface changed to WmiOpcodeInterface (special characters support for password)
# 1.0.6 2023-10-25 - Get-RequiredBiosSettings revised (logfile output & splitting boot order entries on ":")
# 1.0.5 2023-10-23 - Lenovo BIOS password handling revised
# 1.0.4 2020-10-07 - Changed BIOS password variable handling to Base64 strings (RFC: 3077)
# 1.0.3 2019-12-06 - Formatting error solved in function Get-RequiredBiosSettings (character ' in ValidatePattern)
# 1.0.2 2018-02-14 - Synopsis of all functions adjusted
# 1.0.1 2018-02-13 - All functions now return a PSCustomObject with all necessary information
# 1.0.0 2018-02-07 - Initial release
#
#endregion ############################################## CHANGELOG #################################################

Function Get-BiosSettings
{
    <#
	.SYNOPSIS
		Get BIOS/UEFI settings/values.
	.DESCRIPTION
		Get the possible BIOS/UEFI settings/values and the currently set value of each setting.
	.PARAMETER ComputerName
	    The hostname of the computer from which you want to get the BIOS/UEFI settings.
    .INPUTS
        System.String
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
		Get-BiosSettings -ComputerName <String>
	#>

    [OutputType([pscustomobject])]
    PARAM
    (
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = "localhost"
    )

    BEGIN
    {
        ## Create new result object
        $ResultObject = New-ResultObject

        [System.Collections.Hashtable]$CurrentSettings = New-Object System.Collections.Hashtable
	    [System.Collections.Hashtable]$PossibleSettings = New-Object System.Collections.Hashtable
    }	
    PROCESS
    {
        try
        {
            ## Get WMI object/instance of Lenovo_BiosSetting class
	        $WMILenovoBiosSetting = Get-WmiObject -ComputerName $ComputerName -Namespace "root/wmi" -Class "Lenovo_BiosSetting" -ErrorAction Stop

            ## Enumerate the object and get each setting
	        foreach ($Setting in $WMILenovoBiosSetting)
            {
                ## Check if the element is not empty and not "ShowOnly" (read-only)
		        if (($Setting.CurrentSetting -ne "") -and ($Setting.CurrentSetting -notmatch "ShowOnly"))
                {
                    ## Split the current object on "," to separate option & value(s) string (format: SATAControllerMode,AHCI)
			        $CurrentSetting = $Setting.CurrentSetting -split ',', 2
			        $CurrentOption = $CurrentSetting[0]
			        $CurrentValues = $CurrentSetting[1]

                    ## Check if values string contains ";" to identicate a special BIOS/UEFI settings format
			        if ($CurrentValues -match ";")
                    {
                        ## Split values string on ";" to separate currently active value and possible values
				        $CurrentValues = $CurrentValues -split ';'
				        $CurrentValue = $CurrentValues[0]

                        ## Remove unwanted string parts to get clean values array
				        $PossibleValues = $($($CurrentValues[1] -replace "\[Optional:") -replace "\]") -split ','

                        ## Add the option name & the current/possible value(s) to hashtables
				        $CurrentSettings.Add($CurrentOption, $CurrentValue)
                        if (($CurrentOption -match "Boot Sequence") -or ($CurrentOption -match "BootOrder")) {
                            $PossibleSettings.Add($CurrentOption, ($CurrentValue -split ':'))
                        } else {
				            $PossibleSettings.Add($CurrentOption, $PossibleValues)
                        }
			        }
			        else
                    {
                        ## Remove unwanted string parts to get clean current value
				        $CurrentValue = $CurrentValues -replace "\]"

                        ## Add the option name & the current value to hashtable
				        $CurrentSettings.Add($CurrentOption, $CurrentValue)

                        ## Construct the possible values array and add it to hashtable                        
				        $PossibleSettings.Add($CurrentOption, (Get-OppositeFromValue -Value $CurrentValue))
			        }
		        } 
	        }
            $ResultObject.Result = $PossibleSettings, $CurrentSettings
            $ResultObject.LogEntry = "Successfully read the BIOS/UEFI configuration."
	    }
        catch
        {
            $ResultObject = Get-ErrorObject $_
            foreach ($Message in $ResultObject.ErrorMessages) {
                Write-Log -Message $Message -Type 3 -Info $MyInvocation
            }
            $ResultObject.LogEntry = "Failed to get the BIOS/UEFI configuration."
        }
        return $ResultObject
    }
    END {}
}

Function Get-RequiredBiosSettings
{
    <#
	.SYNOPSIS
		Get a hashtable with the final configuration that will be applied to the current device.
	.DESCRIPTION
		Compares the BIOS/UEFI settings of the configuration XML file with the possible BIOS/UEFI settings on the current device.
	.PARAMETER XmlBiosSettingsFile
	    The path to the BIOS/UEFI configuration XML file.
    .PARAMETER XmlBiosSettingNode
	    The name of the parent nodes of the BIOS/UEFI configuration XML file.
    .PARAMETER ListOfPossibleBIOSSettings
	    A hashtable with the possible BIOS/UEFI settings/values collected with "Get-BiosSettings" function.
    .PARAMETER ListOfCurrentBIOSSettings
	    A hashtable with the currently active BIOS/UEFI settings/values collected with "Get-BiosSettings" function.
    .INPUTS
        System.String
        System.Collections.Hashtable
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
		Get-RequiredBiosSettings -XmlBiosSettingsFile ".\settings\Lenovo\PE\_Global.xml" -XmlBiosSettingNode "/settings/os[@caption='WIN_7']/setting" -ListOfPossibleBIOSSettings (Get-BiosSettings)[0] -ListOfCurrentBIOSSettings (Get-BiosSettings)[1]
	#>

    [OutputType([pscustomobject])]
    PARAM
    (
		[Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [ValidatePattern('.xml$')]
		[string]$XmlBiosSettingsFile,

		[Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
		[string]$XmlBiosSettingNode,

		[Parameter(Mandatory=$true, Position=2)]
		[System.Collections.Hashtable]$ListOfPossibleBIOSSettings,

        [Parameter(Mandatory=$true, Position=3)]
		[System.Collections.Hashtable]$ListOfCurrentBIOSSettings
	)

    BEGIN
    {
        ## Create new result object
        $ResultObject = New-ResultObject

	    [System.Collections.Hashtable]$ListOfBiosSettingsToSet = New-Object System.Collections.Hashtable
	    [xml]$XmlBiosSettingsFileContent = Get-Content $XmlBiosSettingsFile -ErrorAction Stop
    }
    PROCESS
    {
        try
        {
            ## Continue if the passed xml file has content
	        if ($XmlBiosSettingsFileContent)
            {
                ## Get an object with all settings and their values from config file
		        $Nodes = $XmlBiosSettingsFileContent.SelectNodes($XmlBiosSettingNode)
		
                ## Enumerate the nodes and..
                foreach ($Node in $Nodes)
                {
                    ## ..get each BIOS/UEFI option name.
			        $BiosOption = $Node.option

                    ## Try to get the possible values of the current enumerated BIOS/UEFI option and..
			        $PossibleBiosValues = $ListOfPossibleBiosSettings[$BiosOption]

                    ## ..the active value of the current enumerated BIOS/UEFI option.
			        $CurrentBiosValue = $ListOfCurrentBIOSSettings[$BiosOption]

                    ## If the XML BIOS/UEFI option exists on the current device..
			        if ($PossibleBiosValues)
                    {
                        ## ..split the related value string at ":" if there are several colon separated values present and its the boot order option.
                        if (($BiosOption -match "Boot Sequence") -or ($BiosOption -match "BootOrder")) {
				            $ListOfValuesToSet = $Node.value -split ":"
                        } else {
                            $ListOfValuesToSet = $Node.value
                        }

                        $ValuesToSet = ""
                        ## Go through the hashtable that contains the options/values you want to set.
				        foreach ($ValueToSet in $ListOfValuesToSet)
                        {
                            ## If the current value is a valid value..
					        if ($PossibleBiosValues.Contains($ValueToSet))
                            {
                                ## ..check if the current option is the boot device order. If yes..
						        if (($BiosOption -match "Boot Sequence") -or ($BiosOption -match "BootOrder"))
                                {
                                    ## ..combine all values to one value separated by ":"
							        $ValuesToSet += $ValueToSet +":"
						        }
						        else {
							        $ValuesToSet += $ValueToSet +","
						        }
					        }
				        }
				        $ValuesToSet = $ValuesToSet -replace ".$"

                        ## If the BIOS/UEFI option does not already exists in the hashtable (error handling if there is a duplicate or empty entry in the XML file)..
				        if (!($ListOfBiosSettingsToSet.ContainsKey($BiosOption)) -and !([System.String]::IsNullOrEmpty($ValuesToSet)))
                        {
                            if ($ValuesToSet -ne $CurrentBiosValue) {
					            ## ..add the BIOS/UEFI option and their value(s) to the final hashtable.
					            $ListOfBiosSettingsToSet.Add($BiosOption, $ValuesToSet)
                            } else {
                                Write-Log -Message "<$($BiosOption)> already has the value <$($ValuesToSet)>. It will be skipped." -Type 1 -Info $MyInvocation
                            }
				        }
			        }
		        }
		        $ResultObject.Result = $ListOfBiosSettingsToSet
                $ResultObject.LogEntry = "<$($ListOfBiosSettingsToSet.Count)> setting(s) found, which must be changed to achieve the standard configuration."
	        }
            else {
                $ResultObject.LogEntry = "No suitable BIOS/UEFI settings found in the configuration file."
            }
        }
        catch
        {
            $ResultObject = Get-ErrorObject $_
            foreach ($Message in $ResultObject.ErrorMessages) {
                Write-Log -Message $Message -Type 3 -Info $MyInvocation
            }
            $ResultObject.LogEntry = "Failed to get the required BIOS/UEFI settings."
        }
        return $ResultObject
    }
    END {}
}

Function Set-BiosPassword
{
    <#
	.SYNOPSIS
		Sets/changes the BIOS/UEFI password.
	.DESCRIPTION
		Uses the passed comma separated password string to change the BIOS/UEFI password to the new value.
	.PARAMETER OldPasswords
	    A string with comma separated Base64 converted old BIOS/UEFI passwords.
    .PARAMETER NewPassword
	    A Base64 string representing the new BIOS/UEFI password.
    .INPUTS
        System.String
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
		Set-BiosPassword -OldPasswords "password,12345678,testpwd" -NewPassword "new_password"
	#>

    [OutputType([pscustomobject])]
    PARAM
	(
		[Parameter(Mandatory=$false, Position=0)]
		[string]$OldPasswords,
		
        [Parameter(Mandatory=$false, Position=1)]
		[string]$NewPassword
	)

	BEGIN
    {
        ## Create new result object
        $ResultObject = New-ResultObject
        $ResultObject.IsError = $true
        $ResultObject.LogEntry = "Failed to change the BIOS/UEFI password."

        ## Set variables to "12345678" if $null is passed to the function
        if ($OldPasswords -eq $null) {
            $OldPasswords = "MTIzNDU2Nzg="
        }
        ## If the new password string is $null or empty replace it with "12345678" (Lenovo workaround)
        if ($NewPassword -eq $null -or $NewPassword -eq "") {
            $NewPassword = "MTIzNDU2Nzg="
        }
        
        ## Check if password variable can be converted from Base64 to plain text
        try {
            if ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($NewPassword))) {
                Write-Log -Message "The new BIOS password is Base64 converted." -Type 1 -Info $MyInvocation
                $NewPassword = Get-DecodedPassword $NewPassword
            }
        } catch { }

        ## Generate a generic list by splitting the passed password string at ","
		$OldPasswordsList = [System.Collections.Generic.List[System.Object]]$OldPasswords.Split(",")
        
        ## Search for an empty password item in the generic list.
        [int]$EmptyItem = $OldPasswordsList.IndexOf("")
        
        ## If an empty entry was found..
        if ($EmptyItem -ge 0)
        {
            ## ..remove it at the determined position.
            $OldPasswordsList.RemoveAt($EmptyItem)
        }

        ## Search for an "12345678" item in the generic list.
        [int]$LenovoItem = $OldPasswordsList.IndexOf("MTIzNDU2Nzg=")
        
        ## If no "12345678" entry was found..
        if ($LenovoItem -eq -1)
        {
            ## ..insert to the first position/index the VW default empty password equivalent "12345678" (Lenovo workaround)
            $OldPasswordsList.Insert(0, "MTIzNDU2Nzg=")
        } elseif ($LenovoItem -gt 0) {
            ## If an "12345678" entry was found, remove it at the determined position and..
            $OldPasswordsList.RemoveAt($LenovoItem)

            ## ..insert to the first position/index the VW default empty password equivalent "12345678" (Lenovo workaround)
            $OldPasswordsList.Insert(0, "MTIzNDU2Nzg=")
        }
	}
	PROCESS
    {
        try
        {
            if (![System.String]::IsNullOrEmpty($OldPasswords) -or ![System.String]::IsNullOrEmpty($NewPassword))
            {
                ## Get WMI object/instance of Lenovo_BiosPasswordSettings & Lenovo_WmiOpcodeInterface class
	            $WMILenovoBiosPasswordSettings = Get-WmiObject -Namespace "root/wmi" -Class "Lenovo_BiosPasswordSettings" -ErrorAction Stop
	            $WMILenovoSetBiosPassword = Get-WmiObject -Namespace "root/wmi" -Class "Lenovo_WmiOpcodeInterface" -ErrorAction Stop

	            foreach ($PasswordSetting in $WMILenovoBiosPasswordSettings)
                {
                    #region Check if supervisor password is set (PasswordState)
                    ## 0 - No passwords set
                    ## 1 - Power on password set
                    ## 2 - Supervisor password set
                    ## 3 - Power on password and Supervisor password set
                    ## 4 - User HDD or User HDD and Master password set
                    ## 5 - Power on password and (User HDD or User HDD and Master password) set
                    ## 6 - Supervisor password and (User HDD or User HDD and Master password) set
                    ## 7 - Power on password, Supervisor password, and (User HDD or User HDD and Master password) set
                    #endregion

                    Write-Log -Message "Check the WMI BIOS/UEFI PasswordState of the current device.." -Type 1 -Info $MyInvocation
                    Write-Log -Message "$(Convert-PasswordStateToText $PasswordSetting.PasswordState) (PasswordState: $($PasswordSetting.PasswordState))" -Type 1 -Info $MyInvocation

                    ## If a supervisor password is set..
		            if ([int[]](2,3,6,7) -contains $PasswordSetting.PasswordState)
                    {
                        ## Go through the password pool and try to change the password.
                        for ($i=0; $i -le ($OldPasswordsList.Count - 1); $i++)
                        {
                            ## Check if password variable can be converted from Base64 to plain text
                            try {
                                if ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($OldPasswordsList[$i].ToString()))) {
                                    Write-Log -Message "The old BIOS password is Base64 converted." -Type 1 -Info $MyInvocation
                                    $OldPassword = Get-DecodedPassword $OldPasswordsList[$i].ToString()
                                } else {
                                    $OldPassword = $OldPasswordsList[$i].ToString()
                                }
                            } catch { $OldPassword = $OldPasswordsList[$i].ToString() }

                            ## Construct the WMI password parameter set and..
                            [System.Collections.Specialized.OrderedDictionary]$WmiOpcodeInterfaceParms = New-Object System.Collections.Specialized.OrderedDictionary
                            $WmiOpcodeInterfaceParms.Add("WmiOpcodePasswordType", "WmiOpcodePasswordType:pap;")
                            $WmiOpcodeInterfaceParms.Add("WmiOpcodePasswordAdmin", "WmiOpcodePasswordAdmin:$($OldPassword);")
                            $WmiOpcodeInterfaceParms.Add("WmiOpcodePasswordCurrent01", "WmiOpcodePasswordCurrent01:$($OldPassword);")
                            $WmiOpcodeInterfaceParms.Add("WmiOpcodePasswordNew01", "WmiOpcodePasswordNew01:$($NewPassword);")
                            $WmiOpcodeInterfaceParms.Add("WmiOpcodePasswordSetUpdate", "WmiOpcodePasswordSetUpdate;")
                                                        
                            ## ..call the WmiOpcodeInterface() WMI method to change the password.
                            :nextpwd foreach ($WmiOpcodeInterfaceParm in $WmiOpcodeInterfaceParms.GetEnumerator())
                            {
                                $ExitMessage = $WMILenovoSetBiosPassword.WmiOpcodeInterface($WmiOpcodeInterfaceParm.Value).Return
                                switch ($ExitMessage.ToUpper())
                                { 
                                    "SUCCESS" {
                                        Write-Log -Message "Successfully executed the WMI method <WmiOpcodeInterface()> with the parameter <$($WmiOpcodeInterfaceParm.Key)> (Try $($i + 1) of $($OldPasswordsList.Count))." -Type 1 -Info $MyInvocation
                                    }
                                    default {
                                        Write-Log -Message "Failed to execute the WMI method <WmiOpcodeInterface()> with the parameter <$($WmiOpcodeInterfaceParm.Key)> (Try $($i + 1) of $($OldPasswordsList.Count)). (Return: $($ExitMessage) / PasswordState: $($PasswordSetting.PasswordState))" -Type 3 -Info $MyInvocation
                                        break nextpwd
                                    }
                                }
                            }

                            ## If password change was successful, exit the function and return the right old password.
		                    if ($ExitMessage.ToUpper() -eq "SUCCESS") {
                                $ResultObject.Result = $OldPasswordsList[$i].ToString()
                                $ResultObject.IsError = $false
                                $ResultObject.LogEntry = "Successfully changed the BIOS/UEFI password."
                                break
		                    }
                        }
		            }
                    else {
                        Write-Log -Message "The current supervisor password (BIOS password) is empty. Its not possible to set a new password via WMI. Please set the default start password '12345678' manually and try again. (PasswordState: $($PasswordSetting.PasswordState))" -Type 2 -Info $MyInvocation
                    }
	            }
            }
            else {
                $ResultObject.Result = $null
                $ResultObject.IsError = $false
                $ResultObject.LogEntry = "The old password collection and the new password string are empty. No password change needed."
            }
		}
		catch
        {
            $ResultObject = Get-ErrorObject $_
            foreach ($Message in $ResultObject.ErrorMessages) {
                Write-Log -Message $Message -Type 3 -Info $MyInvocation
            }
            $ResultObject.LogEntry = "Failed to change the BIOS/UEFI password."
        }
        return $ResultObject
    }
    END {}
}

Function Set-BiosSettings
{
    <#
	.SYNOPSIS
		Sets/changes BIOS/UEFI configuration.
	.DESCRIPTION
		Sets/changes BIOS/UEFI configuration using the BIOS/UEFI password.
	.PARAMETER ListOfBiosSettingsToSet
		A hash table holding the configuration to be applied to the current device.
	.PARAMETER BiosPassword
		A string representing the current BIOS/UEFI password (Base64 string).
    .INPUTS
        System.String
        System.Collections.Hashtable
    .OUTPUTS
        System.Management.Automation.PSCustomObject
	.EXAMPLE
		Set-BiosSettings -ListOfBiosSettingsToSet <Hashtable> -BiosPassword "current_password"
	#>

    [OutputType([pscustomobject])]
    PARAM
	(
		[Parameter(Mandatory=$true, Position=0)]
		[System.Collections.Hashtable]$ListOfBiosSettingsToSet,
		
		[Parameter(Mandatory=$false, Position=1)]
		[string]$BiosPassword
	)

	BEGIN
    {
        ## Create new result object
        $ResultObject = New-ResultObject
        $ResultObject.IsError = $true
        $ResultObject.LogEntry = "Failed to change the BIOS/UEFI configuration."

        ## If the password string is $null replace it with "12345678" (Lenovo workaround)
        if ($BiosPassword -eq $null) {
            $BiosPassword = "MTIzNDU2Nzg="
        }

        ## Check if password variable can be converted from Base64 to plain text
        try {
            if ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BiosPassword))) {
                Write-Log -Message "The BIOS password is Base64 converted." -Type 1 -Info $MyInvocation
                $BiosPassword = Get-DecodedPassword $BiosPassword
            }
        } catch { }
	}	
	PROCESS
    {
        try
        {
            $WMISetBiosSetting = Get-WmiObject -Namespace "root/wmi" -Class "Lenovo_SetBiosSetting" -ErrorAction Stop
            $WMIOpcodeInterface = Get-WmiObject -Namespace "root/wmi" -Class "Lenovo_WmiOpcodeInterface" -ErrorAction Stop
            $WMISaveBiosSettings = Get-WmiObject -Namespace "root/wmi" -Class "Lenovo_SaveBiosSettings" -ErrorAction Stop

            ## Go through the hashtable and..
	        foreach ($Setting in $ListOfBiosSettingsToSet.GetEnumerator())
            {
                ## ..set the BIOS/UEFI option to the specified value with WMI method SetBiosSetting().
		        [string]$ExitMessage = $WMISetBiosSetting.SetBiosSetting("$($Setting.Key),$($Setting.Value)").Return
		        
                if ($ExitMessage.ToUpper() -eq "SUCCESS") {
			        Write-Log -Message "<$($Setting.Key)> successfully set to <$($Setting.Value)>." -Type 1 -Info $MyInvocation
		        } else {
			        Write-Log -Message "<$($Setting.Key)> could not be set to <$($Setting.Value)>. ErrorMessage: $($ExitMessage)." -Type 2 -Info $MyInvocation
		        }
            }

            ## Authenticate via WMI method WmiOpcodeInterface().
		    [string]$ExitMessage = $WMIOpcodeInterface.WmiOpcodeInterface("WmiOpcodePasswordAdmin:$($BiosPassword);").Return
		        
            if ($ExitMessage.ToUpper() -eq "SUCCESS") {
			    Write-Log -Message "Password authentication via WMI parameter <WmiOpcodePasswordAdmin> successful." -Type 1 -Info $MyInvocation
		    } else {
			    throw "Password authentication via WMI parameter <WmiOpcodePasswordAdmin> failed. ErrorMessage: $($ExitMessage)."
		    }
                
            ## Save the changed BIOS/UEFI option(s)/value(s) via WMI method SaveBiosSettings().
		    $ExitMessage = $WMISaveBiosSettings.SaveBiosSettings().Return
		        
            if ($ExitMessage.ToUpper() -eq "SUCCESS") {
			    Write-Log -Message "The settings have been succesfully saved." -Type 1 -Info $MyInvocation
		    } else {
			    throw "The settings could not be saved. ErrorMessage: $($ExitMessage)."
		    }

            $ResultObject.Result = $true
            $ResultObject.IsError = $false
            $ResultObject.LogEntry = "Successfully changed the BIOS/UEFI configuration."
		}
		catch
        {
            $ResultObject = Get-ErrorObject $_
            foreach ($Message in $ResultObject.ErrorMessages) {
                Write-Log -Message $Message -Type 3 -Info $MyInvocation
            }
            $ResultObject.LogEntry = "Failed to change the BIOS/UEFI configuration."
        }
        return $ResultObject
    }
    END {}
}

Function Get-OppositeFromValue
{
    <#
	.SYNOPSIS
		Get value opposit.
	.DESCRIPTION
		Returns the value and its opposit as string array.
	.PARAMETER Value
		The value from which you want to get the opposit.
    .INPUTS
        System.String
    .OUTPUTS
        System.Collections.Generic.List
	.EXAMPLE
		Get-OppositeFromValue -Value "Enable"
	#>

    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    BEGIN {}
    PROCESS
    {
        switch ($Value)
        {
            "Enable" { $Value = "$($Value):Disable" }
            "Disable" { $Value = "$($Value):Enable" }
            "Enabled" { $Value = "$($Value):Disabled" }
            "Disabled" { $Value = "$($Value):Enabled" }
            "IPv4First" { $Value = "$($Value):IPv6First" }
            "IPv6First" { $Value = "$($Value):IPv4First" }
            "AHCI" { $Value = "$($Value):RAID" }
            "RAID" { $Value = "$($Value):AHCI" }
            default { }
        }

        return [System.Collections.Generic.List[System.Object]]$Value.Split(":")
    }
    END {}
}

Function Convert-PasswordStateToText
{
    <#
	.SYNOPSIS
		Get informations about the WMI BIOS/UEFI PasswordState.
	.DESCRIPTION
		Returns informations about the passed WMI BIOS/UEFI PasswordState.
	.PARAMETER PasswordState
		The PasswordState number (0-7) from which you want to get the meaning.
    .INPUTS
        System.Int32
    .OUTPUTS
        System.String
	.EXAMPLE
		Convert-PasswordStateToText -PasswordState 2
	#>

    [CmdletBinding()]
    [OutputType([string])]
    PARAM
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateRange(0,7)]
        [int]$PasswordState
    )

    BEGIN {}
    PROCESS
    {
        switch ($PasswordState)
        {
            "0" { return "No passwords set" }
            "1" { return "POWER ON password set" }
            "2" { return "SUPERVISOR password set" }
            "3" { return "POWER ON password and SUPERVISOR password set" }
            "4" { return "USER HDD or (USER HDD and MASTER password set)" }
            "5" { return "POWER ON password and (USER HDD or (USER HDD and MASTER password)) set" }
            "6" { return "SUPERVISOR password and (USER HDD or (USER HDD and MASTER password)) set" }
            "7" { return "POWER ON password, SUPERVISOR password and (USER HDD or (USER HDD and MASTER password)) set" }
            default { return "Unknown PasswordState" }
        }
    }
    END {}
}

Function Export-BiosSettingsToFile
{
    <#
	.SYNOPSIS
		Saves BIOS/UEFI settings to file.
	.DESCRIPTION
		Exports the passed BIOS/UEFI settings hashtable to file.
	.PARAMETER BiosSettings
		The hashtable holding the configuration you want to export to file.
	.PARAMETER FilePath
		The name of the export file including absolute path.
    .INPUTS
        System.String
        System.Collections.Hashtable
    .OUTPUTS
        System.Management.Automation.PSCustomObject
	.EXAMPLE
		Export-BiosSettingsToFile -BiosSettings <Hashtable> -FilePath "$env:TEMP\BIOS_Export.txt"
	#>

    [OutputType([pscustomobject])]
    PARAM
    (
        [Parameter(Mandatory=$true, Position=0)]
		[System.Collections.Hashtable]$BiosSettings,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
		[string]$FilePath
    )

    BEGIN
    {
        ## Create new result object
        $ResultObject = New-ResultObject
    }
    PROCESS
    {
        try
        {
            ## Check if hashtable contains data,..
		    if ($BiosSettings)
            {
			    ## ..create export file if not exists and write the BIOS/UEFI configuration to it.
	            $BiosSettings.GetEnumerator() | Sort-Object Name | ForEach-Object {"{0}={1}" -f $_.Name,$_.Value} | Add-Content -Path $FilePath -Encoding UTF8 -Force -ErrorAction SilentlyContinue
		    
                ## Check whether the file exists and whether the file is larger than 100 bytes to get a rudimentary success check.
                if ((Test-Path $FilePath) -and ((Get-Item $FilePath).Length -gt 100)) {
                    $ResultObject.Result = $true
                    $ResultObject.LogEntry = "Successfully exported the BIOS/UEFI configuration."                    
                    Rename-Item -Path $FilePath -NewName $($FilePath -replace ".txt", ".log") -Force
                } else {
                    $ResultObject.IsError = $true
                    $ResultObject.LogEntry = "Failed to export the BIOS/UEFI configuration."
                }
            }
	    }
        catch
        {
            $ResultObject = Get-ErrorObject $_
            foreach ($Message in $ResultObject.ErrorMessages) {
                Write-Log -Message $Message -Type 3 -Info $MyInvocation
            }
            $ResultObject.LogEntry = "Failed to export the BIOS/UEFI configuration."
        }
        return $ResultObject
    }
    END {}
}