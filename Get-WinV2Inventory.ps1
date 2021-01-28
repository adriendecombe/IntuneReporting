<#
.SYNOPSIS
    This script performs the Export of Intune Inventory Data.
    the script has been created by Adrien Decombe - adrien.decombe@exakis-nelite.com for Windows Edition V2 Product at AXA
.DESCRIPTION
	The script is provided as a template to perform the Export of Intune Inventory Data into Azure Storage Account Table
.NOTES
    Version: 2.0
    Author: Adrien Decombe
    Creation Date: 23/11/2020
#>

####################################################
###########      Auth Functions      ###############
####################################################

Function Get-AuthToken {
    <#
    .SYNOPSIS
    Function to request and return the GraphAPI OAuth2 token for futur requests
    
    .DESCRIPTION
    Function to request and return the GraphAPI OAuth2 token for futur requests
    
    .PARAMETER ClientID
    Id of the App Registration
    
    .PARAMETER ClientSecret
    Client Secret generated in the app registration
    
    .PARAMETER TenantID
    Id the the targeted Tenant
    
    .EXAMPLE
    Get-AuthTokenClientSecret -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $ClientID,
        [Parameter(Mandatory = $true)]
        $ClientSecret,
        [Parameter(Mandatory = $true)]
        $TenantID
    )

    # Azure AD OAuth Token for Graph API
    # Body params
    $granttype = 'client_credentials'
    $scope = 'https://graph.microsoft.com/.default'

    # Construct URI
    $uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id  = $clientId
        scope      = $scope
        grant_type = $granttype
        client_secret   = $ClientSecret
    }

    # Get OAuth 2.0 Token
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

    # Access Token
    $token = ($tokenRequest.Content | ConvertFrom-Json).access_token

    $Date = Get-Date $(Get-Date).AddSeconds(3600)

    $Header = @{
        'Content-Type' = 'application-json'
        Authorization  = "Bearer $Token"
        ExpiresOn      = $Date
    }
    return $Header
}

####################################################
########      Graph Rest Functions      ############
####################################################

Function Invoke-ListGraphRequest {
    <#
    .SYNOPSIS
    Function to make a List Graph Request
    
    .DESCRIPTION
    This function makes a list graph request
    This is used when the ressource we are requesting contains multiple entries
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER graphApiVersion
    The Graph API version that you wish to use
    Beta or v1.0
    
    .PARAMETER Resource
    The path for the ressource
    
    .EXAMPLE
    Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion "beta" -Resource "/deviceManagement/windowsAutopilotDeviceIdentities"
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        $AuthToken, 
        [Parameter(Mandatory = $True)]
        $graphApiVersion,
        [Parameter(Mandatory = $True)]
        $Resource
    )
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

        $Results = $Response.value
        $NextLink = $Response."@odata.nextLink"
        while ($null -ne $NextLink) {
            Get-GraphToken -TenantID $TenantID -User $User -Pass $Pass
            $Response = (Invoke-RestMethod -Uri $NextLink -Headers $authToken -Method Get)
            $NextLink = $null
            $NextLink = $Response."@odata.nextLink"
            $Results += $Response.value
        }
        return $Results
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Output "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Output
        break
    }
}

Function Invoke-GetGraphRequest {
    <#
    .SYNOPSIS
    Function to make a Get Graph Request
    
    .DESCRIPTION
    This function makes a Get graph request
    This is used when the ressource we are requesting contains only one entry
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER graphApiVersion
    The Graph API version that you wish to use
    Beta or v1.0
    
    .PARAMETER Resource
    The path for the ressource
    
    .EXAMPLE
    Invoke-GetGraphRequest -AuthToken $AuthToken -graphApiVersion "beta" -Resource "/users/59f9f842-9586-47d9-b4d9-615deda120af"
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $graphApiVersion,
        [Parameter(Mandatory = $True)]
        $Resource
    )
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $Response = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        return $Response
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Output "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Output
        break
    }
}

####################################################
########   Custom Formating Functions      #########
####################################################

function Get-IntuneInventory {
    <#
    .SYNOPSIS
    Function to execute the intune device inventory
    
    .DESCRIPTION
    This function executes the intune Windows Autopilot device inventory
    it first gather all windows managed devices, then for each of them will get the primary user info
    then will consolidate all necessary data, and will upload it to the given storage account table
    
    .PARAMETER Date
    The date of the extract with following format
    %Y-%m-%dT%H:%M:%S
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER Ctx
    The storage context for azure storage account
    New-AzStorageContext
    
    .PARAMETER TableName
    The name of the table to which the data will be pushed
    
    .EXAMPLE
    Get-IntuneInventory -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $DeviceTableName

    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Date,
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )
    
    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTable

    $DateFile = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S"

    $graphApiVersion = "beta"
    $Resource = "/deviceManagement/windowsAutopilotDeviceIdentities"
    $AutopilotDevices = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource

    $graphApiVersion = "beta"
    $Resource = "/deviceManagement/managedDevices"
    $ManagedDevices = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource | Where-Object { ($_.operatingSystem -like "*Windows*") }
    $AutopilotManagedDevices = $ManagedDevices | Where-Object { ($_.joinType -like "azureADJoined") -and ($_.autopilotEnrolled -like "True") }
    
    $Progress = 0

    foreach ($device in $AutopilotManagedDevices) {
        
        $userid = $device.userId
        if ($userID) {
            $graphApiVersion = "beta"
            $Resource = "users/$userid"
            $ADUser = Invoke-GetGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource
        }
        else {
            $ADUser = $Null
        }
        $AutopilotDevice = $AutopilotDevices | Where-Object { $_.serialNumber -eq $device.serialNumber } | Select-Object -First 1

        $HashTable = @{}
        $HashTable["Date"] = $DateFile
        $HashTable["ID"] = $Device.ID
        $HashTable["DeviceName"] = $Device.deviceName
        $HashTable["Manufacturer"] = $Device.manufacturer
        $HashTable["Model"] = $Device.model
        $HashTable["SerialNumber"] = $Device.serialNumber
        $HashTable["OS"] = $Device.operatingSystem
        $HashTable["OsVersion"] = $Device.osVersion
        $HashTable["totalStorageSpace"] = $([int]$($Device.totalStorageSpaceInBytes / 1000000000))
        $HashTable["freeStorageSpace"] = $([int]$($Device.freeStorageSpaceInBytes / 1000000000))
        $HashTable["PrimaryUser"] = $Device.userDisplayName
        $HashTable["PrimaryUserUPN"] = $Device.userPrincipalName
        $HashTable["lastSyncDateTime"] = $Device.lastSyncDateTime
        $HashTable["GroupTag"] = $AutopilotDevice.GroupTag

        $HashTable["PrimaryUserMail"] = $ADUser.mail
        $HashTable["PrimaryUserCountry"] = $ADUser.country
        $HashTable["PrimaryUserCompany"] = $ADUser.companyName

        
        $nullKeys = $HashTable.Keys |Where-Object {($null -eq $HashTable[$_]) -or ($HashTable[$_] -eq "")}
        $nullKeys |ForEach-Object { $HashTable[$_] = "None"}

        $RowKey = $Progress.ToString('000000000')
        try {
            Add-AzTableRow -table $CloudTable -partitionKey $DateFile -RowKey $RowKey -property $HashTable >> $null
        }
        catch {
            Write-Output "Error"
        }
        $Progress++
    }
}

Function Get-AllDeviceConfigStatus {
    <#
    .SYNOPSIS
    Function to execute the intune Configuration inventory
    
    .DESCRIPTION
    This function executes the intune Configuration inventory
    it first gather all windows Configuration profiles, then for each of them will get the status for each assigned devices
    then will consolidate all necessary data, and will upload it to the given storage account table
    
    .PARAMETER Date
    The date of the extract with following format
    %Y-%m-%dT%H:%M:%S
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER Ctx
    The storage context for azure storage account
    New-AzStorageContext
    
    .PARAMETER TableName
    The name of the table to which the data will be pushed
    
    .EXAMPLE
    Get-AllDeviceConfigStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $ComplianceTableName
    
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Date,
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )

    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTabl

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceConfigurations"
    $AllConfig = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource
    $WindowsConfig = $AllConfig | Where-Object { $_."@odata.Type" -like "*Windows*" }

    $Progress = 0
    foreach ($Config in $WindowsConfig) {
        $ConfigName = $Config.DisplayName

        $graphApiVersion = "beta"
        $Resource = "/deviceManagement/deviceConfigurations/$($Config.ID)/deviceStatuses"
        $AllStatus = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource | Where-Object { $_.status -ne "notApplicable" }

        if ($AllStatus) {
            foreach ($Status in $AllStatus) {

                $HashTable = @{}
                $HashTable["Date"] = $Date
                $HashTable["ID"] = $Status.ID
                $HashTable["ConfigName"] = $ConfigName
                $HashTable["DeviceName"] = $Status.deviceDisplayName
                $HashTable["Username"] = $Status.userName
                $HashTable["status"] = $Status.status
                $HashTable["LastReport"] = $Status.lastReportedDateTime

                $RowKey = $Progress.ToString('000000000')
                try {
                    Add-AzTableRow -table $CloudTable -partitionKey $Date -RowKey $RowKey -property $HashTable >> $null
                }
                catch {
                    Write-Output "Error"
                }
                $Progress++
            }
        }
    }
}

Function Get-AllDeviceComplianceStatus {
    <#
    .SYNOPSIS
    Function to execute the intune compliance inventory
    
    .DESCRIPTION
    This function executes the intune compliance inventory
    it first gather all windows compliance profiles, then for each of them will get the status for each assigned devices
    then will consolidate all necessary data, and will upload it to the given storage account table
    
    .PARAMETER Date
    The date of the extract with following format
    %Y-%m-%dT%H:%M:%S
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER Ctx
    The storage context for azure storage account
    New-AzStorageContext
    
    .PARAMETER TableName
    The name of the table to which the data will be pushed
    
    .EXAMPLE
    Get-AllDeviceComplianceStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $ComplianceTableName
    
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Date,
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )

    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTable

    $DateFile = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S"

    $graphApiVersion = "beta"
    $Resource = "/deviceManagement/deviceCompliancePolicies"
    $AllCompliance = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource
    $WindowsCompliance = $AllCompliance | Where-Object { $_."@odata.Type" -like "*Windows*" }

    $Progress = 0
    foreach ($Compliance in $WindowsCompliance) {

        $ComplianceName = $Compliance.DisplayName
            
        $graphApiVersion = "Beta"
        $Resource = "/deviceManagement/deviceCompliancePolicies/$($Compliance.ID)/deviceStatuses"
        $AllStatus = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource | Where-Object { $_.status -ne "notApplicable" }
        
        if ($AllStatus) {
            foreach ($Status in $AllStatus) {
            
                $HashTable = @{}
                $HashTable["Date"] = $DateFile
                $HashTable["ID"] = $Status.ID
                $HashTable["ComplianceName"] = $ComplianceName
                $HashTable["DeviceName"] = $Status.deviceDisplayName
                $HashTable["Username"] = $Status.userName
                $HashTable["status"] = $Status.status
                $HashTable["LastReport"] = $Status.lastReportedDateTime

                $RowKey = $Progress.ToString('000000000')
                try {
                    Add-AzTableRow -table $CloudTable -partitionKey $DateFile -RowKey $RowKey -property $HashTable >> $null
                }
                catch {
                    Write-Output "Error"
                }
                $Progress++
            }
        }
    }
}

Function Get-AllAppInstallStatus {
    <#
    .SYNOPSIS
    Function to execute the intune App inventory
    
    .DESCRIPTION
    This function executes the intune App inventory
    it first gather all windows App, then for each of them will get the status for each assigned devices
    then will consolidate all necessary data, and will upload it to the given storage account table
    
    .PARAMETER Date
    The date of the extract with following format
    %Y-%m-%dT%H:%M:%S
    
    .PARAMETER AuthToken
    The variable containing the Auth Token that was requested by calling the Get-AuthToken function
    
    .PARAMETER Ctx
    The storage context for azure storage account
    New-AzStorageContext
    
    .PARAMETER TableName
    The name of the table to which the data will be pushed
    
    .EXAMPLE
    Get-AllAppInstallStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $ComplianceTableName
    
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Date,
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )

    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTable

    $DateFile = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S"

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    $AllApps = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource

    $WindowsApps = $AllApps | Where-Object { (($_.'@odata.type') -notlike ("*ios*")) }  | Where-Object { (($_.'@odata.type') -notlike ("*android*")) }

    $Progress = 0
    foreach ($App in $WindowsApps) {
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps/$($App.ID)/deviceStatuses"
        $AllStatus = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource | Where-Object {$_.installState -ne "notInstalled"}

        $AppType = $($($app.'@odata.type').Split('.'))[-1]

        if ($AllStatus) {
            foreach ($Status in $AllStatus) {
                
                $HashTable = @{}
                $HashTable["Date"] = $DateFile
                $HashTable["ID"] = $Status.ID
                $HashTable["AppName"] = $App.displayName
                $HashTable["AppID"] = $App.ID
                $HashTable["AppType"] = $AppType
                $HashTable["DeviceName"] = $Status.deviceName
                $HashTable["DeviceID"] = $Status.deviceId
                $HashTable["Username"] = $Status.userName
                $HashTable["InstallState"] = $Status.installState
                $HashTable["LastSync"] = $Status.lastSyncDateTime
                $HashTable["DisplayVersion"] = $Status.displayVersion
                $HashTable["ContentVersion"] = $App.committedContentVersion

                $nullKeys = $HashTable.Keys |Where-Object {($null -eq $HashTable[$_]) -or ($HashTable[$_] -eq "")}
                $nullKeys |ForEach-Object { $HashTable[$_] = "None"}

                $RowKey = $Progress.ToString('000000000')
                try {
                    Add-AzTableRow -table $CloudTable -partitionKey $DateFile -RowKey $RowKey -property $HashTable >> $null
                }
                catch {
                    Write-Output "Error"
                }
                $Progress++
            }
        }
    }
}

Function New-AzureStorageTable{
    <#
    .SYNOPSIS
    Table Init Function
    
    .DESCRIPTION
    Function that will create the azure storage table and populate the firsts rows needed for the Powerbi template report
    
    .PARAMETER Ctx
    Azure Storage Context
    
    .PARAMETER TableName
    Name of the table
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )

    New-AzStorageTable -Name $TableName -Context $Ctx
}

####################################################
###################   Main   #######################
####################################################
Function Main {
    <#
    .SYNOPSIS
    The Main workflow of the extraction
    
    .DESCRIPTION
    This function initialize variables needed for the execution
    Initialize the Storage Context for the azure Storage Account
    Then Get the Auth Token from Graph API
    Launches the Intune Device Inventory
    Launches the Intune Config Inventory
    Launches the Intune Compliance Inventory
    Launches the Intune App Inventory
    
    .EXAMPLE
    Main
    
    #>
    $TenantID = Get-AutomationVariable -Name TenantID
    $ClientID = Get-AutomationVariable -Name ClientID
    $ClientSecret = Get-AutomationVariable -Name ClientSecret
    
    $SAName = Get-AutomationVariable -Name SAName
    $SAKey = Get-AutomationVariable -Name SAKey
    $Ctx = New-AzStorageContext -StorageAccountName $SAName -StorageAccountKey $SAKey
    
    $DeviceTableName = Get-AutomationVariable -Name DeviceTableName
    $ConfigTableName = Get-AutomationVariable -Name ConfigTableName
    $ComplianceTableName = Get-AutomationVariable -Name ComplianceTableName
    $AppTableName = Get-AutomationVariable -Name AppTableName

    $Date = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S"
    
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $clientId -ClientSecret $ClientSecret
    }
    Catch {
        Write-Output "Error during token acquirement"
        Write-Output $_
        return -1
    }
    Try {
        Try{
            Get-AzStorageTable -Name $DeviceTableName -Context $Ctx -ErrorAction Stop >> $Null
        }
        catch{
            Write-Output "Table Missing, Creating and Initializing"
            New-ShiftTable -Ctx $ctx -TableName $TableName
            Start-Sleep 5
        }
        Get-IntuneInventory -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $DeviceTableName
    }
    Catch {
        Write-Output "Error during Device Inventory"
        Write-Output $_
        return -2
    }
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $clientId -ClientSecret $ClientSecret
    }
    Catch {
        Write-Output "Error during token acquirement"
        Write-Output $_
        return -1
    }
    Try {
        Try{
            Get-AzStorageTable -Name $ConfigTableName -Context $Ctx -ErrorAction Stop >> $Null
        }
        catch{
            Write-Output "Table Missing, Creating and Initializing"
            New-ShiftTable -Ctx $ctx -TableName $TableName
            Start-Sleep 5
        }
        Get-AllDeviceConfigStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $ConfigTableName
    }
    Catch {
        Write-Output "Error during Config Inventory"
        Write-Output $_
        return -3
    }
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $clientId -ClientSecret $ClientSecret
    }
    Catch {
        Write-Output "Error during token acquirement"
        Write-Output $_
        return -1
    }
    Try {
        Try{
            Get-AzStorageTable -Name $ComplianceTableName -Context $Ctx -ErrorAction Stop >> $Null
        }
        catch{
            Write-Output "Table Missing, Creating and Initializing"
            New-ShiftTable -Ctx $ctx -TableName $TableName
            Start-Sleep 5
        }
        Get-AllDeviceComplianceStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $ComplianceTableName
    }
    Catch {
        Write-Output "Error during Compliance Inventory"
        Write-Output $_
        return -4
    }
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $clientId -ClientSecret $ClientSecret
    }
    Catch {
        Write-Output "Error during token acquirement"
        Write-Output $_
        return -1
    }
    Try {
        Try{
            Get-AzStorageTable -Name $AppTableName -Context $Ctx -ErrorAction Stop >> $Null
        }
        catch{
            Write-Output "Table Missing, Creating and Initializing"
            New-ShiftTable -Ctx $ctx -TableName $TableName
            Start-Sleep 5
        }
        Get-AllAppInstallStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $AppTableName
    }
    Catch {
        Write-Output "Error during App Inventory"
        Write-Output $_
        return -5
    }
    return 0
}

Main