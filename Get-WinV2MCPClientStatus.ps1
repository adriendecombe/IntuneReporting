<#
.SYNOPSIS
	Verison 1.0
    This script performs the Export of MCP Client remidiation Script results. 
    the script has been created by Adrien Decombe - adrien.decombe@exakis-nelite.com
.DESCRIPTION
	The script is provided as a template to perform the Export of Intune Inventory Data

.NOTES
    Version: 1.1
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

Function Get-DeviceHealthStatus {
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
    $Resource = "/deviceManagement/deviceHealthScripts"
    $MCPHealthScriptDisplayName = "MCP Client Connectivity"

    $MCPHealthScript = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource | Where-Object {$_.DisplayName -Like $MCPHealthScriptDisplayName}

    $Progress = 0
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceHealthScripts/$($MCPHealthScript.ID)/deviceRunStates"
    $AllStatus = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource

    ##Line to delete in PROD
    $recentStatus = $AllStatus | Where-Object {$_.preRemediationDetectionScriptOutput -like "MCP Client Installed*"}

    if ($recentStatus) {
        foreach ($Status in $recentStatus) {
            
            $HashTable = @{}
            $HashTable["Date"] = $DateFile
            $HashTable["ID"] = $Status.ID
            $HashTable["DetectionState"] = $Status.detectionState
            $HashTable["LastSync"] = $Status.lastSyncDateTime
            $HashTable["lastStateUpdateDateTime"] = $Status.lastStateUpdateDateTime

            $PreOutput = $Status.preRemediationDetectionScriptOutput
            $PreOutputTab = $PreOutput.Split(',')

            Foreach($Line in $PreOutputTab){
                $SplitedLine = $Line.split('=')
                $Key = $SplitedLine[0].Replace(" ","")
                $Value = $SplitedLine[1]
                $HashTable[$Key] = $Value
            }

            $nullKeys = $HashTable.Keys |Where-Object {($null -eq $HashTable[$_]) -or ($HashTable[$_] -eq "")}
            $nullKeys | ForEach-Object { $HashTable[$_] = "None"}

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

function Get-IntuneInventory {
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

    $TenantID = Get-AutomationVariable -Name TenantID
    $ClientID = Get-AutomationVariable -Name ClientID
    $ClientSecret = Get-AutomationVariable -Name ClientSecret
    
    $SAName = Get-AutomationVariable -Name SAName
    $SAKey = Get-AutomationVariable -Name SAKey
    $Ctx = New-AzStorageContext -StorageAccountName $SAName -StorageAccountKey $SAKey

    $HealthTableName = Get-AutomationVariable -Name HealthTableName
    
    $Date = Get-Date -UFormat "%Y%m%d%H%M"
    
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret
    }
    Catch {
        $Stopwatch.Stop()
        Write-Host "Error during token acquirement"
        Write-Host $_
        return -1
    }
    
    Try {
        Try{
            Get-AzStorageTable -Name $HealthTableName -Context $Ctx -ErrorAction Stop >> $Null
        }
        catch{
            Write-Output "Table Missing, Creating and Initializing"
            New-ShiftTable -Ctx $ctx -TableName $TableName
            Start-Sleep 5
        }
        Get-DeviceHealthStatus -Date $Date -AuthToken $AuthToken -Ctx $Ctx -TableName $HealthTableName
    }
    Catch {
        Write-Host "Error during Health Inventory"
        Write-Host $_
        return -2
    }
    return 0
}

Main