<#
.SYNOPSIS
	Verison 1.0
    This script performs a full Intune Inventory Data export. 
    the script has been created by Adrien Decombe - adrien.decombe@exakis-nelite.com for Windows Edition V2 Product at AXA
.DESCRIPTION
	This script performs a full Intune Inventory Data export. 

.NOTES
    Version: 1.0
    Author: Adrien Decombe
    Creation Date: 23/11/2020
#>

####################################################
###########      Auth Functions      ###############
####################################################

Function Get-AuthToken {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $User,
        [Parameter(Mandatory = $true)]
        $Pass,
        [Parameter(Mandatory = $true)]
        $TenantID
    )

    # Azure AD OAuth Token for Graph API
    # Body params
    $granttype = 'password'
    $ClientID = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'
    $scope = 'https://graph.microsoft.com/.default'

    # Construct URI
    $uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id  = $clientId
        scope      = $scope
        grant_type = $granttype
        username   = $User
        password   = $Pass
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
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    }
}

Function Invoke-GetGraphRequest {
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
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    }
}

####################################################
########   Custom Formating Functions      #########
####################################################

function Get-FullIntuneInventory {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        $AuthToken,
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName
    )
    
    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTable

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"
    $ManagedDevices = Invoke-ListGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource
        
    foreach ($device in $ManagedDevices) {
        $userid = $device.userId
        if ($userID) {
            $graphApiVersion = "beta"
            $Resource = "users/$userid"
            $ADUser = Invoke-GetGraphRequest -AuthToken $AuthToken -graphApiVersion $graphApiVersion -Resource $Resource
        }
        else {
            $ADUser = $Null
            Continue
        }

        $HashTable = @{}
        $HashTable["ID"] = $Device.ID
        $HashTable["DeviceName"] = $Device.deviceName
        $HashTable["Manufacturer"] = $Device.manufacturer
        $HashTable["Model"] = $Device.model
        $HashTable["SerialNumber"] = $Device.serialNumber
        $HashTable["OS"] = $Device.operatingSystem
        $HashTable["OsVersion"] = $Device.osVersion
        $HashTable["PrimaryUser"] = $Device.userDisplayName
        $HashTable["PrimaryUserUPN"] = $Device.userPrincipalName
        $HashTable["lastSyncDateTime"] = $Device.lastSyncDateTime
        
        $HashTable["PrimaryUserMail"] = $ADUser.mail
        $HashTable["PrimaryUserID"] = $ADUser.ID
        $HashTable["PrimaryUserCountry"] = $ADUser.country
        $HashTable["PrimaryUserCompany"] = $ADUser.companyName

        $HashTable["imei"] = $Device.IMEI
        $HashTable["meid"] = $Device.meid

        $nullKeys = $HashTable.Keys | Where-Object {($null -eq $HashTable[$_]) -or ($HashTable[$_] -eq "")}
        $nullKeys | ForEach-Object { $HashTable[$_] = "None"}

        try {
            Add-AzTableRow -table $CloudTable -partitionKey $Device.serialNumber -RowKey $Device.ID -property $HashTable -UpdateExisting >> $null
        }
        catch {
            Write-Host "Error"
        }
        $Progress++
    }
}

function Clear-Table{
    param
    (
        [Parameter(Mandatory = $True)]
        $Ctx,
        [Parameter(Mandatory = $True)]
        $TableName,
        [Parameter(Mandatory = $false)]
        $LimitHour = -2
    )

    $Limit = Get-Date -Date $(Get-Date -Minute 0 -Second 0).AddHours($LimitHour) -UFormat "%Y-%m-%dT%H:%M:%S.000Z"

    $filter = "Timestamp le datetime'$($Limit)'"

    $CloudTable = (Get-AzStorageTable -Name $TableName -Context $Ctx).CloudTable
    $OldRows = Get-AzTableRow -table $cloudTable -customFilter $filter

    $OldRows | Remove-AzTableRow -table $cloudTable
}

####################################################
###################   Main   #######################
####################################################
Function Main {

    $TenantID = Get-AutomationVariable -Name TenantID
    $User = Get-AutomationVariable -Name User
    $Pass = Get-AutomationVariable -Name Pass

    $SAName = Get-AutomationVariable -Name SAName
    $SAKey = Get-AutomationVariable -Name SAKey
    $Ctx = New-AzStorageContext -StorageAccountName $SAName -StorageAccountKey $SAKey
    
    $TableName = Get-AutomationVariable -Name FullInventoryTableName
    
    Try {
        $AuthToken = Get-AuthToken -TenantID $TenantID -User $User -Pass $Pass
    }
    Catch {
        $Stopwatch.Stop()
        Write-Host "Error during token acquirement"
        Write-Host $_
        return -1
    }
    Try {
        Get-FullIntuneInventory -AuthToken $AuthToken -ctx $Ctx -TableName $TableName
    }
    Catch {
        Write-Host "Error during Device Inventory"
        Write-Host $_
        return -2
    }
    return 0
}
#Main