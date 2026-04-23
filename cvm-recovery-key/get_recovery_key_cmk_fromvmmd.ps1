<#
.SYNOPSIS
    Extracts a Recovery Key either from an VMMD SAS URL or from VMMD.VHD file.
#>

param(
    [Parameter(Mandatory=$true, ParameterSetName='VmmdSas', HelpMessage="VMMD SAS URL with read access.")]
    [string] $vmmdSas,
    [Parameter(Mandatory=$true, ParameterSetName='VmmdRecoveryKeyData', HelpMessage="VMMD.RECOVERYKEYDATA file path.")]
    [string] $vmmdRecoveryKeyDataPath
)

$ErrorActionPreference = 'Stop'

switch($PSCmdlet.ParameterSetName)
{
    'VmmdSas'
    {
        $guid = New-Guid
        $vmmdFile = "vmmd_$guid"
        $response = Invoke-WebRequest -Uri $vmmdSas -UseBasicParsing
        $vmmdContent = ""
        $stringContent = [System.Text.Encoding]::UTF8.GetString($response.Content)

        foreach ($char in $stringContent.ToCharArray()) {
            if ($char -eq 0) {
                break
            }
            $vmmdContent += $char
        }
        Set-Content -Path $vmmdFile -Value $vmmdContent

        $vmmdJsonObject = $vmmdContent | ConvertFrom-Json
        

        if (-not $vmmdJsonObject.DiskEncryptionSettings.recoverykey_info)
        {
            throw 'RecoveryKeyInfo does not exist'
        }

        $algorithm = $vmmdJsonObject.DiskEncryptionSettings.recoverykey_info.algorithm_type
        $keyUri = $vmmdJsonObject.DiskEncryptionSettings.recoverykey_info.key_id
        $wrappedKey = $vmmdJsonObject.DiskEncryptionSettings.recoverykey_info.wrapped_key
        $osType = $vmmdJsonObject.DiskEncryptionSettings.recoverykey_info.os_type

        if ($algorithm -is [String[]])
        {
            $algorithm = $algorithm[0]
        }
        if ($keyUri -is [String[]])
        {
            $keyUri = $keyUri[0]
        }
        if ($wrappedKey -is [String[]])
        {
            $wrappedKey = $wrappedKey[0]
        }
        if ($osType -is [String[]])
        {
            $osType = $osType[0]
        }
    }

    'VmmdRecoveryKeyData'
    {
        $metadataContent = Get-Content $vmmdRecoveryKeyDataPath
        $metadata = @{}
        $metadataContent.Split(':') | %{$item = $_.Split('='); $metadata += @{$item[0] = $item[1]}}

        $algorithm = $metadata['algorithm_type']
        $keyUri = $metadata['key_id']
        $wrappedKey = $metadata['wrapped_key']
        $osType = $metadata['os_type']
    }
}

Write-Host "Keyuri: $keyUri"
$resource = [uri]$keyUri

# Finding Key Vault or Managed HSM resource URL
$azureContext = Get-AzContext
if ($resource.Authority.EndsWith($azureContext.Environment.AzureKeyVaultDnsSuffix)) # i.e. vault.azure.net
{ 
    $vaultResourceUrl = $azureContext.Environment.AzureKeyVaultServiceEndpointResourceId
} 
elseif ($resource.Authority.EndsWith($azureContext.Environment.ExtendedProperties['ManagedHsmServiceEndpointSuffix'])) # i.e. managedhsm.azure.net
{ 
    $vaultResourceUrl = $azureContext.Environment.ExtendedProperties['ManagedHsmServiceEndpointResourceId']
} 
else
{
    throw "Unknown resouce authority $($resource.Authority)"
}

Write-Verbose "Vault resource url: $vaultResourceUrl"

$azureAccessToken = Get-AzAccessToken -ResourceUrl $vaultResourceUrl
if($azureAccessToken -eq $null)
{
    throw "Azure access token not available."
}

# Newer AzCLI SDK versions has Token of type System.Security.SecureString
if ($azureAccessToken.Token -is [System.Security.SecureString])
{
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($azureAccessToken.Token)
    try
    {
        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}
else
{
    $token = $azureAccessToken.Token
}

# Convert Base64 string to Base64Url required by MHSM
$base64url = $wrappedKey.Split('=')[0]
$base64url = $base64url.Replace('+', '-')
$base64url = $base64url.Replace('/', '_')
					   

$headers = @{'Authorization' = "Bearer $($token)"; "Content-Type" = "application/json" }
		
$Body = @{
        "alg" = "$($algorithm)"
        "value" = "$($base64url)"
        }
$unwrapUri = $keyUri.TrimEnd("/") + "/unwrapkey?api-version=7.1"
$Parameters = @{
    Method = "POST"
    Uri =  "$($unwrapUri)"
    Body = ($Body | ConvertTo-Json) 
    Headers =  $headers 
}

$response = Invoke-RestMethod @Parameters #response in base64
If (-not $response) 
{
    throw "Can't recieve an answer from $unwrapUri"
}

# Convert Base64Url string returned by KeyVault unwrap to Base64 string
$secretBase64 = $response.value
$secretBase64 = $secretBase64.Replace('-', '+');
$secretBase64 = $secretBase64.Replace('_', '/');
if ($secretBase64.Length %4 -eq 2)
{
    $secretBase64+= '==';
}
elseif ($secretBase64.Length %4 -eq 3)
{
    $secretBase64+= '=';
}

if ($osType -eq "Windows")
{
    $recoveryKey = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($secretBase64))
    Write-Host "Windows recovery key is : $recoveryKey"
}
else
{
    # Linux
    $byteArray = [Convert]::FromBase64String($secretBase64)
    if ($byteArray.Length -ne 16)
    {
        throw "Byte array size is not of correct length"
    }

    $recoveryArray = New-Object System.Collections.ArrayList
    for($i = 0; $i -le 7; $i++)
    {
        $recoveryArray.Add([bitconverter]::ToUInt16($byteArray,$i * 2).ToString("D5")) | Out-Null
    }
    $recoveryKey =  $recoveryArray -join "-"
    Write-Host "Linux recovery key in base64 format is: $secretBase64"
    Write-Host "Linux recovery key is : $recoveryKey"
}