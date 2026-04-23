<#
.SYNOPSIS
    Extracts a Recovery Key either from an uploaded VMGS.VHD file, or from a local VMGS.METADATA file.
#>

param(
    [Parameter(Mandatory=$true, ParameterSetName='VmgsSas', HelpMessage="VMGS SAS URL with read access.")]
    [string] $vmgsSas,
    [Parameter(Mandatory=$true, ParameterSetName='VmgsMetadata', HelpMessage="VMGS.METADATA file path.")]
    [string] $vmgsMetadataPath
)

$ErrorActionPreference = 'Stop'

switch($PSCmdlet.ParameterSetName)
{
    'VmgsSas'
    {
        $response = Invoke-WebRequest -Uri $vmgsSas -Method Head
        if (-not $response) 
        {
            throw "Get headers request for VMGS disk failse."
        }

        $headers = $response.Headers
        if (-not $headers.ContainsKey('x-ms-meta-Cvm_recovery_key_alg'))
        {
            throw 'x-ms-meta-Cvm_recovery_key_alg does not exist'
        }
        if (-not $headers.ContainsKey('x-ms-meta-Cvm_recovery_key_identifier'))
        {
            throw 'x-ms-meta-Cvm_recovery_key_identifier does not exist'
        }
        if (-not $headers.ContainsKey('x-ms-meta-Cvm_wrapped_recovery_key'))
        {
            throw 'x-ms-meta-Cvm_wrapped_recovery_key does not exist'
        }
        if (-not $headers.ContainsKey('x-ms-meta-Cvm_recovery_key_os_type'))
        {
            throw 'x-ms-meta-Cvm_recovery_key_os_type does not exist'
        }

        $algorithm = $headers.'x-ms-meta-Cvm_recovery_key_alg'
        $keyUri = $headers.'x-ms-meta-Cvm_recovery_key_identifier'
        $wrappedKey = $headers.'x-ms-meta-Cvm_wrapped_recovery_key'
        $osType = $headers.'x-ms-meta-Cvm_recovery_key_os_type'

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

    'VmgsMetadata'
    {
        $metadataContent = Get-Content $vmgsMetadataPath
        $metadata = @{}
        $metadataContent.Split(';') | %{$item = $_.Split('='); $metadata += @{$item[0] = $item[1]}}

        $algorithm = $metadata['Cvm_recovery_key_alg']
        $keyUri = $metadata['Cvm_recovery_key_identifier']
        $wrappedKey = $metadata['Cvm_wrapped_recovery_key']
        $osType = $metadata['Cvm_recovery_key_os_type']
    }
}

$resource = [uri]$keyUri
if ($resource.Authority.EndsWith("vault.azure.net"))
{
    $token = $(az account get-access-token --resource=https://vault.azure.net --query accessToken --output tsv)
}
elseif ($resource.Authority.EndsWith("managedhsm.azure.net"))
{
    $token = $(az account get-access-token --resource=https://managedhsm.azure.net --query accessToken --output tsv)
}
else
{
    throw "Cannot recognize Azure vault type from the key's URI '$resource'"
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
    Write-Host "Linux recovery key is : $recoveryKey"
}