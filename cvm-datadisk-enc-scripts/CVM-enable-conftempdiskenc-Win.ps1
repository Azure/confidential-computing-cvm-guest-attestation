﻿<#
.SYNOPSIS
 This script can be used to turn on confidential temp disk encryption for an existing Azure Windows confidential VM.
 Usage: Open this script file in "Windows PowerShell ISE", or use CloudShell in Azure portal. Review and update each "Step". Afterwards, highlight the section and hit F8 to run in ISE or copy and paste into cloud shell.

 Requirements: 1-) The confidential VM is already created with confidential OS disk encrtyption on.
               2-) The VM SKU has a temp disk and it is formatted as NTFS.

 Status: This script is for public preview.
#>

#### Step 0: Make sure your Az powershell modules are up-to-date.

if ((Get-Module Az.Compute).Version.Major -lt 6)
{
    Update-Module -Name Az* -Force                                          # Requires elevated (admin) Powershell window
}

#### End of step 0


#### Step 1 - Set the global parameters which will be used throughout the script.

$subscriptionId    = "__SUB_ID_HERE__"                                      # User must have at least contributor access.
$resourceGroup     = "__RG_HERE__"                                          # Resource group
$cvmName           = "__CVM_NAME_HERE__"                                    # CVM must have been created beforehand. Follow https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-portal-amd
$location          = "__REGION_HERE__"                                      # Azure region where the CVM is created.
$kvName            = "__AKV_NAME_HERE__"                                    # Azure Key vault name. It must exist.

#### End of step 1


#### Step 2- Login to Azure and set context to the subscription

Login-AzAccount -Subscription $subscriptionId
Select-AzSubscription -SubscriptionId $subscriptionId

#### End of step 2


#### Step 3 - Install ADE with public settings defined below.

$keyvault = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $resourceGroup
if ($keyvault -eq $null)
{
    Write-Error("Failed to locate $kvName keyvault in $resourceGroup")
    break __Exit
}

# ADE settings:
$Publisher                   = "Microsoft.Azure.Security"
$ExtName                     = "AzureDiskEncryption"
$ExtHandlerVer               = "2.5"
$EncryptionOperation         = "EnableEncryption"

# Settings for enabling temp disk encryption only providing Azure Key Vault resource.
# Note: Key names in PublicSetting are case sensitive. Do not change the case.
$pubSettings                 = @{};
$pubSettings.Add("VolumeType", "Data")
$pubSettings.Add("EncryptionOperation", $EncryptionOperation)
$pubSettings.Add("KeyVaultURL", $keyvault.VaultUri)
$pubSettings.Add("KeyVaultResourceId", $keyvault.ResourceId)

# Settings for enabling temp disk encryption only providing Azure managed HSM (mHSM) resource. For more info, see https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview
#$pubsettings                                  = @{};
#$pubSettings.Add("KekVaultResourceId",        "__AZURE_MHSM_RESOURCE_ID_HERE__")
#$pubSettings.Add("KeyEncryptionKeyURL",       "__AZURE_KEK_URL_HERE__")
#$pubsettings.Add("EncryptionManagedIdentity", "__AZURE_USER_ASSIGNED_MANAGED_IDENTITY_RESOURCE_ID_HERE")  # Asign "Managed HSM Crypto User" role on key in local RBAC for SKR. (Either)
#$pubsettings.Add("EncryptionManagedIdentity", "client_id=__CLIENT_ID_OF_MSI_HERE")                        # Asign "Managed HSM Crypto User" role on key in local RBAC for SKR. (Or)
#$pubSettings.Add("VolumeType",                "Data")
#$pubsettings.Add("KeyStoreType",              "ManagedHSM")
#$pubsettings.Add("EncryptionOperation",       $EncryptionOperation)
#$pubSettings.Add("KeyEncryptionAlgorithm",    "RSA-OAEP")

Set-AzVMExtension `
    -ResourceGroupName $resourceGroup `
    -VMName $cvmName `
    -Publisher $Publisher `
    -ExtensionType $ExtName `
    -TypeHandlerVersion $ExtHandlerVer `
    -Name $ExtName `
    -EnableAutomaticUpgrade $false `
    -Settings $pubSettings `
    -Location $location

# Verify: switch to the portal and verify that the extension provision is succeded.
Write-Host "Waiting 2 minutes for extension status update"
Start-Sleep 120
$status = Get-AzVMExtension -ResourceGroupName $resourceGroup -VMName $cvmName -Name $ExtName -Status
$status
$status.SubStatuses

#### End of step 3.

Write-Host "Script ended"