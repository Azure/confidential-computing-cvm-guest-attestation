#
# This script can be used to create an Azure Linux confidential VM and turn data disk encryption (DDE) feature on.
# Usage: Open this script file in "Windows PowerShell ISE", or use CloudShell in Azure portal. Review and update each "Step". Afterwards, highlight the section and hit F8 to run in ISE or copy and paste into cloud shell.
#
# Requirements: 1-) The confidential VM is already created with confidential OS disk encrtyption on
#               2-) One or more data disks are attached and partitioned. The volumes are formatted as ext4 or xfs.
#               3-) A Customer Managed Key (RSA 3072 bits) is created in AKV or mHSM with the modified SKR policy.
#               4-) A user assigned managed identity (UAI) is created and granted Get,Release permissions on the RSA key.
#


#### Step 0: Make sure your Azure powershell modules are up-to-date.

if ((Get-Module Az.Compute).Version.Major -lt 6)
{
    Update-Module -Name Az* -Force   # Requires elevated (admin) Powershell window
}

#### End of step 0



#### Step 1 - Set the global parameters which will be used throughout the script.

$subscriptionId    = "__SUB_ID_HERE__"                                          # User must have at least contributor access.
$inCloudShell      = if ($env:AZD_IN_CLOUDSHELL) { $true } else { $false }      # Determine if running in CloudShell.
$user              = if ($inCloudShell) { $env:LOGNAME } else { $env:USERNAME } # in CloudShell, it is LOGNAME.
$suffix            = [System.Guid]::NewGuid().ToString().Substring(0,8)         # Suffix to append to resources.
$resourceGroup     = "$user-lnx-dde-$suffix"                                    # The RG will be created
$location          = "West US"                                                  # "West US", "East US", "North Europe", "West Europe", "Italy North" etc. For complete list, see https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview#regions
$kvName            = "$user-akv-$suffix"                                        # AKV will be created.
$rsaKeyName        = "$user-dde-key1"                                           # RSA key will be created
# The SKR policy is slightly modified version for DDE. Copy it to your cloud shell or local drive and update path.
$skrPolicyFile     = if ($inCloudShell) { "public_SKR_policy-datadisk.json" } else { "C:\Temp\cvm\public_SKR_policy-datadisk.json" }
$uaManagedIdentity = "$user-ade-uai"                                            # User assigned identity will be created.


# CVM settings
$infix             = [System.Guid]::NewGuid().ToString().Substring(0,4)
$cvmName           = "cvm-$infix-w22"                                           # CVM name must be <= 15 chars.
$Offer             = "0001-com-ubuntu-confidential-vm-jammy"
$SKU               = "22_04-lts-cvm"
#$cvmName          = "$user-cvm-u20".Substring(0, 14)                           # CVM name must be <= 15 chars.
#$Offer            = "0001-com-ubuntu-confidential-vm-focal"                    # You can choose Ubuntu {20.04, 22.04}
#$SKU              = "20_04-lts-cvm"
$VMSize            = "Standard_DC2ads_v5"
$PublisherName     = "Canonical"
$securityType      = "ConfidentialVM"
$vnetname          = "myVnet"
$vnetAddress       = "10.0.0.0/16"
$subnetname        = "slb" + $resourceGroup
$subnetAddress     = "10.0.2.0/24"
$NICName           = $cvmName+ "-nic"
$PublicIPName      = $cvmName+ "-ip"
$secureboot        = $true
$vtpm              = $true

# Linux SSH credentials.
$dummyPass = [System.Guid]::NewGuid().ToString() | ConvertTo-SecureString -AsPlainText -Force  # Linux does not use passwd
$cred = New-Object System.Management.Automation.PSCredential ($user, $dummyPass)
# Replace below with your ssh pub key. This is in the format of ssh-rsa AAAAB3NzaC1y..... For more info: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/ssh-from-windows
$sshPubKeyRSA = "ssh-rsa __SSH_RSA_PUB_KEY_HERE__"

#### End of step 1



#### Step 2 - Login to Azure and create the resource group

Login-AzAccount -Subscription $subscriptionId
Select-AzSubscription -SubscriptionId $subscriptionId
New-AzResourceGroup -Name $resourceGroup -Location $location

#### End of step 2



#### Step 3 - Create a premium Azure Key Vault (or managed HSM, see online docs)

New-AzKeyVault -VaultName $kvName -ResourceGroupName $resourceGroup -Location $location -Sku Premium -EnablePurgeProtection
if ($inCloudShell) {
    Set-AzKeyVaultAccessPolicy -VaultName $kvName -ResourceGroupName $resourceGroup -PermissionsToKeys all -UserPrincipalName $env:ACC_OID
}

$keyvault = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $resourceGroup
Add-AzKeyVaultKey -VaultName $kvName -Name $rsaKeyName -Destination HSM -KeyType RSA -Size 3072 -KeyOps wrapKey,unwrapKey -Exportable -ReleasePolicyPath $skrPolicyFile
$rsaKey = Get-AzKeyVaultKey -VaultName $kvName -Name $rsaKeyName

#### End of step 3.



#### Step 4 - Create user assigned managed identity.

New-AzUserAssignedIdentity -Name $uaManagedIdentity -ResourceGroupName $resourceGroup -Location $location
$userAssignedMI = Get-AzUserAssignedIdentity -Name $uaManagedIdentity -ResourceGroupName $resourceGroup

# Wait for a few seconds for the MI to be available. If NotFound is returned, re-run the command.
Start-Sleep 30
# Assign Get,Release permissions on the CMK to the User assigned MI.
Set-AzKeyVaultAccessPolicy -VaultName $kvName -ResourceGroupName $resourceGroup -ObjectId $userAssignedMI.PrincipalId -PermissionsToKeys get,release

#### End of step 4.


#### Step 5 - Create a CVM and assign the Managed identity: This step takes ~5 mins, good time for a coffee break :-)

# Network resources
$frontendSubnet = New-AzVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetAddress
$vnet = New-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resourceGroup -Location $location -AddressPrefix $vnetAddress -Subnet $frontendSubnet -Force
$publicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $resourceGroup -AllocationMethod Static -DomainNameLabel $cvmName -Location $location -Sku Standard -Tier Regional -Force
$nic = New-AzNetworkInterface -Name $NICName -ResourceGroupName $resourceGroup -Location $location -SubnetId $vnet.Subnets[0].Id -EnableAcceleratedNetworking -Force -PublicIpAddressId $publicIP.Id

# VM creation
$vmConfig = New-AzVMConfig -VMName $cvmName -VMSize $VMSize
Set-AzVMOperatingSystem -VM $vmConfig -Linux -ComputerName $cvmName -Credential $cred

Add-AzVmSshPublicKey -VM $vmConfig -KeyData $sshPubKeyRSA -Path "/home/$user/.ssh/authorized_keys"

Set-AzVMSourceImage -VM $vmConfig -PublisherName $PublisherName -Offer $Offer -Skus $SKU -Version latest
Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
$vmConfig = Set-AzVMSecurityProfile -VM $vmConfig -SecurityType $securityType
$vmConfig = Set-AzVMUefi -VM $vmConfig -EnableVtpm $vtpm -EnableSecureBoot $secureboot

# SSE with PMK and CVM with CMK. Create a DES for OS Disk
$rsaKeyNameForOS = "$user-os-key1"
$desName = "$user-os-des1"
Add-AzKeyVaultKey -VaultName $kvName -Name $rsaKeyNameForOS -Destination HSM -KeyType RSA -Size 3072 -KeyOps wrapKey,unwrapKey -Exportable -UseDefaultCVMPolicy
$rsaKeyForOS = Get-AzKeyVaultKey -VaultName $kvName -Name $rsaKeyNameForOS
$desConfig = New-AzDiskEncryptionSetConfig -Location $location -KeyUrl $rsaKeyForOS.id -SourceVaultId $keyvault.ResourceId -IdentityType SystemAssigned -EncryptionType ConfidentialVmEncryptedWithCustomerKey 
$desConfig | New-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resourceGroup
$des = Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resourceGroup

# Wait for a few seconds for the MI to be available. If NotFound is returned, re-run the command.
Start-Sleep 30
# Assign wrapKey,UnwrapKey for CPS to work with CMK. (Get and Release are sufficient for DDE)
Set-AzKeyVaultAccessPolicy -VaultName $kvName -ResourceGroupName $resourceGroup -ObjectId $des.Identity.PrincipalId -PermissionsToKeys get,wrapKey,unwrapKey

# Grant get, release permissions to Confidential Guest VM Agent.
$cvmAgent = Get-AzADServicePrincipal -DisplayName "Confidential Guest VM Agent"
Set-AzKeyVaultAccessPolicy -VaultName $kvName -ResourceGroupName $resourceGroup -ObjectId $cvmAgent.Id -PermissionsToKeys Get,Release

# Create the confidential VM.
$vmConfig = Set-AzVMOSDisk -VM $vmConfig -CreateOption FromImage -SecurityEncryptionType DiskWithVMGuestState -SecureVMDiskEncryptionSet $des.Id
New-AzVM -ResourceGroupName $resourceGroup -Location $location -VM $vmConfig

# Add an empty datadisk of size 128GB
$vm = Get-AzVM -Name $cvmName -ResourceGroupName $resourceGroup
$dataDiskName = $cvmName+"-datadisk1"
$vm = Add-AzVMDataDisk -VM $vm -Name $dataDiskName -CreateOption Empty -Lun 2 -DiskSizeInGB 128 -Caching ReadOnly -DeleteOption Delete
Update-AzVM -VM $vm -ResourceGroupName $resourceGroup

# Assign the Managed Identity to the CVM
$vm = Get-AzVM -Name $cvmName -ResourceGroupName $resourceGroup
Update-AzVM -VM $vm -ResourceGroupName $resourceGroup -IdentityType UserAssigned -IdentityId $userAssignedMI.Id

# SSH to the VM and partition the data disk, run these commands in bash. These commands are to be executed manually. (or customer can run a CustomScriptExtension)
$ipAddress = $publicIP.IpAddress
Write-Host "ssh -P 22 -i /path/to/priv.key $user@$ipAddress"
Write-Host "Enter password for your priv.key"
Write-Host "sudo su -"
Write-Host "lsblk (to locate the disk device: assuming it is /dev/sdX"
Write-Host "fdisk /dev/sdX"
Write-Host "n"
Write-Host "p"
Write-Host "1"
Write-Host "<Enter>"
Write-Host "+16G"
Write-Host "w <enter>"
Write-Host "lsblk"
Write-Host "mkfs.ext4 /dev/sdX1"
Write-Host "mkdir /datadisk1"
Write-Host "blkid /dev/sdX1 (take the UUID)"
Write-Host "vim /etc/fstab (or your favorited editor: pico, nano etc)"
Write-Host "UUID=<from blkid> /datadisk1 ext4 defaults,discard 0 1"
Write-Host ":wq"
Write-Host "mount -a"
Write-Host "lsblk"
Write-Host "Observe the volume is mounted on /datadisk1"

#### End of step 5.



#### Step 6 - Install ADE with public settings defined below to enable temp and data disk encryption.

# ADE settings:
$KV_URL                      = $keyvault.VaultUri
$KV_RID                      = $keyvault.ResourceId
$KEK_URL                     = $rsaKey.Id
$EncryptionManagedIdentity   = "EncryptionManagedIdentity";
$KV_UAI_RID = $userAssignedMI.Id

$Publisher                   = "Microsoft.Azure.Security"
$ExtName                     = "AzureDiskEncryptionForLinux"
$ExtHandlerVer               = "1.4"
$EncryptionOperation         = "EnableEncryption"
$PrivatePreviewFlag_TempDisk = "PrivatePreview.ConfidentialEncryptionTempDisk" # After public preview, this will be renamed to NoConfidentialEncryptionTempDisk and defaults to false; so temp disk enc is on by default.
$PrivatePreviewFlag_DataDisk = "PrivatePreview.ConfidentialEncryptionDataDisk"

# Settings for Azure Key Vault (AKV)
$pubSettings = @{};
$pubSettings.Add("KeyVaultURL", $KV_URL)
$pubSettings.Add("KeyVaultResourceId", $KV_RID)
$pubSettings.Add("KeyEncryptionKeyURL", $KEK_URL)
$pubSettings.Add("KekVaultResourceId", $KV_RID)
$pubSettings.Add("KeyEncryptionAlgorithm", "RSA-OAEP")
$pubSettings.Add($EncryptionManagedIdentity, $KV_UAI_RID)       # this could also be client_id=<GUID1> or object_id=<GUID2>
$pubSettings.Add("VolumeType", "Data")
$pubSettings.Add($PrivatePreviewFlag_TempDisk, "true")
$pubSettings.Add($PrivatePreviewFlag_DataDisk, "true")
$pubSettings.Add("EncryptionOperation", $EncryptionOperation)
$pubSettings.Add("EncryptFormatAll", "true") # This formats the data drives for faster encryption. Be warned!!

# Settings for Azure managed HSM (mHSM). For more info, see https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview
# $pubSettings = @{};
# $pubSettings.Add("KeyEncryptionKeyURL", $MHSM_KEK_URL)
# $pubSettings.Add("KekVaultResourceId", $MHSM_RID)
# $pubSettings.Add($EncryptionManagedIdentity, $KV_UAI_RID)
# $pubSettings.Add("VolumeType", "Data")
# $pubSettings.Add("KeyStoreType", "ManagedHSM")
# $pubSettings.Add("EncryptionOperation", $EncryptionOperation)

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

# Verify that the extension provision has succeded.
$status = Get-AzVMExtension -ResourceGroupName $resourceGroup -VMName $cvmName -Name $ExtName
$status
$status.SubStatuses

# Verify lsblk output. Similar to:
#sdb                                                        8:16   0   75G  0 disk
#└─sdb1                                                     8:17   0   75G  0 part
#  └─resourceencrypt                                      253:1    0   75G  0 crypt /mnt
#sdc                                                        8:32   0  128G  0 disk
#└─sdc1                                                     8:33   0 14.9G  0 part
#  └─aad07665-960c-4ddc-8b94-846076ab7bdc                 253:2    0 14.9G  0 crypt /datadisk1


# Verify in diskmgmt.msc that existing temp and data volumes got encrypted.
# Create additional volumes and and observe they get encrypted.


#### End of step 6.



#### Step 7 - Cleanup. Remove the extension or the resource group forall resources.

# Remove VM extensionto to repeat install.
# Remove-AzVMExtension -ResourceGroupName $resourceGroup -VMName $cvmName -Name $ExtName

Remove-AzResourceGroup $resourceGroup

#### End of step 7.