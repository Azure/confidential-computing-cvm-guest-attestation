# CVM Recovery Key Retrieval (CMK)

This folder contains helper scripts to retrieve an OS disk recovery key for a non-booting Azure Confidential VM (CVM) protected with a Customer Managed Key (CMK):

- `get_recovery_key_cmk_fromvmmd.ps1` – Extract recovery key from a VMMD (Virtual Machine Metadata) blob snapshot or SAS URL.
- `get_recovery_key_cmk_fromvmgs.ps1` – Extract recovery key from a VMGS (Virtual Machine Guest State) blob snapshot or SAS URL.

## Mitigation Steps to Recover a Non-Booting CVM

1. Locate the OS disk of the non-booting CVM in the Azure portal and create a full snapshot.
2. Export the snapshot and obtain the SAS URLs.
   - Count the exported SAS URLs to determine which script to use:
     - **3 SAS URLs** – Use `get_recovery_key_cmk_fromvmmd.ps1` (extracts from VMMD blob).
     - **2 SAS URLs** – Use `get_recovery_key_cmk_fromvmgs.ps1` (extracts from VMGS blob).
3. Grant **Unwrap** permission on the CMK used for disk encryption.
   - The recovery flow unwraps the disk recovery key using the CMK referenced in `DiskEncryptionSettings.recoverykey_info.key_id`.
   - Identify where the key is stored:
     - Azure Key Vault, or
     - Managed HSM.
   - Grant the identity running the script:
     - Key Vault: `unwrapKey` and `get` permissions on the key.
     - Managed HSM: a key role that includes Unwrap (for example, `Managed HSM Crypto User`) or a custom role with `Microsoft.KeyVault/managedHSM/keys/unwrap/action`.
   - Ensure the identity can obtain an access token for the vault resource:
     - `https://vault.azure.net` for Key Vault
     - `https://managedhsm.azure.net` for Managed HSM
4. Run the script with the VMMD SAS URL to retrieve the BitLocker/disk recovery key.
5. Enable Serial Console for the VM in the Azure portal (if not already enabled).
6. When prompted in Serial Console, paste the recovery key obtained in step 4 and press Enter to resume boot.

## Prerequisites

- PowerShell 5.1+ or PowerShell 7+ or Azure CLI in portal
- Az PowerShell module with an authenticated Azure context
  - Script uses `Get-AzContext` and `Get-AzAccessToken`
- Network access to the SAS URL and Key Vault/Managed HSM endpoint

## Script Usage

### Using `get_recovery_key_cmk_fromvmmd.ps1` (for 3 exported SAS URLs)

#### Option A: VMMD SAS URL

```powershell
pwsh ./get_recovery_key_cmk_fromvmmd.ps1 -vmmdSas "<VMMD_SAS_URL>"
```

#### Option B: Local VMMD.RECOVERYKEYDATA file

```powershell
pwsh ./get_recovery_key_cmk_fromvmmd.ps1 -vmmdRecoveryKeyDataPath "C:\path\to\VMMD.RECOVERYKEYDATA"
```

### Using `get_recovery_key_cmk_fromvmgs.ps1` (for 2 exported SAS URLs)

#### VMGS SAS URL

```powershell
pwsh ./get_recovery_key_cmk_fromvmgs.ps1 -vmgsSas "<VMGS_SAS_URL>"
```

## Expected Output

- For Windows disks:
  - `Windows recovery key is : <key>`
- For Linux disks:
  - `Linux recovery key in base64 format is: <base64>`
  - `Linux recovery key is : <formatted-key>`

## Troubleshooting

- `RecoveryKeyInfo does not exist`
  - The VMMD content does not contain `DiskEncryptionSettings.recoverykey_info`.
- `Unknown resouce authority ...`
  - The key URI is not recognized as Key Vault or Managed HSM in the current Azure environment.
- `Azure access token not available.`
  - Sign in and set the correct subscription/context (for example, `Connect-AzAccount` and `Set-AzContext`).
- Unwrap request fails with authorization errors
  - Verify key permissions/role assignments for the identity running the script.
