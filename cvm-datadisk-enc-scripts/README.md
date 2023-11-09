# Sample scripts to enable confidential temp and data disk encryption in Confidential VMs. Currently, confidential temp disk encryption is public preview while confidential data disk encryption is in private preview.

The code in this directory is to demonstrate how to turn on confidential temp and data disk encryption in confidential Azure VMs. Azure powershell modules and resources such as subscription id, resource group, confidential VM, AKV, RSA key, manage identity are required to execute the scenarios.

## Execution instructions

1. Download the files in this directory to your local drive, such as C:\temp\cvm
2. Choose one of the powershell files depending on your choices of OS (Windows or Linux) and action you want to take.

- If you already provisioned the necessary resources, go with CVM-enable-conftempdiskenc-*.ps1
- Otherwise, to create the resources, go with CVM-create-confdatadiskenc-*.ps1

3. Update the place holders in the script file and follow the comments to execute in Powershell ISE or Azure Cloud Shell in portal.
