# Sample scripts to enable temp and data disk encryption in Confidential VMs

The code in this directory is to demonstrate how to turn on temp and data disk encryption in confidential Azure VMs. Azure powershell modules and resources such as subscription id, resource group, confidential VM, AKV, RSA key, manage identity are required to execute the scenarios.

## Execution instructions

1. Download the files in this directory to your local drive, such as C:\temp\cvm
2. Choose one of the powershell files depending on your choices of OS (Windows or Linux)

- If you already provisioned the necessary resources, go with CVM-enable-datadiskenc-*.ps1
- Otherwise, to create the resources, go with CVM-create-datadiskenc-*.ps1

3. Update the place holders in the script file and follow the comments to execute in Powershell ISE.
