# Platform Guest Attestation App for Windows
Guest attestation is the process of cryptographically appraising a VM’s reported state, ensuring the reported security properties can be trusted and that they meet the requirements of a baseline attestation policy.

### Example scenario

![image](https://user-images.githubusercontent.com/32008026/170385860-03f7f487-c606-4648-8fc1-048968b687f7.png)

![image](https://user-images.githubusercontent.com/32008026/170386018-e9cda749-ade4-471d-a9f0-ef698ce7a9c7.png)


## Build Instructions
 1. Create a Windows Confidential or Trusted Launch virtual machine in Azure and clone the sample application.
 2. Install Visual Studio with the Desktop development with C++ workload installed and running on your computer. If it's not installed yet, follow the steps in  [Install C++ support in Visual Studio](https://docs.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170).
 3. To build your project, choose **Build Solution** from the **Build** menu. The **Output** window shows the results of the build process.
 4. Once the build is successful, to run the application navigate to the `Release` build folder and run the `AttestationClientApp.exe` file.


![image](https://user-images.githubusercontent.com/32008026/170388502-17e56492-8604-400f-ae04-b6548baac22d.png)


## Steps to run sample client
1. Download [sample-client.zip](https://github.com/akashgupta29/attestation-app-windows/blob/main/sample-client.zip) from the repo.
2. Unzip the folder.
3. Navigate inside the folder and run `VC_redist.x64.exe`. This will install Microsoft C and C++ ([MSVC](https://docs.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170)) runtime libraries on the machine.
4. Run the `AttestationClientApp.exe` to trigger the sample client.
