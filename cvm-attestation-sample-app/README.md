# Platform Guest Attestation
Guest attestation is the process of cryptographically appraising a VM’s reported state, ensuring the reported security properties can be trusted and that they meet the requirements of a baseline attestation policy.

### Example scenario

![image](https://user-images.githubusercontent.com/32008026/170385860-03f7f487-c606-4648-8fc1-048968b687f7.png)

![image](https://user-images.githubusercontent.com/32008026/170386018-e9cda749-ade4-471d-a9f0-ef698ce7a9c7.png)


## Build Instructions for Windows
 1. Create a Windows Confidential or Trusted Launch virtual machine in Azure and clone the sample application.
 2. Install Visual Studio with the Desktop development with C++ workload installed and running on your computer. If it's not installed yet, follow the steps in  [Install C++ support in Visual Studio](https://docs.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170).
 3. To build your project, choose **Build Solution** from the **Build** menu. The **Output** window shows the results of the build process.
 4. Once the build is successful, to run the application navigate to the `Release` build folder and run the `AttestationClientApp.exe` file.

![image](https://user-images.githubusercontent.com/32008026/170388502-17e56492-8604-400f-ae04-b6548baac22d.png)


## Build Instructions for Linux

Create a Linux Confidential or Trusted Launch virtual machine in Azure and clone the application.

Use the below command to install the `build-essential` package. This package will install everything required for compiling our sample application written in C++.
```sh
$ sudo apt-get install build-essential
```

Install the below packages
```sh
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install libjsoncpp-dev
$ sudo apt-get install libboost-all-dev
$ sudo apt install nlohmann-json3-dev
```

Download the attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/

Use the below command to install the attestation package
```sh
$ sudo dpkg -i azguestattestation1_1.0.2_amd64.deb
```

Once the above packages have been installed, use the below steps to build and run the app

```sh
$ cd attestation-app-linux/
$ cmake .
$ make
$ sudo ./AttestationClient -o token
```

![image](https://user-images.githubusercontent.com/32008026/170384716-d13876e2-4078-47bd-9994-5ca44318b4d4.png)
