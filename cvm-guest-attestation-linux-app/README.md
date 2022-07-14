# Platform Guest Attestation App for Linux
Guest attestation is the process of cryptographically appraising a VM’s reported state, ensuring the reported security properties can be trusted and that they meet the requirements of a baseline attestation policy.

### Example scenario

![image](https://user-images.githubusercontent.com/32008026/170385860-03f7f487-c606-4648-8fc1-048968b687f7.png)

![image](https://user-images.githubusercontent.com/32008026/170386018-e9cda749-ade4-471d-a9f0-ef698ce7a9c7.png)


## Build Instructions

Create a Linux Confidential or Trusted Launch virtual machine in Azure and clone the application.

Use the below command to install the `build-essential` package. This package will install everything required for compiling our sample application written in C++.
```sh
$ sudo apt-get install build-essential
```

Use the below commands to install `libcurl4-openssl-dev` and `libjsoncpp-dev` packages
```sh
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install libjsoncpp-dev
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
$ sudo ./AttestationClient
```

![image](https://user-images.githubusercontent.com/32008026/170384716-d13876e2-4078-47bd-9994-5ca44318b4d4.png)

## Steps to run sample client
1. Download [sample-client.zip](https://github.com/akashgupta29/attestation-app-linux/blob/main/sample-client.zip) from the repo.
2. Unzip the folder.
3. Use the below commands to install `libcurl4-openssl-dev` and `libjsoncpp-dev` packages:
    ```sh
    $ sudo apt-get install libcurl4-openssl-dev
    $ sudo apt-get install libjsoncpp-dev
      ```
4. Download the attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/
   
   Use the below command to install the attestation package:
    ```sh
    $ sudo dpkg -i azguestattestation1_1.0.2_amd64.deb
    ```
5. To run the sample client, navigate inside the unzipped folder and run the below command:
    ```sh
    $ sudo ./AttestationClient
    ```

