## Steps to run Windows client
1. Download the latest exe for Windows.
2. Unzip the folder.
3. Navigate inside the folder and run `VC_redist.x64.exe`. This will install Microsoft C and C++ ([MSVC](https://docs.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170)) runtime libraries on the machine.
4. Run the `AttestationClientApp.exe -a <attestation-url> -n <nonce-value> -o <token>` to trigger the sample client.
Note: if `-o` is not specified to as `token`, the exe prints a binary result true or false depending on the attestation result and the platform being `sevsnp`.

![image](https://user-images.githubusercontent.com/32008026/191386248-830a3982-1696-40bb-92e5-e8b9d1d3a23b.png)


## Steps to run Linux client
1. Download the latest exe for Linux.
2. Unzip the folder.
3. Use the below commands to install `libcurl4-openssl-dev` and `libjsoncpp-dev` packages:
    ```sh
    $ sudo apt-get install libcurl4-openssl-dev
    $ sudo apt-get install libjsoncpp-dev
    $ sudo apt-get install libboost-all-dev
    $ sudo apt install nlohmann-json3-dev
    ```
4. Download the attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/
   
   Use the below command to install the attestation package:
    ```sh
    $ sudo dpkg -i azguestattestation1_1.0.2_amd64.deb
    ```
5. To run the sample client, navigate inside the unzipped folder and run the below command:
    ```sh
    $ sudo ./AttestationClient -a <attestation-url> -n <nonce-value> -o <token>
    ```
