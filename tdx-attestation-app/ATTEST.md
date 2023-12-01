# Important Notice as of 10/17
Support for in-guest attestation is only available using the Azure in-guest app. You can leverage this to attest with Intel Trust Authority. Intel in-guest application is under development and will be released in the coming weeks.

## **Performing Remote Attestation**

* [Microsoft Azure in-guest app](#azure-in-guestapp)
* [Intel Trust Authority in-guest app](#ita-in-guestapp)
## <a id='azure-in-guestapp'></a> Azure in-guest app
### Before you start: 
1. You have successfully deployed your VM in Azure with Ubuntu.
2. Install and build sample application
-------------------------------------------------

### Install and Build the Attestation Application

1. Clone the Repository
``` bash
git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation.git
```

2. Navigate to directory
```
cd confidential-computing-cvm-guest-attestation
```

3. Check preview branch
``` bash
git checkout tdx-preview
```

4. Navigate to Application Folder
```
cd tdx-attestation-app
```

5. Install Dependencies
- Ubuntu
```bash
sudo ./install.sh
```

6. Configure and Build
```sh
cmake .
make
```
7. To attest with MAA run the application with the following command:
```sh
sudo ./TdxAttest -c maa_config.json
```
9. To attest with Intel Trust Authority sign up to retrieve an API Key for [Intel Trust Authority](https://github.com/Azure/azure-compute-tdx-preview/blob/main/ITA.md)

10. Once you have the API Key, modify the `config.json`

11. Run the application using the following command:
```sh
sudo ./TdxAttest -c config.json
```

-------------------------------------------------

### Understanding the Config Definition
``` json
{
  "attestation_url": "attestation endpoint to validate the hardware evidence",
  "attestation_provider": "attestation provider (allowed values: 'Intel Trust Authority' or 'maa')",
  "api_key": "the api key if needed; this is required for Intel Trust Authority",
  "enable_metrics": "set to true to enable measurements for each request",
  "output_filename": "store the hardware evidence (Td Quote) into a file"
}
```
> **NOTE:** User claims are not supported at the moment.

### Sample of Config Definition
``` json
{
  "attestation_url": "https://api.projectIntel Trust Authority.intel.com/appraisal/v1/attest",
  "attestation_provider": "Intel Trust Authority",
  "api_key": "<add API KEY here>",
  "enable_metrics": true
}
```

### **Enable_metrics**
If metrics are enabled, new `metrics.json` file will be created, as well as a summary will be printed in the console:

``` bash
...
Run Summary:
        Evidence Request(ms): 27.899809
        Attestation Request(ms): 2172.986599
```

`metrics.json` Example:
``` json
{
    "Attestation Request(ms)": "2172.879354",
    "Evidence Request(ms)": "71.515078"
}
```

## <a id='ita-in-guestapp'></a> Intel Trust Authority in-guest app
### Before you start
1. You have successfully deployed your VM in Azure with Ubuntu.
2. Install go1.19 or newer. For Ubuntu 22.04 LTS,
``` bash
sudo snap install go --classic
```
3. Install tpm2-tools package
``` bash
sudo apt install tpm2-tools
```

### Build the Intel Trust Authority tdx-cli
1. Clone the Repository
``` bash
git clone https://github.com/intel/trustauthority-client -b azure-tdx-preview
```

2. Navigate to directory
``` bash
cd trustauthority-client/tdx-cli
```

3. Build the Intel Trust Authority-cli
``` bash
make cli
```
### Run the Intel Trust Authority-cli
1. Sign up to retrieve an API Key for [Intel Trust Authority](https://github.com/Azure/azure-compute-tdx-preview/blob/main/ITA.md)

2. Once you have the API Key, create a config.json like below:
```json
{
    "trustauthority_url": "https://portal.trustauthority.intel.com",
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
3. Run the cli tool using the following command:
```bash
sudo ./trustauthority-cli token --config config.json --user-data <base64 encoded userdata>  --no-eventlog
```

**Note:** the user-data is base64 standard encoded. It could be any format (binary, JSON object) that client or relying party can understand. The hash(SHA512) of the user-data will be included in the <b>attester_runtime_data.user-data</b> claim in the attesation token released by Intel Trust Authority. Some online tool like https://base64.guru/converter/encode/text can be used to encode the data to base64 standard format.