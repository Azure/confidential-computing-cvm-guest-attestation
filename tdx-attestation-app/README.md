# Hardware Attestation

## Build Instructions for Linux

Create a Linux Tursted Domain virtual machine in Azure and clone the application.

Use the below command to install all the dependencies necessary to run this sample app.
```sh
$ sudo ./install.sh
```

Once the above install script is done, use the below steps to build and run the app

```sh
cmake .
```
```sh
make
```
```sh
sudo ./TdxAttest -c config.json
```

> **Important**
>
> Running without `sudo` should work and if there is an error while opening the driver, add the driver
> to the user group with the following command:
>
> ```
> sudo chmod og=rw /dev/tdx_guest
> ```

## Config Definition
```
{
  "attestation_url": "<attestation endpoint to validate the hardware evidence>",
  "attestation_provider": "<attestation provider (allowed values: amber or maa)>",
  "api_key": "<the api key if needed | this is required for Amber>",
  "enable_metrics": set to true to enable measurements for each request,
  "output_filename": "<store the hardware evidence (Td Quote) into a file>",
  "claims": <a well formed json object for generating the hardware evidence>
}
```

## enable_metrics
If metrics are enabled, new `metrics.json` file will be created, as well as a summary:
```
...
Run Summary:
        Evidence Request(ms): 27.899809
        Attestation Request(ms): 2172.986599
```

`metrics.json` Example:
```
{
    "Attestation Request(ms)": "2172.879354",
    "Evidence Request(ms)": "71.515078"
}
```