
# CVM Attestation Sample for AKS

This solution is to be deployed on a CVM node in AKS cluster and will run a CVM attestation client, receive the attestation response and then decode the attestation report. It includes the following files:
1. **attestation-client.Dockerfile**: The docker file to build the container image that runs the attestation app. The sample container image is pushed to MCR: mcr.microsoft.com/acc/samples/cvm-attestation:1.0.
2. **get-attestation-report.sh**: The entry point script runs in the container image that triggers the attestation and then receive and decode the response.
3. **cvm-attestation.yaml**: The yaml file to deploy an AKS pod that runs the attestation client.

## To deploy the AKS pod
1. After getting the AKS credential, run the command:
    ```
    kubectl apply -f cvm-attestation.yaml
    ```

2. Then check the pod status, make sure **cvm-attestation** is in **Completed** status
    ```
    kubectl get pods
    ```
    
3. Get the attestation report by checking logs
    ```
    kubectl logs cvm-attestation
    ```
    Output:
    ```
    {
      "alg": "RS256",
      "jku": "https://sharedeus2.eus2.attest.azure.net/certs",
      "kid": "J0pAPdfXXHqWWimgrH853wMIdh5/fLe1z6uSXYPXCa0=",
      "typ": "JWT"
    }
    {
      "exp": 1663376286,
      "iat": 1663347486,
      "iss": "https://sharedeus2.eus2.attest.azure.net",
      "jti": "89a500344d9ecc081b14ff6c848fbc1d557694946e6f8d83687654a1139e055d",
      "nbf": 1663347486,
      "secureboot": true,
      "x-ms-attestation-type": "azurevm",
      "x-ms-azurevm-attestation-protocol-ver": "2.0",
      "x-ms-azurevm-attested-pcrs": [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7
      ],
      "x-ms-azurevm-bootdebug-enabled": false,
      "x-ms-azurevm-dbvalidated": true,
      "x-ms-azurevm-dbxvalidated": true,
      "x-ms-azurevm-debuggersdisabled": true,
      "x-ms-azurevm-default-securebootkeysvalidated": true,
      "x-ms-azurevm-elam-enabled": false,
      "x-ms-azurevm-flightsigning-enabled": false,
      "x-ms-azurevm-hvci-policy": 0,
      "x-ms-azurevm-hypervisordebug-enabled": false,
      "x-ms-azurevm-is-windows": false,
      "x-ms-azurevm-kerneldebug-enabled": false,
      "x-ms-azurevm-osbuild": "NotApplication",
      "x-ms-azurevm-osdistro": "Ubuntu",
      "x-ms-azurevm-ostype": "Linux",
      "x-ms-azurevm-osversion-major": 18,
      "x-ms-azurevm-osversion-minor": 4,
      "x-ms-azurevm-signingdisabled": true,
      "x-ms-azurevm-testsigning-enabled": false,
      "x-ms-azurevm-vmid": "A80B7FE7-5B93-4027-9971-6CCEE468C2B3",
      "x-ms-isolation-tee": {
        "x-ms-attestation-type": "sevsnpvm",
        "x-ms-compliance-status": "azure-compliant-cvm",
        "x-ms-runtime": {
          "keys": [
            {
              "e": "AQAB",
              "key_ops": [
                "encrypt"
              ],
              "kid": "HCLAkPub",
              "kty": "RSA",
              "n": "2I-ayAABWYhQU-D81quVW4i1sH14-Offul2U2LwsgtihxykIzXY_5YzQAY4e56GMZSpm5r6telRr5rnFJa8iklzol7ecYZEX1nc1WK51a68E2kZNyomFVSIlDPJCn14NpRoxuipIfhe16zWVYZ8dpYbpelyzHZZpskdBLnUKldffUYliWSXLBpjPb89VV0FYxKPi_bSGviBXWOiRtcITRcXfpjlfD3DgZqlK4gj11RChqaEYG_GAPlxceu5h1pusgLuPEULWzvkKuGw7j8ZrxdYEUNB-uHU0nxuQvYxtksPs3zX6ELcV2GjwJupzYUUAu95OQUGI-soDWKvIXM4epw"
            }
          ],
          "vm-configuration": {
            "console-enabled": true,
            "current-time": 1662691445,
            "secure-boot": true,
            "tpm-enabled": true,
            "vmUniqueId": "A80B7FE7-5B93-4027-9971-6CCEE468C2B3"
          }
        },
        "x-ms-sevsnpvm-authorkeydigest": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "x-ms-sevsnpvm-bootloader-svn": 2,
        "x-ms-sevsnpvm-familyId": "01000000000000000000000000000000",
        "x-ms-sevsnpvm-guestsvn": 2,
        "x-ms-sevsnpvm-hostdata": "0000000000000000000000000000000000000000000000000000000000000000",
        "x-ms-sevsnpvm-idkeydigest": "57486a447ec0f1958002a22a06b7673b9fd27d11e1c6527498056054c5fa92d23c50f9de44072760fe2b6fb89740b696",
        "x-ms-sevsnpvm-imageId": "02000000000000000000000000000000",
        "x-ms-sevsnpvm-is-debuggable": false,
        "x-ms-sevsnpvm-launchmeasurement": "ad6de16ac59ee52351c6038df58d1be5aeaf41cd0f7c81b2279ecca0df6ef43a2b69d663ad6973d6dbb9db0ffd7a9023",
        "x-ms-sevsnpvm-microcode-svn": 93,
        "x-ms-sevsnpvm-migration-allowed": false,
        "x-ms-sevsnpvm-reportdata": "d707bdbeeeb6c6e7fa42e94e71ec537e21c8d4c4316422c4011742f55ecc22c00000000000000000000000000000000000000000000000000000000000000000",
        "x-ms-sevsnpvm-reportid": "afc01d4d5f22974bd00c2d993bc3354fcd3bf37c789c2611233da72df1712d82",
        "x-ms-sevsnpvm-smt-allowed": true,
        "x-ms-sevsnpvm-snpfw-svn": 6,
        "x-ms-sevsnpvm-tee-svn": 0,
        "x-ms-sevsnpvm-vmpl": 0
      },
      "x-ms-policy-hash": "wm9mHlvTU82e8UqoOy1Yj1FBRSNkfe99-69IYDq9eWs",
      "x-ms-runtime": {
        "client-payload": {
          "nonce": "MTIzNA=="
        },
        "keys": [
          {
            "e": "AQAB",
            "key_ops": [
              "encrypt"
            ],
            "kid": "TpmEphemeralEncryptionKey",
            "kty": "RSA",
            "n": "peWMfgAALfH53tQC-noqUvYLgycL8K9Ejn7mKKDJwu7hdrrfydinD04burg83WANTGOKO4OHiNieJf4SiGmxZQyLym6gJr4m0bGbsMt4NM6dXXVmRZZSkCp4hn_2XL6aMOnnn0YNOXg6zmRmOeRu4rgkOA_WCd8YE23k7wp0twZG0VCgVmUUr2LD_xwqLLsukoDG8_b38QJmkh78Vz6BGLIA9-qgG5fpBGVoERWe1CCC1aH7bkKhKtNPSD0x6EbfxCfe4dU_Adg6xdxuaDEK9mcfxZWz56cevmlc44SapFm00iSYeWmyoyqlZUJ6mr-1P-DYataNHZPZr8mz2wDAgQ"
          }
        ]
      },
      "x-ms-ver": "1.0"
    }
    ```
    


