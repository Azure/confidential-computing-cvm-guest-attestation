
# CVM Attestation Sample for AKS

This solution is to be deployed on a CVM node in AKS cluster and will run a CVM attestation client and then decode the attestation report. It provides the following files:
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
    Initiating Guest Attestation
    Level: Info Tag: AttestatationClientLib ParseURL:519:Attestation URL info - protocol {https}, domain {sharedwus.wus.attest.azure.net}
    Level: Info Tag: AttestatationClientLib Attest:99:Attestation URL - https://sharedwus.wus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01
    Level: Info Tag: AttestatationClientLib GetOSInfo:600:Retrieving OS Info
    Level: Info Tag: AttestatationClientLib GetIsolationInfo:670:Retrieving Isolation Info
    Level: Debug Tag: AttestatationClientLib GetVCekCert:63:VCek cert received from IMDS successfully
    Level: Info Tag: AttestatationClientLib DecryptMaaToken:369:Successfully Decrypted inner key
    Level: Info Tag: AttestatationClientLib Attest:164:Successfully attested and decrypted response.
    eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkd3VzLnd1cy5hdHRlc3QuYXp1cmUubmV0L2NlcnRzIiwia2lkIjoiWHhSYzJ2TGgxRTVGcnNOYXduUkgzUHp1RmdxZzNxN052Q2Ruam9KSEJHRT0iLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NjI2MTM0ODcsImlhdCI6MTY2MjU4NDY4NywiaXNzIjoiaHR0cHM6Ly9zaGFyZWR3dXMud3VzLmF0dGVzdC5henVyZS5uZXQiLCJqdGkiOiJhMjQxY2FjMTlhYWUyMDRlZjUyZTM5YzJkNmI1ZDJjNzBlMWUyYzFhZWFjNGFkOWJmODZhYTE3ODEyNjdhZGM0IiwibmJmIjoxNjYyNTg0Njg3LCJzZWN1cmVib290Ijp0cnVlLCJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJhenVyZXZtIiwieC1tcy1henVyZXZtLWF0dGVzdGF0aW9uLXByb3RvY29sLXZlciI6IjIuMCIsIngtbXMtYXp1cmV2bS1hdHRlc3RlZC1wY3JzIjpbMCwxLDIsMyw0LDUsNiw3XSwieC1tcy1henVyZXZtLWJvb3RkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWRidmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGJ4dmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGVidWdnZXJzZGlzYWJsZWQiOnRydWUsIngtbXMtYXp1cmV2bS1kZWZhdWx0LXNlY3VyZWJvb3RrZXlzdmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZWxhbS1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWZsaWdodHNpZ25pbmctZW5hYmxlZCI6ZmFsc2UsIngtbXMtYXp1cmV2bS1odmNpLXBvbGljeSI6MCwieC1tcy1henVyZXZtLWh5cGVydmlzb3JkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWlzLXdpbmRvd3MiOmZhbHNlLCJ4LW1zLWF6dXJldm0ta2VybmVsZGVidWctZW5hYmxlZCI6ZmFsc2UsIngtbXMtYXp1cmV2bS1vc2J1aWxkIjoiTm90QXBwbGljYXRpb24iLCJ4LW1zLWF6dXJldm0tb3NkaXN0cm8iOiJVYnVudHUiLCJ4LW1zLWF6dXJldm0tb3N0eXBlIjoiTGludXgiLCJ4LW1zLWF6dXJldm0tb3N2ZXJzaW9uLW1ham9yIjoxOCwieC1tcy1henVyZXZtLW9zdmVyc2lvbi1taW5vciI6NCwieC1tcy1henVyZXZtLXNpZ25pbmdkaXNhYmxlZCI6dHJ1ZSwieC1tcy1henVyZXZtLXRlc3RzaWduaW5nLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tdm1pZCI6IkQzRkQ0QjA5LTM3QTMtNDBENS04RjJBLUVBODA3NjIyMTNDQyIsIngtbXMtaXNvbGF0aW9uLXRlZSI6eyJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJzZXZzbnB2bSIsIngtbXMtY29tcGxpYW5jZS1zdGF0dXMiOiJhenVyZS1jb21wbGlhbnQtY3ZtIiwieC1tcy1ydW50aW1lIjp7ImtleXMiOlt7ImUiOiJBUUFCIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImtpZCI6IkhDTEFrUHViIiwia3R5IjoiUlNBIiwibiI6InkyZ0JmUUFCaG5hUkt3VFM3WGZVNGZ5U2VOYXNRa2xjTmZBZF9pQ0hvOXY4MzZUWVFlemFpMWtILXpQc3JzNDRBMm1JS1BLS3NKYXQzN1dUdG1aamVYTzdLNGhvVkZVUEJQZHNOc0t5bk9pbFIwcXVTNmJLaDh5ZWVTRkgwLXVsbmhNRW5EVGZLZ0VMSV80TjZqZDZxV0F0Ul9wZThiZVRhYWhoankwR1FaX1NXY2phOTVFODU2eEhqZlhGVXY1ZnRKWXV0V2k4QXktT2RaRDV0RFpEYjY0b0djVXZQRncyb2NfdGhZYnpkYUt1T2JJVnhkdUpUOEZiVFNIdHR6UnZiRURMUkNxN1FURXZPdWtnb2REU0NDNl9RWHRORzdMMlBhUFQwbHhRNWdqVFBiVHNzM1FQUXBoS3VmVk1DWkFyM0NUQWpPNHo4N1JqMDNnZ2N6bUVLUSJ9XSwidm0tY29uZmlndXJhdGlvbiI6eyJjb25zb2xlLWVuYWJsZWQiOnRydWUsImN1cnJlbnQtdGltZSI6MTY2MjU4NDY4NCwic2VjdXJlLWJvb3QiOnRydWUsInRwbS1lbmFibGVkIjp0cnVlLCJ2bVVuaXF1ZUlkIjoiRDNGRDRCMDktMzdBMy00MEQ1LThGMkEtRUE4MDc2MjIxM0NDIn19LCJ4LW1zLXNldnNucHZtLWF1dGhvcmtleWRpZ2VzdCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tYm9vdGxvYWRlci1zdm4iOjIsIngtbXMtc2V2c25wdm0tZmFtaWx5SWQiOiIwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tZ3Vlc3Rzdm4iOjIsIngtbXMtc2V2c25wdm0taG9zdGRhdGEiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pZGtleWRpZ2VzdCI6IjU3NDg2YTQ0N2VjMGYxOTU4MDAyYTIyYTA2Yjc2NzNiOWZkMjdkMTFlMWM2NTI3NDk4MDU2MDU0YzVmYTkyZDIzYzUwZjlkZTQ0MDcyNzYwZmUyYjZmYjg5NzQwYjY5NiIsIngtbXMtc2V2c25wdm0taW1hZ2VJZCI6IjAyMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pcy1kZWJ1Z2dhYmxlIjpmYWxzZSwieC1tcy1zZXZzbnB2bS1sYXVuY2htZWFzdXJlbWVudCI6ImFkNmRlMTZhYzU5ZWU1MjM1MWM2MDM4ZGY1OGQxYmU1YWVhZjQxY2QwZjdjODFiMjI3OWVjY2EwZGY2ZWY0M2EyYjY5ZDY2M2FkNjk3M2Q2ZGJiOWRiMGZmZDdhOTAyMyIsIngtbXMtc2V2c25wdm0tbWljcm9jb2RlLXN2biI6OTMsIngtbXMtc2V2c25wdm0tbWlncmF0aW9uLWFsbG93ZWQiOmZhbHNlLCJ4LW1zLXNldnNucHZtLXJlcG9ydGRhdGEiOiIwOTU4MjMyM2FlN2VkYWEzMWZlNzZiNDk2NWIyMWQ0Yzk4MmUxZTFhM2I3M2M1YjQ2YTlhNTkwYjM4Y2U3YzAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tcmVwb3J0aWQiOiI0YmVjMDE3NmJiYzgwYjgwMjY3M2VlZTMyNWIzMjk4OWFmNmEyMzJiY2UyZDQxYmE1NDU0OWE5ODRkMDQ0MjU4IiwieC1tcy1zZXZzbnB2bS1zbXQtYWxsb3dlZCI6dHJ1ZSwieC1tcy1zZXZzbnB2bS1zbnBmdy1zdm4iOjYsIngtbXMtc2V2c25wdm0tdGVlLXN2biI6MCwieC1tcy1zZXZzbnB2bS12bXBsIjowfSwieC1tcy1wb2xpY3ktaGFzaCI6IndtOW1IbHZUVTgyZThVcW9PeTFZajFGQlJTTmtmZTk5LTY5SVlEcTllV3MiLCJ4LW1zLXJ1bnRpbWUiOnsiY2xpZW50LXBheWxvYWQiOnsibm9uY2UiOiJNVEl6TkE9PSJ9LCJrZXlzIjpbeyJlIjoiQVFBQiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJraWQiOiJUcG1FcGhlbWVyYWxFbmNyeXB0aW9uS2V5Iiwia3R5IjoiUlNBIiwibiI6Im9jVEZZQUFBdFB1NGw3NGZhZk81d19PTTZBVWo0OTdvOUFzeWM2ZXFJMVdlWEpGdEU4R3lCZXdKMUNSbUx5ME5LNmxQNEl6QmRDWEVZdEdpRmlNY3BqYzZmRTd2TEFDOWhDTXBmU0JyRk1QbXh3WmJaYzRSeDRKZFpJSXRsa2xtTmVqcW5PeWxCdDNyZzh1VnQ1UG1pTWxLMWtocnpPRzNVVmJ2bzRHT0F2UFhhcllRcHdBc2xsUTM4TENlQ2NOa2YxWm5xbERJN2pkYlAzV0xaMll3OVNQZUs2cV9JMVB1TW1jM3pTUlpuSDFJR3M5OURJb2NZRDZCNElWOWx6S3ZvdXFyN2Jqd25Wb2hSQkdNSXZDZlQ2U0ZmRnViVVNRLTcxYmRrcTlUQlBYLThVMjZaSlhyaHZsZEtSN2UwaV9DLTIxSDRlODRLaHpoZFlsV0ZhTGszdyJ9XX0sIngtbXMtdmVyIjoiMS4wIn0.ueLM8zD7mfLzng23ArHMqd-ycZgxpINMRaKfZ_QI2KQ7W5ugfccZ1xvU2yNkjW38JdvC-CIWoifAeoDpAU7Yha306g8-KBcNY5HewO-Z8qUPvBk0DJxqKkwNvEtvmv7bcStRi-rZC_EAmsU32s1E2yb-UyEsH-6tBjnLqBrvqYrv0QgXK5imhwQnOSJCpAoG3nkgdNJY4gj5TsaBV5L48IvcnaHpCkjk6Vy6REiAHstcRypEr5WgEBzL_qPvFIsYoP6zWHe2ZzOnHWYFixuqS-OxbXcJwobyJASvKZh0s5ySPIp2y0AVaSsKMr1hK36JdVhSTsrpjpziHZDhaM0kMQ
    {
      "alg": "RS256",
      "jku": "https://sharedwus.wus.attest.azure.net/certs",
      "kid": "XxRc2vLh1E5FrsNawnRH3PzuFgqg3q7NvCdnjoJHBGE=",
      "typ": "JWT"
    }
    {
      "exp": 1662613487,
      "iat": 1662584687,
      "iss": "https://sharedwus.wus.attest.azure.net",
      "jti": "a241cac19aae204ef52e39c2d6b5d2c70e1e2c1aeac4ad9bf86aa1781267adc4",
      "nbf": 1662584687,
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
      "x-ms-azurevm-vmid": "D3FD4B09-37A3-40D5-8F2A-EA80762213CC",
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
              "n": "y2gBfQABhnaRKwTS7XfU4fySeNasQklcNfAd_iCHo9v836TYQezai1kH-zPsrs44A2mIKPKKsJat37WTtmZjeXO7K4hoVFUPBPdsNsKynOilR0quS6bKh8yeeSFH0-ulnhMEnDTfKgELI_4N6jd6qWAtR_pe8beTaahhjy0GQZ_SWcja95E856xHjfXFUv5ftJYutWi8Ay-OdZD5tDZDb64oGcUvPFw2oc_thYbzdaKuObIVxduJT8FbTSHttzRvbEDLRCq7QTEvOukgodDSCC6_QXtNG7L2PaPT0lxQ5gjTPbTss3QPQphKufVMCZAr3CTAjO4z87Rj03ggczmEKQ"
            }
          ],
          "vm-configuration": {
            "console-enabled": true,
            "current-time": 1662584684,
            "secure-boot": true,
            "tpm-enabled": true,
            "vmUniqueId": "D3FD4B09-37A3-40D5-8F2A-EA80762213CC"
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
        "x-ms-sevsnpvm-reportdata": "09582323ae7edaa31fe76b4965b21d4c982e1e1a3b73c5b46a9a590b38ce7c010000000000000000000000000000000000000000000000000000000000000000",
        "x-ms-sevsnpvm-reportid": "4bec0176bbc80b802673eee325b32989af6a232bce2d41ba54549a984d044258",
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
            "n": "ocTFYAAAtPu4l74fafO5w_OM6AUj497o9Asyc6eqI1WeXJFtE8GyBewJ1CRmLy0NK6lP4IzBdCXEYtGiFiMcpjc6fE7vLAC9hCMpfSBrFMPmxwZbZc4Rx4JdZIItlklmNejqnOylBt3rg8uVt5PmiMlK1khrzOG3UVbvo4GOAvPXarYQpwAsllQ38LCeCcNkf1ZnqlDI7jdbP3WLZ2Yw9SPeK6q_I1PuMmc3zSRZnH1IGs99DIocYD6B4IV9lzKvouqr7bjwnVohRBGMIvCfT6SFfFubUSQ-71bdkq9TBPX-8U26ZJXrhvldKR7e0i_C-21H4e84KhzhdYlWFaLk3w"
          }
        ]
      },
      "x-ms-ver": "1.0"
    }
    ```
    


