//-------------------------------------------------------------------------------------------------
// <copyright file="TpmCertOperations.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <string>
#include <cstring>
#include <json/json.h>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "Tpm.h"
#include "AttestationHelper.h"
#include "AttestationLibConst.h"

class TpmCertOperations {
public:
    /**
     * @brief This function is used to check if AK cert renewal is required or not for the VM
     * @param[out] True, if the renewal is required. False, if renewal is not required
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult IsAkCertRenewalRequired(bool& is_ak_renewal_required);

    /**
     * @brief This function is used to perform the AK renew operation.
     * It also writes the renewed cert to the TPM
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult RenewAndReplaceAkCert();
private:
    /**
     * @brief This function will be used to read the AK cert from TPM
     * and convert it to PEM format
     * @param [out] PEM formatted AkCert  
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult ReadAkCertFromTpm(std::string& ak_cert);

    /**
     * @brief This function will be used to remove the header and footer from the PEM format
     * @return base64 encoded cert without header and footer.
     */
    std::string RemoveCertHeaderAndFooter(const std::string& pem_cert);

    /**
     * @brief This function will be used to read AK Pub from TPM
     * @param [out] AikPub key 
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
    */
    attest::AttestationResult ReadAikPubFromTpm(std::string& ak_pub);

    /**
     * @brief This function parse thim response and get akcert.
     * @return Renewed Ak cert in PEM format
    */
    std::string ParseAndGetAkCert(const std::string& json_response);

    /**
     * @brief This function is used to get the issuer of cert injected in TPM
     * @param [out] True if provisioned AK Cert is AME/ESTS rooted. False in case cert is self signed.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
    */
    attest::AttestationResult IsAkCertProvisioned(X509* ak_cert_x509);
};