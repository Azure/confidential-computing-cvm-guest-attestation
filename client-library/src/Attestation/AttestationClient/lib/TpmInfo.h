//-------------------------------------------------------------------------------------------------
// <copyright file="Tpm.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <json/json.h>
#include <AttestationTypes.h>

namespace attest {

/**
 *@brief Structure to hold Tpm related information.
 */
class TpmInfo {
public:

    bool Validate() const;
    Json::Value ToJson() const;

    Buffer aik_cert_; /**< Client Tpm's aik cert */
    Buffer aik_pub_; /**< Client Tpm's aik publick key */
    PcrSet pcr_values_ = {}; /**< Client Tpm's current pcr values */
    PcrQuote pcr_quote_ = {}; /**< Client Tpm's current pcr value hash and signature */
    EphemeralKey encryption_key_ = {}; /**< Encryption key components that will be used by AAS to encrypt jwt sym key */
};
}// attest
