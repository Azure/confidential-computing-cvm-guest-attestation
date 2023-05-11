//-------------------------------------------------------------------------------------------------
// <copyright file="Constants.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <string>

class Constants
{
public:
    // Default attestation url
    static inline const std::string DEFAULT_ATTESTATION_URL{"https://sharedweu.weu.attest.azure.net/"};

    // AKV suffix for public cloud
    static inline const std::string AKV_URL_SUFFIX{"vault.azure.net"};

    // mHSM suffix for public cloud
    static inline const std::string MHSM_URL_SUFFIX{"managedhsm.azure.net"};

    // Default AKV resource url
    static inline const std::string AKV_RESOURCE_URL{"https://vault.azure.net"};

    // Default mHSM resource url
    static inline const std::string MHSM_RESOURCE_URL{"https://managedhsm.azure.net"};

    // IMDS token URL
    static inline const std::string IMDS_TOKEN_URL{"http://169.254.169.254/metadata/identity/oauth2/token"};

    // IMDS api version
    static inline const std::string IMDS_API_VERSION = "2018-02-01";

    // Default Nonce
    static inline const std::string NONCE = "ADE0101";
};
