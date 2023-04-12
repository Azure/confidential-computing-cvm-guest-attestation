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

    // Default AKV url
    static inline const std::string AKV_RESOURCE_URL{"https://vault.azure.net"};

    // IMDS token URL
    static inline const std::string IMDS_TOKEN_URL{"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"};
};
