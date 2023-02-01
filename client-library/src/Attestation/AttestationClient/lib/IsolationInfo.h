//-------------------------------------------------------------------------------------------------
// <copyright file="IsolationInfo.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <json/json.h>
#include <AttestationTypes.h>

namespace attest {
    enum class IsolationType {
        TRUSTED_LAUNCH,
        SEV_SNP
    };

    /**
     *@brief Structure to hold isolation type related information.
     */
    class IsolationInfo {
    public:

        bool Validate() const;
        Json::Value ToJson() const;

        IsolationType isolation_type_ = IsolationType::TRUSTED_LAUNCH;
        Buffer snp_report_;
        Buffer runtime_data_;
        std::string vcek_cert_;
    };
}// attest
