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
        SEV_SNP,
        TDX
    };

    /**
     *@brief Structure to hold isolation type related information.
     */
    class IsolationInfo {
    public:

        bool Validate() const;
        Json::Value ToJson() const;

        /**
         * @brief Specifies the type of isolation being used.
         *
         * Note: Isolation type Trusted_Launch doesn't require any additional proof
         */
        IsolationType isolation_type_ = IsolationType::TRUSTED_LAUNCH;

        /**
         * @brief Stores the SEV-SNP attestation report.
         */
        Buffer snp_report_;

        /**
         * @brief Stores the VCEK certificate for SEV-SNP.
         */
        std::string vcek_cert_;

        /**
         * @brief Stores the TDX attestation quote.
         *
         * The TDX quote includes a signed TDX report along with the certificate
         * chain required for verification.
         */
        Buffer tdx_quote_;

        /**
         * @brief Stores the runtime data.
         *
         * This data is common for both SEV-SNP and TDX isolation types.
         */
        Buffer runtime_data_;
    private:
        Json::Value CreateSevSnpEvidence() const;
        Json::Value CreateTdxEvidence() const;
    };
}// attest
