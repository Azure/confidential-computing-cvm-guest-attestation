//-------------------------------------------------------------------------------------------------
// <copyright file="IsolationInfo.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <json/json.h>
#include <AttestationTypes.h>
#include "IsolationInfo.h"
#include "AttestationLibConst.h"
#include "AttestationHelper.h"

namespace attest {
    bool IsolationInfo::Validate() const {
        if (isolation_type_ == IsolationType::SEV_SNP && 
           (snp_report_.empty() || vcek_cert_.empty() || runtime_data_.empty())) {
            return false;
        }

        return true;
    }

    Json::Value IsolationInfo::ToJson() const {
        Json::Value isolation_info;
        if (isolation_type_ == IsolationType::TRUSTED_LAUNCH) {
            isolation_info[JSON_ISOLATION_TYPE_KEY] = JSON_ISOLATION_TYPE_TVM;
        }
        else {
            isolation_info[JSON_ISOLATION_TYPE_KEY] = JSON_ISOLATION_TYPE_SEVSNP;

            Json::Value isolation_evidence;
            Json::Value proof;
            proof[JSON_ISOLATION_EVIDENCE_SNPREPORT] = base64::binary_to_base64url(snp_report_);
            proof[JSON_ISOLATION_EVIDENCE_VCEKCERT] = vcek_cert_;

            Json::StreamWriterBuilder builder;
            const std::string proof_str = Json::writeString(builder, proof);
            isolation_evidence[JSON_ISOLATION_PROOF_KEY] = base64::base64_encode(proof_str);
            isolation_evidence[JSON_ISOLATION_RUNTIME_DATA_KEY] = base64::binary_to_base64(runtime_data_);

            isolation_info[JSON_ISOLATION_EVIDENCE_KEY] = isolation_evidence;
        }

        return isolation_info;
    }
}// attest
