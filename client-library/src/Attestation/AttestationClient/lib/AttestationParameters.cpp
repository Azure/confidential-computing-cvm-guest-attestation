//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationParameters.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include "AttestationHelper.h"

#include "AttestationParameters.h"
#include "AttestationLibConst.h"

namespace attest {

static std::string getOSTypeStr(const OsType& os_type) {
    switch(os_type) {
        case OsType::LINUX:
            return std::string("Linux");
        case OsType::WINDOWS:
            return std::string("Windows");
        default:
            return std::string("Unknown");
    }
}

bool AttestationParameters::Validate() const {
    // Check if the member variable values are as expected.

    // Validate the tpminfo valus.
    if(!tpm_info_.Validate()) {
        return false;
    }

    if (!isolation_info_.Validate()) {
        return false;
    }

    if(os_info_.type == OsType::INVALID ||
       os_info_.build.empty() ||
       os_info_.distro_name.empty() ||
       os_info_.distro_version_major == 0 ||
       attestation_protocol_ver_.empty()) {
        return false;
    }
    return true;
}

Json::Value AttestationParameters::ToJson() const {
    Json::Value attestation_info;
    std::string os_type_str = getOSTypeStr(os_info_.type);

    std::string os_type_encoded = base64::binary_to_base64(Buffer(os_type_str.begin(), os_type_str.end()));
    std::string os_distro_encoded = base64::binary_to_base64(Buffer(os_info_.distro_name.begin(), os_info_.distro_name.end()));
    std::string os_build_encoded = base64::binary_to_base64(Buffer(os_info_.build.begin(), os_info_.build.end()));

    attestation_info[JSON_PROTOCOL_VERSION_KEY] = attestation_protocol_ver_;
    attestation_info[JSON_OS_TYPE_KEY] = os_type_encoded;
    attestation_info[JSON_OS_DISTRO_KEY] = os_distro_encoded;
    attestation_info[JSON_OS_VERSION_MAJOR_KEY] = os_info_.distro_version_major;
    attestation_info[JSON_OS_VERSION_MINOR_KEY] = os_info_.distro_version_minor;
    attestation_info[JSON_OS_BUILD_KEY] = os_build_encoded;

    attestation_info[JSON_TCG_LOGS_KEY] = base64::binary_to_base64(tcg_logs_);

    Json::Value client_payload;
    for(auto const& entry: client_payload_) {
        std::string value = base64::binary_to_base64(Buffer(entry.second.begin(), entry.second.end()));
        client_payload[entry.first.c_str()] = value;
    }
    attestation_info[JSON_CLIENT_PAYLOAD_KEY] = client_payload;

    attestation_info[JSON_TPM_INFO_KEY] = tpm_info_.ToJson();
    attestation_info[JSON_ISOLATION_INFO_KEY] = isolation_info_.ToJson();

    return attestation_info;
}
} // attest
