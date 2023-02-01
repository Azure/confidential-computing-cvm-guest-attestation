//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationParameters.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <string>
#include <map>

#include <json/json.h>
#include <AttestationTypes.h>

#include "AttestationLibTypes.h"
#include "TpmInfo.h"
#include "IsolationInfo.h"

namespace attest {

/**
 * @brief The version number of the attestation protocol between the client and the service.
 */
static const std::string protocol_version("2.0");

/**
 * @brief Structure to hold information that needs to be sent to AAS for
 * attestation.
 */
class AttestationParameters {
public:

    bool Validate() const;
    Json::Value ToJson() const;

    OsInfo os_info_; /**< Struct to hold OS information like name and version */
    Buffer tcg_logs_; /**< tcg logs from the client system */
    std::unordered_map<std::string, std::string> client_payload_; /**< key value pair of data that needs to be sent to AAS for attestation*/
    TpmInfo tpm_info_ = {}; /**< Struct to hold Tpm related information */
    IsolationInfo isolation_info_ = {}; /**< Struct to hold the isolation type and evidence related information */
    const std::string attestation_protocol_ver_ = protocol_version;
};
} // attest
