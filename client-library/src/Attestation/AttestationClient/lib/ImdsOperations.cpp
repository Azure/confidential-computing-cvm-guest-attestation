//-------------------------------------------------------------------------------------------------
// <copyright file="ImdsOperations.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <curl/curl.h>
#include <json/json.h>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include "Logging.h"
#include "ImdsOperations.h"
#include "Exceptions.h"
#include "AttestationHelper.h"
#include "AttestationClientImpl.h"
#include "AttestationLibUtils.h"
#include "AttestationLibConst.h"
#include "TpmUnseal.h"
#include "HttpClient.h"

// IMDS endpoint for getting the VCek certificate
constexpr char imds_endpoint[] = "http://169.254.169.254/metadata";
constexpr char vcek_cert_path[] = "/THIM/amd/certification";

attest::AttestationResult ImdsOperations::GetVCekCert(std::string& vcek_cert) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    std::string http_response;
    std::string url = std::string(imds_endpoint) +
                      std::string(vcek_cert_path);

    HttpClient http_client;
    if ((result = http_client.InvokeHttpImdsRequest(http_response, url, HttpClient::HttpVerb::GET)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to retrieve VCek certificate from IMDS: %s",
            result.description_.c_str());
        return result;
    }

    Json::Value root;
    Json::Reader reader;
    bool parsing_successful = reader.parse(http_response, root);
    if (!parsing_successful) {
        CLIENT_LOG_ERROR("Invalid JSON reponse from IMDS");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_JSON_RESPONSE;
        result.description_ = std::string("Invalid JSON reponse from IMDS");
        return result;
    }

    std::string cert = root["vcekCert"].asString();
    std::string chain = root["certificateChain"].asString();
    if (cert.empty() ||
        chain.empty()) {
        CLIENT_LOG_ERROR("Empty VCek cert received from THIM");
        result.code_ = AttestationResult::ErrorCode::ERROR_EMPTY_VCEK_CERT;
        result.description_ = std::string("Empty VCek cert received from THIM");
        return result;
    }

    CLIENT_LOG_DEBUG("VCek cert received from IMDS successfully");
    std::string cert_chain = cert + chain;
    vcek_cert = attest::base64::base64_encode(cert_chain);
    return result;
}
