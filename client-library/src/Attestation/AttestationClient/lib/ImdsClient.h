//-------------------------------------------------------------------------------------------------
// <copyright file="ImdsClient.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <curl/curl.h>
#include <json/json.h>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "Logging.h"
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "AttestationLibUtils.h"
#include "TelemetryReportingBase.h"

class ImdsClient {
public:
    enum class HttpVerb {
        GET,
        POST
    };

    /**
     * @brief This function will be used to retrieve VM Id from IMDS
     * @return On success, vm_id is returned. On failure, empty string is returned. 
     */
    std::string GetVmId();

    /**
     * @brief This function will be used to send a renew AK cert request to OneCert via THIM agent
     * @param[in] cert, the old AK cert which has already expired or will expire within next 90 days
     * @param[in] vm_id, the VM Id guid
     * @param[in] request_id, the request id guid
     * @param[in] api_version Thim api version
     * @return On success, guid is returned. On failure, empty string is returned.
     */
    std::string RenewAkCert(
        const std::string& cert,
        const std::string& vm_id,
        const std::string& request_id,
        const std::string& api_version);

    /**
     * @brief This function will be used to send a request
     * to get the renewed AK cert from OneCert via THIM agent
     * @param[in] cert_query_guid, the guid which is sent to onecert to get the renewed AK cert
     * @param[in] vm_id, the VM Id guid
     * @param[in] request_id, the request id guid
     * @return On success, renewed AK cert is returned as PEM string. On failure, empty string is returned.
     */
    std::string QueryAkCert(
        const std::string& cert_query_guid,
        const std::string& vm_id,
        const std::string& request_id);
private:
    /**
     * @brief This function will be used to get the IMDS VM Id query URL
     * @return On success, IMDS VM Id query URL is returned
     */
    std::string GetVmIdQueryEndpoint();

    /**
     * @brief This function will be used to get the THIM AK Renew URL
     * @param[in] vm_id, the VM Id guid
     * @param[in] request_id, the request id guid
     * @param[in] api_version, Thim api version
     * @return On success, THIM AK Renew URL is returned
     */
    std::string GetThimAkRenewEndpoint(const std::string& vm_id, const std::string& request_id, const std::string& api_version);

    /**
     * @brief This function will be used to get the THIM AK Query URL
     * @param[in] vm_id, the VM Id guid
     * @param[in] request_id, the request id guid
     * @param[in] cert_query_guid, the certificate query GUID
     * @return On success, THIM AK Query URL is returned
     */
    std::string GetThimQueryAkEndpoint(const std::string& vm_id, const std::string& request_id, const std::string& cert_query_guid);

    /**
     * @brief This function will be used to invoke a HTTP request
     * @param[in] url, the url endpoint to be called
     * @param[in] http_verb, the HTTP verb (GET or POST)
     * @param[in] request_body, the request body. This is expected for any POST calls.
     * @return On success, string response is returned. On Failure, empty string is returned.
     */
    std::string InvokeHttpRequest(const std::string& url, const ImdsClient::HttpVerb& http_verb, const std::string& request_body = std::string());
    
    /**
     * @brief This function will be used to URL encode the data
     * @param[in] data, the data to be URL encoded
     * @return On success, URL encoded string is returned
     */
    std::string UrlEncode(const std::string& data);

    /*
     * @brief CURL Callback to write response to a user specified pointer
    */
    static size_t WriteResponseCallback(void* contents, size_t size, size_t nmemb, void* response);
};