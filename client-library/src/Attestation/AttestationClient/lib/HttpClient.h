//-------------------------------------------------------------------------------------------------
// <copyright file="HttpClient.h" company="Microsoft Corporation">
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
#include "Logging.h"
#include <stdio.h>
#include "AttestationLibTypes.h"
#include "AttestationParameters.h"
#include "Tpm.h"
#include "AttestationClient.h"

class HttpClient {
public:
    enum class HttpVerb {
        GET,
        POST
    };

    /**
     *@brief This function will be used to send a http request 
     * @param[in] url, the url endpoint to be called
     * @param[in] http_verb, the HTTP verb (GET or POST)
     * @param[in] request_body, the request body. This is expected for any POST calls.
     * @param[in] content_type, content type to be included in the request headers.
     * @param[out] http_response The response received from the endpoint.
     * @return On sucess, the function returns
     * AttestationResult::ErrorCode::SUCCESS and the http_response is set to the
     * response from the end point.On failure, AttestationResult::ErrorCode is
     * returned.
     */
    attest::AttestationResult InvokeHttpImdsRequest(std::string& http_response,
                                                    const std::string& url,
                                                    const HttpClient::HttpVerb& http_verb,
                                                    const std::string& request_body = std::string(),
                                                    const std::string &content_type = std::string());

private:
    /**
     * @brief CURL Callback to write response to a user specified pointer
     */
    static size_t WriteResponseCallback(void* contents, size_t size, size_t nmemb, void* response);
};