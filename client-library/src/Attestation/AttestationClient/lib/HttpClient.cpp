//-------------------------------------------------------------------------------------------------
// <copyright file="HttpClient.cpp" company="Microsoft Corporation">
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
#include "HttpClient.h"
#include "Exceptions.h"
#include "AttestationHelper.h"
#include "AttestationClientImpl.h"
#include "AttestationLibUtils.h"
#include "AttestationLibConst.h"
#include "TpmUnseal.h"

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_RESOURCE_NOT_FOUND 404
#define HTTP_STATUS_TOO_MANY_REQUESTS 429
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define MAX_RETRIES 3

attest::AttestationResult HttpClient::InvokeHttpImdsRequest(std::string& http_response,
                                                            const std::string& url,
                                                            const HttpClient::HttpVerb& http_verb,
                                                            const std::string& request_body,
                                                            const std::string& content_type) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        CLIENT_LOG_ERROR("Failed to initialize curl for http request.");
        result.code_ = AttestationResult::ErrorCode::ERROR_CURL_INITIALIZATION;
        result.description_ = std::string("Failed to initialize curl for http request.");
        return result;
    }

    // Set the the HTTPHEADER object to send Metadata in the response.
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Metadata:true");

    if (!content_type.empty()) {
        headers = curl_slist_append(headers, content_type.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Send a pointer to a std::string to hold the response from the end
    // point along with the handler function.
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // Set the url of the end point that we are trying to talk to.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    if (http_verb == HttpClient::HttpVerb::POST) {
        if (request_body.empty()) {
            CLIENT_LOG_ERROR("Request body missing for POST request");
            result.code_ = AttestationResult::ErrorCode::ERROR_EMPTY_REQUEST_BODY;
            result.description_ = std::string("Request body missing for POST request");
            return result;
        }

        // Set Http verb as POST
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

        // set the payload that will be sent to the endpoint.
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_body.size());
    }

    // Adding timeout for 300 sec
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);

    CURLcode res = CURLE_OK;
    uint8_t retries = 0;
    while ((res = curl_easy_perform(curl)) == CURLE_OK) {
        long response_code = HTTP_STATUS_OK;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (HTTP_STATUS_OK == response_code) {
            http_response = response;
            if (http_response.size() == 0) {
                CLIENT_LOG_ERROR("Empty response received");
                result.code_ = AttestationResult::ErrorCode::ERROR_EMPTY_RESPONSE;
                result.description_ = std::string("Empty response received");
            }

            break;
        }
        else if (response_code == HTTP_STATUS_RESOURCE_NOT_FOUND ||
            response_code == HTTP_STATUS_TOO_MANY_REQUESTS ||
            response_code >= HTTP_STATUS_INTERNAL_SERVER_ERROR) {
            if (retries == MAX_RETRIES) {
                CLIENT_LOG_ERROR("Http Request failed with error:%ld description:%s",
                    response_code,
                    response.c_str());
                result.code_ = AttestationResult::ErrorCode::ERROR_HTTP_REQUEST_EXCEEDED_RETRIES;
                result.description_ = response;
                break;
            }
            CLIENT_LOG_ERROR("HTTP request failed with response code:%ld description:%s",
                response_code,
                response.c_str());
            CLIENT_LOG_INFO("Retrying HTTP request:%d", retries);

            // Retry with backoff 30 -> 60 -> 120 seconds
            std::this_thread::sleep_for(
                std::chrono::seconds(
                    static_cast<long long>(30 * pow(2.0, static_cast<double>(retries++)))
                ));
            response = std::string();
            continue;
        }
        else {
            CLIENT_LOG_ERROR("HTTP request failed with response code:%ld description:%s",
                response_code,
                response.c_str());
            result.code_ = AttestationResult::ErrorCode::ERROR_HTTP_REQUEST_FAILED;
            result.description_ = response;
            break;
        }
    }

    if (res != CURLE_OK) {
        CLIENT_LOG_ERROR("curl_easy_perform() failed:%s", curl_easy_strerror(res));
        result.code_ = AttestationResult::ErrorCode::ERROR_SENDING_CURL_REQUEST_FAILED;
        result.description_ = std::string("Failed sending curl request with error:") + std::string(curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return result;
}

size_t HttpClient::WriteResponseCallback(void* contents, size_t size, size_t nmemb, void* response)
{
    if (response == nullptr ||
        contents == nullptr) {
        CLIENT_LOG_ERROR("Invalid input parameters");
        return 0;
    }
    std::string* responsePtr = reinterpret_cast<std::string*>(response);

    char* contentsStr = (char*)contents;
    size_t contentsSize = size * nmemb;

    responsePtr->insert(responsePtr->end(), contentsStr, contentsStr + contentsSize);

    return contentsSize;
}