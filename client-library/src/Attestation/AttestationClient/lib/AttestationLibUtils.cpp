//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationLibUtils.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <iostream>
#include <algorithm>
#include <math.h>
#include <chrono>
#include <thread>
#include <climits>
#include <sstream>
#include <curl/curl.h>
#include <json/json.h>
#include <boost/algorithm/string.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "Logging.h"
#include "AttestationLibConst.h"
#include "AttestationLibUtils.h"
#include "AttestationHelper.h"

#define MAX_RETRIES 3

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_SERVER_ERROR 500
#define HTTP_STATUS_ATTESTATION_FAILURE 400

// IMDS HTTP Error Codes
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_RESOURCE_NOT_FOUND 404
#define HTTP_STATUS_TOO_MANY_REQUESTS 429

/// <summary>
/// Log the error and return the error code and description
/// </summary>
/// <param name="errorCode">Client error code</param>
/// <param name="errorDescription">The description of the error code</param>
/// <returns>AttestationResult</returns>
static inline AttestationResult LogErrorAndGetResult(const AttestationResult::ErrorCode& errorCode,
    const std::string& errorDescription)
{
    CLIENT_LOG_ERROR("Error code:%d description:%s",
        errorCode,
        errorDescription.c_str());
    AttestationResult result;
    result.code_ = errorCode;
    result.description_ = errorDescription;
    return result;
}

namespace attest {

PcrList GetAttestationPcrList(uint32_t pcr_selector) {
    if(pcr_selector == 0) {
        #ifdef PLATFORM_UNIX
        attest::PcrList list{0, 1, 2, 3, 4, 5, 6, 7};
        #else
        attest::PcrList list{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14};
        #endif
        return list;
    } else {
      attest::PcrList list;
      for(int bit = 0; bit < 32; bit++) {
        if((pcr_selector >> bit) & 1)
          list.push_back(bit);
      }
      return list;
    }
}


namespace os {

#ifdef PLATFORM_UNIX

/**
 * @brief The function will be used to convert the string representation of integer
 * into an integer.
 * @param[in] str string value to be converted to integer.
 * @return On success, the function return a value integer value. On failure,
 * INT_MIN is returned.
 */
static int parseInt(const std::string& str) {
    int num = INT_MIN;
    try {
        num = std::stoi(str);
    }
    catch(std::invalid_argument& e) {
        CLIENT_LOG_ERROR("Invaid input argument");
    }
    catch(std::out_of_range& e) {
        CLIENT_LOG_ERROR("Input out of range");
    }
    return num;
}

bool ParseOSReleaseFile(const char* os_release_path,
                        const std::string& delim,
                        std::unordered_map<std::string, std::string>& entries) {

    if(os_release_path == nullptr ||
       delim.empty()) {
        CLIENT_LOG_ERROR("Invaid input argument");
        return false;
    }

    std::ifstream input(os_release_path);
    if(input.fail()) {
        CLIENT_LOG_ERROR("Failed to open file:%s",
                         os_release_path);
        return false;
    }

    // Set the pointer to the start of the file.
    input.seekg(0);

    while(!input.eof()) {
        std::string line;
        std::getline(input, line);

        size_t delim_pos = line.find_first_of(delim);
        if(delim_pos == std::string::npos) {
            // Since this line does not contain a key value pair, skip the
            // line.
            continue;
        }

        std::string key = line.substr(0, delim_pos);
        std::string value = line.substr(delim_pos + 1);

        // Remove any "" around the value.
        value.erase(std::remove(value.begin(), value.end(), '\"'), value.end());
        entries[key] = value;
    }
    return true;
}

bool ParseVersionString(const std::string& str,
                        uint32_t& major_version,
                        uint32_t& minor_version) {

    major_version = 0;
    minor_version = 0;
    int major = INT_MIN;
    int minor = 0;

    if(str.empty()) {
        CLIENT_LOG_ERROR("Invlid input parameter");
        return false;;
    }

    std::stringstream ss(str);
    if(!ss.eof()) {
        std::string major_str;
        getline(ss, major_str, '.');
        major = parseInt(major_str);
        if(major == INT_MIN) {
            CLIENT_LOG_ERROR("Failed to get major version from string:%s",
                             major_str.c_str());
            return false;
        }
    }

    if(!ss.eof()) {
        std::string minor_str;
        getline(ss, minor_str, '.');
        minor = parseInt(minor_str);
        if(minor == INT_MIN) {
            CLIENT_LOG_ERROR("Failed to get minor version from string:%s",
                             minor_str.c_str());
            return false;
        }
    }

    major_version = major;
    minor_version = minor;
    return true;
}

#else

bool GetWindowsVersion(uint32_t& major_version,
                       uint32_t& minor_version,
                       std::string& os_build) {

    // TODO: Replace these static values with values from the an API.
    major_version = 10;
    minor_version = 0;

    // For windows, the build number is a place holder for future needs to have the
    // OS build number as part of the attestation request.
    os_build = std::string("NotApplicable");

    return true;
}

#endif

} // os

namespace curl {


static size_t writeResponseCallback(void *contents, size_t size, size_t nmemb, void *response)
{
    std::string *responsePtr((std::string*)response);
    std::string responseStr = *responsePtr;

    char *contentsStr = (char*)contents;
    size_t contentsSize = size * nmemb;

    responseStr.insert(responseStr.end(), contentsStr, contentsStr + contentsSize);

    *responsePtr = responseStr;
    return contentsSize;
}

static std::string getErrorMessage(const std::string& http_response) {
    std::string error_str;
    Json::Value response;
    Json::Reader reader;
    bool success = reader.parse(http_response.c_str(), response);
    if(!success) {
        CLIENT_LOG_ERROR("Failed to parse http response");
        return error_str;
    }

    // In case of server errors, the json keys are Camel cases and keys
    // are lower case for all other errors.
    Json::Value error_obj;
    if(response.isMember(JSON_HTTP_ERROR_KEY)) {
       error_obj = response.get(JSON_HTTP_ERROR_KEY, Json::Value());
    } else {
       error_obj = response.get(JSON_HTTP_ERROR_LOWER_KEY, Json::Value());
    }
    if(error_obj.isNull()) {
        CLIENT_LOG_ERROR("Failed to find error obj in http response");
        return error_str;
    }

    std::string error_code;
    if(error_obj.isMember(JSON_HTTP_ERROR_CODE_KEY)) {
        error_code = error_obj.get(JSON_HTTP_ERROR_CODE_KEY, "").asString();
    } else {
        error_code = error_obj.get(JSON_HTTP_ERROR_CODE_LOWER_KEY, "").asString();
    }
    if(error_code.empty()) {
        CLIENT_LOG_ERROR("Failed to get error code from http response");
        return error_str;
    }

    std::string error_message;
    if(error_obj.isMember(JSON_HTTP_ERROR_MESSAGE_KEY)) {
        error_message = error_obj.get(JSON_HTTP_ERROR_MESSAGE_KEY, "").asString();
    } else {
        error_message = error_obj.get(JSON_HTTP_ERROR_MESSAGE_LOWER_KEY, "").asString();
    }
    if(error_message.empty()) {
        CLIENT_LOG_ERROR("Failed to get error message from http response");
        return error_str;
    }

    // The error str being returned contains both the error code and the
    // error message in the format code:message.
    error_str = error_code + ":" + error_message;
    return error_str;
}

AttestationResult SendRequest(const std::string& url,
                              const std::string& payload,
                              std::string& http_response) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    CURL *curl = curl_easy_init();
    if(curl == nullptr) {
        result.code_ = AttestationResult::ErrorCode::ERROR_CURL_INITIALIZATION;
        result.description_ = std::string("Failed to initialize curl for http request.");
        return result;
    }

    // Create a header object to add the authentication token and content-type to the header.
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set the url of the end point that we are trying to talk to.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // set the payload that will be sent to the endpoint.
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());

    // For Linux, We use the native libcurl that is installed from the repo
    // and the lib reads the ca bundle from a pre-defined location.
    // In the Windows case, since we link to the lib as an external lib,
    // we need to explicitly configure the ca bundle location and provide a
    // ca bundle that the lib can use.
    #ifndef PLATFORM_UNIX
    curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    #endif

    // Send a pointer to a std::string to hold the response from the end
    // point along with the handler function.
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeResponseCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = CURLE_OK;
    uint8_t retries = 0;
    while((res = curl_easy_perform(curl)) == CURLE_OK) {

        long response_code = HTTP_STATUS_OK;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if(response_code == HTTP_STATUS_OK) {
            http_response = response;
            break;
        } else if(response_code == HTTP_STATUS_ATTESTATION_FAILURE) {
                std::string error_msg = response;

                CLIENT_LOG_ERROR("Attestation failed with error code:%ld description:%s",
                                 response_code,
                                 error_msg.c_str());

                result.code_ = AttestationResult::ErrorCode::ERROR_ATTESTATION_FAILED;
                result.description_ = error_msg;
                break;
        } else if(response_code >= HTTP_STATUS_SERVER_ERROR) {
            std::string error_msg = response;

            CLIENT_LOG_ERROR("Http Request failed with error:%ld description:%s",
                              response_code,
                              error_msg.c_str());
            CLIENT_LOG_INFO("Retrying");

            //Retry sending the request since this is a server failure.
            if(retries == MAX_RETRIES) {
                CLIENT_LOG_ERROR("Http Request failed with error:%ld description:%s",
                                 response_code,
                                 error_msg.c_str());
                CLIENT_LOG_ERROR("Maxinum retries exceeded.");

                result.code_ = AttestationResult::ErrorCode::ERROR_HTTP_REQUEST_EXCEEDED_RETRIES;
                result.description_ = error_msg;
                break;
            }

            // Sleep for the backoff period and try again.
            std::this_thread::sleep_for(
                std::chrono::seconds(
                    static_cast<long long>(5 * pow(2.0, static_cast<double>(retries++)))
                ));
            response = std::string();
            continue;
        } else {
            std::string error_msg = response;

            CLIENT_LOG_ERROR("Http Request failed with error:%ld description:%s",
                             response_code,
                             error_msg.c_str());

            result.code_ = AttestationResult::ErrorCode::ERROR_HTTP_REQUEST_FAILED;
            result.description_ = error_msg;
            break;
        }
    }
    if(res != CURLE_OK) {
        CLIENT_LOG_ERROR("Failed sending curl request with error:%s",
                         curl_easy_strerror(res));

        result.code_ = AttestationResult::ErrorCode::ERROR_SENDING_CURL_REQUEST_FAILED;
        result.description_ = std::string("Failed sending curl request with error:") + std::string(curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return result;
}
} // curl

namespace jwt {
    bool ExtractJwkInfoFromAttestationJwt(std::string jwt,
                                          std::string& n,
                                          std::string& e) {
        if (jwt.empty()) {
            CLIENT_LOG_ERROR("Invalid input argument");
            return false;
        }
        try {
            std::vector<std::string> tokens;
            boost::split(tokens, jwt, [](char c) {return c == '.'; });
            if (tokens.size() < 3) {
                CLIENT_LOG_ERROR("Invalid JWT token");
                return false;
            }
            Json::Value root;
            Json::Reader reader;
            bool parsing_successful = reader.parse(attest::base64::base64_decode(tokens[1]), root);
            if (!parsing_successful) {
                CLIENT_LOG_ERROR("Error parsing the JWT claims");
                return false;
            }

            Json::Value x_ms_runtime = root["x-ms-runtime"];
            Json::Value keys = x_ms_runtime["keys"];
            Json::Value key = keys[0];
            std::string n_base64url = key["n"].asString();
            std::string e_base64url = key["e"].asString();
            n = n_base64url;
            e = e_base64url;
        }
        catch (...) {
            CLIENT_LOG_ERROR("Unexpected error while extracting JWK info from JWT");
            return false;
        }
        return true;
    }

} // jwt

namespace crypto {
    AttestationResult EncryptDataWithRSAPubKey(BIO* pkey_bio,
                                               const attest::RsaScheme rsaWrapAlgId,
                                               const attest::RsaHashAlg rsaHashAlgId,
                                               const Buffer& input_data,
                                               Buffer& encrypted_data) {
        AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
        if (pkey_bio == NULL ||
            input_data.empty()) {
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER,
                                        "Invalid input parameter");
        }

        const EVP_MD* rsa_md = EVP_md_null();
        switch (rsaHashAlgId)
        {
        case RsaHashAlg::RsaSha1:
            rsa_md = EVP_sha1();
            break;
        case RsaHashAlg::RsaSha256:
            rsa_md = EVP_sha256();
            break;
        case RsaHashAlg::RsaSha384:
            rsa_md = EVP_sha384();
            break;
        case RsaHashAlg::RsaSha512:
            rsa_md = EVP_sha512();
            break;
        default:
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                        "EncryptDataWithRSAPubKey failed; called with unknown message digest algorithm");
        }

        // Set the RSA padding and message digest algorithm
        int ret = 0;
        int rsa_padding_algo = 0;
        switch (rsaWrapAlgId)
        {
        case RsaScheme::RsaEs:
            rsa_padding_algo = RSA_PKCS1_PADDING;
            break;
        case RsaScheme::RsaOaep:
            rsa_padding_algo = RSA_PKCS1_OAEP_PADDING;
            break;
        case RsaScheme::RsaNull:
            rsa_padding_algo = RSA_NO_PADDING;
            break;
        default:
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                 "EncryptDataWithRSAPubKey failed; called with unknown RSA padding algorithm");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pkey_bio, NULL, NULL, NULL);
        EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
            EVP_PKEY_CTX_free(enc_ctx);
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                        "EVP_PKEY_encrypt_init failed");
        }

        // Set the RSA padding algorithm
        ret = EVP_PKEY_CTX_set_rsa_padding(enc_ctx, rsa_padding_algo);
        if (ret <= 0)
        {
            EVP_PKEY_CTX_free(enc_ctx);
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                        "EVP_PKEY_CTX_set_rsa_padding failed");
        }

        // Set the RSA message digest algorithm
        if (rsaWrapAlgId == RsaScheme::RsaOaep)
        {
            ret = EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, rsa_md);
            if (ret <= 0)
            {
                EVP_PKEY_CTX_free(enc_ctx);
                return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                            "EVP_PKEY_CTX_set_rsa_oaep_md failed");
            }
        }
        else if (rsaWrapAlgId == RsaScheme::RsaEs)
        {
            // TODO: There isn't equivalent of EVP_PKEY_CTX_set_rsa_oaep_md for RSA_PKCS1_PADDING
            //       Need to figure out how to set the hash algorithm for RSA_PKCS1_PADDING
            // Note: 1- EVP_PKEY_CTX_set_rsa_oaep_md is only used for RSA_PKCS1_OAEP_PADDING
            //       and not for RSA_PKCS1_PADDING. EVP_PKEY_CTX_set_rsa_oaep_md throws on Linux,
            //       but not on Windows.
            //       2- EVP_PKEY_CTX_set_signature_md is for signing and not for encryption.

            // ret = EVP_PKEY_CTX_set_rsa_???_md(enc_ctx, rsa_md);
        }
        else if (rsaWrapAlgId == RsaScheme::RsaNull)
        {
            // No need to set any MD for RSA_NO_PADDING
        }
        else
        {
            // Should never get here, since we already checked for valid values
            EVP_PKEY_CTX_free(enc_ctx);
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED,
                                        "Invalid RSA wrap algorithm");
        }

        // Encrypt the data
        size_t outlen;
        unsigned char* out;
        if (EVP_PKEY_encrypt(enc_ctx, NULL, &outlen, &input_data.front(), input_data.size()) <= 0) {
            CLIENT_LOG_ERROR("EVP_PKEY_encrypt failed");
            EVP_PKEY_CTX_free(enc_ctx);
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_FAILED,
                                        "EVP_PKEY_encrypt failed");
        }
        out = (unsigned char*)OPENSSL_malloc(outlen);
        if (EVP_PKEY_encrypt(enc_ctx, out, &outlen, &input_data.front(), input_data.size()) <= 0) {
            CLIENT_LOG_ERROR("EVP_PKEY_encrypt failed");
            EVP_PKEY_CTX_free(enc_ctx);
            OPENSSL_free(out);
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_EVP_PKEY_ENCRYPT_FAILED,
                                        "EVP_PKEY_encrypt failed");
        }

        Buffer out_data(out, out + outlen);
        encrypted_data = out_data;
        EVP_PKEY_CTX_free(enc_ctx);
        OPENSSL_free(out);
        return result;
    }

    AttestationResult ConvertJwkToRsaPubKey(BIO* pkey_bio,
                                            const std::string& n,
                                            const std::string& e) {
        AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
        if (pkey_bio == NULL ||
            n.empty() ||
            e.empty()) {
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER,
                                        "Invalid input parameter");
        }
        RSA* rsa = NULL;
        try {
            auto n_bin = base64::base64url_to_binary(n);
            auto e_bin = base64::base64url_to_binary(e);
            BIGNUM* modul = BN_bin2bn(n_bin.data(), n_bin.size(), NULL);
            BIGNUM* expon = BN_bin2bn(e_bin.data(), e_bin.size(), NULL);
            rsa = RSA_new();
            RSA_set0_key(rsa, modul, expon, NULL);
            PEM_write_bio_RSA_PUBKEY(pkey_bio, rsa);
        }
        catch (...) {
            result = LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_CONVERTING_JWK_TO_RSA_PUB,
                                          "Error while converting JWK to RSA public key");
        }

        RSA_free(rsa);
        return result;
    }
} // crypto

namespace url {
    AttestationResult ParseURL(const std::string& url,
                               std::string& domain) {
        AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
        if (url.empty()) {
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER,
                                        "Invalid input parameter");
        }

        std::string sanitized_url = url;
        // trim the url from left and right ends
        boost::trim_left(sanitized_url);
        boost::trim_right(sanitized_url);

        std::string path, dns, protocol, port, query;
        int offset = 0;
        size_t path_idx, port_idx, query_idx;
        offset = offset == 0 && sanitized_url.compare(0, 8, "https://") == 0 ? 8 : offset;
        offset = offset == 0 && sanitized_url.compare(0, 7, "http://") == 0 ? 7 : offset;
        path_idx = sanitized_url.find_first_of('/', offset + 1);
        path = path_idx == std::string::npos ? "" : sanitized_url.substr(path_idx);
        dns = std::string(sanitized_url.begin() + offset, path_idx != std::string::npos ? sanitized_url.begin() + path_idx : sanitized_url.end());
        port = (port_idx = dns.find(":")) != std::string::npos ? dns.substr(port_idx + 1) : "";
        dns = dns.substr(0, port_idx != std::string::npos ? port_idx : dns.length());
        protocol = offset > 0 ? sanitized_url.substr(0, offset - 3) : "";
        query = (query_idx = path.find("?")) != std::string::npos ? path.substr(query_idx + 1) : "";
        path = query_idx != std::string::npos ? path.substr(0, query_idx) : path;
        if (dns.empty()) {
            return LogErrorAndGetResult(AttestationResult::ErrorCode::ERROR_PARSING_DNS_INFO,
                                        "Error extracting DNS info from URL");
        }

        CLIENT_LOG_INFO("Attestation URL info - protocol {%s}, domain {%s}", 
                            protocol.c_str(), dns.c_str());
        domain = dns;
        return result;
    }
} // url
} // attest
