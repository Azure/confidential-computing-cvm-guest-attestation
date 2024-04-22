//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationUtil.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
//

// TODO: Use OPENSSL_cleanse(buffer, sizeof(buffer)) to clear sensitive data from memory.

#include <cstdlib>
#include <ctime>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <AttestationClient.h>
#include "AttestationUtil.h"
#include "Logger.h"
#include "Constants.h"

using namespace attest;
using json = nlohmann::json;

bool Util::isTraceOn = false;
int Util::traceLevel = 1;

/// \copydoc Util::base64_to_binary()
std::vector<BYTE> Util::base64_to_binary(const std::string &base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::vector<BYTE>(It(std::begin(base64_data)), It(std::end(base64_data))), [](char c)
                                                { return c == '\0'; });
}

/// \copydoc Util::binary_to_base64()
std::string Util::binary_to_base64(const std::vector<BYTE> &binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<BYTE>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));
    return tmp.append((3 - binary_data.size() % 3) % 3, '=');
}

/// \copydoc Util::binary_to_hex()
std::string Util::binary_to_hex(const std::vector<BYTE> &binary_data)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto c : binary_data)
    {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

/// \copydoc Util::hex_to_binary()
std::vector<BYTE> Util::hex_to_binary(const std::string &hex_data)
{
    std::vector<BYTE> result;
    for (size_t i = 0; i < hex_data.length(); i += 2)
    {
        std::string byteString = hex_data.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
        result.push_back(byte);
    }
    return result;
}

/// \copydoc Util::binary_to_base64url()
std::string Util::binary_to_base64url(const std::vector<BYTE> &binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<BYTE>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));

    // For encoding to base64url, replace "+" with "-" and "/" with "_"
    boost::replace_all(tmp, "+", "-");
    boost::replace_all(tmp, "/", "_");

    // We do not need to add padding characters while url encoding.
    return tmp;
}

/// \copydoc Util::base64url_to_binary()
std::vector<BYTE> Util::base64url_to_binary(const std::string &base64_data)
{
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return base64_to_binary(stringData);
}

/// \copydoc Util::base64_decode()
std::string Util::base64_decode(const std::string &data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(data)), It(std::end(data))), [](char c)
                                                { return c == '\0'; });
}

/// \copydoc Util::url_encode()
std::string Util::url_encode(const std::string &data)
{
    std::string encoded_str{data};

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        TRACE_ERROR_EXIT("curl_easy_init() failed")
    }

    char *output = curl_easy_escape(curl, data.c_str(), data.length());
    if (output)
    {
        encoded_str = data;
        curl_free(output);
    }

    curl_easy_cleanup(curl);

    return encoded_str;
}

/// <summary>
/// Callback for curl perform operation.
/// </summary>
size_t Util::CurlWriteCallback(char *data, size_t size, size_t nmemb, std::string *buffer)
{
    size_t result = 0;
    if (buffer != NULL)
    {
        buffer->append(data, size * nmemb);
        result = size * nmemb;
    }
    return result;
}

/// Retrieve IMDS token retrieval URL for a resource url.
/// eg, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"};
static inline std::string GetImdsTokenUrl(std::string url)
{
    std::ostringstream oss;
    oss << Constants::IMDS_TOKEN_URL;
    oss << "?api-version=" << Constants::IMDS_API_VERSION;
    oss << "&resource=" << Util::url_encode(url);

    // Managed id is optional if there is only 1 client id registered for the VM.
    auto client_id = std::getenv("IMDS_CLIENT_ID");
    if (client_id != nullptr && strlen(client_id) > 0)
    {
        oss << "&client_id=" << client_id;
    }
    else
    {
        auto object_id = std::getenv("IMDS_OBJECT_ID");
        if (object_id != nullptr && strlen(object_id) > 0)
        {
            oss << "&object_id=" << object_id;
        }
        else
        {
            // If client id is not provided, msi_res_id (ARM resource id) could be provided.
            auto msi_res_id = std::getenv("IMDS_MSI_RES_ID");
            if (msi_res_id != nullptr && strlen(msi_res_id) > 0)
            {
                oss << "&msi_res_id=" << Util::url_encode(msi_res_id);
            }
        }
    }

    TRACE_OUT("IMDS token URL: %s", oss.str().c_str());
    return oss.str();
}

// Define a utility method to determine the resource URL based on KEKUrl
std::string getResourceUrl(const std::string &KEKUrl, bool isIMDS = true)
{
    // Constants for suffixes and corresponding resource URLs
    const std::string AKV_URL_SUFFIX = Constants::AKV_URL_SUFFIX;
    const std::string MHSM_URL_SUFFIX = Constants::MHSM_URL_SUFFIX;
    const std::string AKV_RESOURCE_URL = Constants::AKV_RESOURCE_URL;
    const std::string MHSM_RESOURCE_URL = Constants::MHSM_RESOURCE_URL;

    // Check if AKV suffix is present in KEKUrl
    if (KEKUrl.find(AKV_URL_SUFFIX) != std::string::npos)
    {
        TRACE_OUT("AKV resource suffix found in KEKUrl");
        return isIMDS ? AKV_RESOURCE_URL : AKV_RESOURCE_URL + "/.default";
    }
    // If AKV suffix is not found, check if MHSM suffix is present
    else if (KEKUrl.find(MHSM_URL_SUFFIX) != std::string::npos)
    {
        TRACE_OUT("MHSM resource suffix found in KEKUrl");
        return isIMDS ? MHSM_RESOURCE_URL : MHSM_RESOURCE_URL + "/.default";
    }
    // If neither AKV nor MHSM suffix is found, throw an error
    else
    {
        TRACE_ERROR_EXIT("Invalid resource suffix found in KEKUrl: " + KEKUrl)
    }
}

/// \copydoc Util::GetIMDSToken()
std::string Util::GetIMDSToken(const std::string &KEKUrl)
{
    TRACE_OUT("Entering Util::GetIMDSToken()");

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        TRACE_ERROR_EXIT("curl_easy_init() failed")
    }

    // AKV and mHSM has different audience need to be passed to IMDS.
    std::string resourceUrl = getResourceUrl(KEKUrl);
    CURLcode curlRet = curl_easy_setopt(curl, CURLOPT_URL, GetImdsTokenUrl(resourceUrl).c_str());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed")
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Metadata: true");
    curlRet = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed\n")
    }

    curlRet = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed")
    }

    std::string responseStr;
    curlRet = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStr);
    if (curlRet != CURLE_OK)
    {
        std::ostringstream oss;
        oss << "curl_easy_setopt() failed: " << curl_easy_strerror(curlRet);
        TRACE_ERROR_EXIT(oss.str().c_str())
    }

    curlRet = curl_easy_perform(curl);
    if (curlRet != CURLE_OK)
    {
        std::ostringstream oss;
        oss << "curl_easy_perform() failed: " << curl_easy_strerror(curlRet);
        TRACE_ERROR_EXIT(oss.str().c_str())
    }

    curl_easy_cleanup(curl);
    TRACE_OUT("Response: %s\n", Util::reduct_log(responseStr).c_str());
    json json_object = json::parse(responseStr.c_str());
    std::string access_token = json_object["access_token"].get<std::string>();

    TRACE_OUT("Access Token: %s\n", Util::reduct_log(access_token).c_str());

    TRACE_OUT("Exiting Util::GetIMDSToken()");

    return access_token;
}

/// \copydoc Util::GetAADToken()
std::string Util::GetAADToken(const std::string &KEKUrl)
{
    TRACE_OUT("Entering Util::GetAADToken()");

    auto clientId = std::getenv("AKV_SKR_CLIENT_ID");
    auto clientSecret = std::getenv("AKV_SKR_CLIENT_SECRET");
    auto tenantId = std::getenv("AKV_SKR_TENANT_ID");

    std::string resourceUrl = getResourceUrl(KEKUrl, false);
    std::string tokenUrl = "https://login.microsoftonline.com/" + std::string(tenantId) + "/oauth2/v2.0/token";
    std::string postData = "client_id=" + std::string(clientId) + "&client_secret=" + std::string(clientSecret) + "&grant_type=client_credentials&scope= " + resourceUrl;

    CURL *curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, tokenUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postData.length());

        curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode result = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (result == CURLE_OK)
        {
            std::string token;
            json jsonResponse = json::parse(response);
            if (jsonResponse.contains("access_token"))
            {
                token = jsonResponse["access_token"].get<std::string>();
            }
            else
            {
                TRACE_ERROR_EXIT("access_token not found in AAD auth response")
            }

            TRACE_OUT("Response: %s\n", token.c_str());
            TRACE_OUT("Exiting Util::GetAADToken()");
            return token;
        }
        else
        {
            TRACE_ERROR_EXIT("curl_easy_perform() failed for URL")
        }
    }
    else
    {
        TRACE_ERROR_EXIT("curl_easy_init() failed")
    }

    std::cerr << "Failed to obtain AKV AAD token" << std::endl;
    exit(-1);
}

/// \copydoc Util::GetMAAToken()
// TODO: attestation server URL can be constructed from VM region if necessary.
std::string Util::GetMAAToken(const std::string &attestation_url, const std::string &nonce)
{
    TRACE_OUT("Entering Util::GetMAAToken()");

    std::string attest_server_url;
    attest_server_url.assign(attestation_url);
    if (attest_server_url.empty())
    {
        // use the default attestation url
        attest_server_url.assign(Constants::DEFAULT_ATTESTATION_URL);
    }

    std::string nonce_token;
    nonce_token.assign(nonce);
    if (nonce_token.empty())
    {
        // use some random nonce
        nonce_token.assign(Constants::NONCE);
    }

    AttestationClient *attestation_client = nullptr;
    AttestationLogger *log_handle = new Logger(Util::get_trace());

    // Initialize attestation client
    if (!Initialize(log_handle, &attestation_client))
    {
        std::cerr << "Failed to create attestation client object" << std::endl;
        Uninitialize();
        exit(-1);
    }

    // parameters for the Attest call
    attest::ClientParameters params = {};
    params.attestation_endpoint_url = (PBYTE)attest_server_url.c_str();
    std::string client_payload_str = "{\"nonce\": \"" + nonce_token + "\"}"; // nonce is optional
    params.client_payload = (PBYTE)client_payload_str.c_str();
    params.version = CLIENT_PARAMS_VERSION;
    PBYTE jwt = nullptr;
    attest::AttestationResult result;

    bool is_cvm = false;
    bool attestation_success = true;
    std::string jwt_str;
    if ((result = attestation_client->Attest(params, &jwt)).code_ != attest::AttestationResult::ErrorCode::SUCCESS)
    {
        attestation_success = false;
    }

    if (attestation_success)
    {
        jwt_str = std::string(reinterpret_cast<char *>(jwt));
        std::vector<std::string> tokens;
        boost::split(tokens, jwt_str, [](char c)
                     { return c == '.'; });
        if (tokens.size() < 3)
        {
            std::cerr << "Invalid JWT token" << std::endl;
            exit(-1);
        }

        json attestation_claims = json::parse(base64_decode(tokens[1]));
        try
        {
            std::string attestation_type = attestation_claims["x-ms-isolation-tee"]["x-ms-attestation-type"].get<std::string>();
            std::string compliance_status = attestation_claims["x-ms-isolation-tee"]["x-ms-compliance-status"].get<std::string>();
            if (boost::iequals(attestation_type, "sevsnpvm") &&
                boost::iequals(compliance_status, "azure-compliant-cvm"))
            {
                is_cvm = true;
            }
        }
        catch (...)
        {
        } // sevsnp claim does not exist in the token

        attestation_client->Free(jwt);
        Uninitialize();
    }

    TRACE_OUT("Exiting Util::GetMAAToken()");
    return jwt_str;
}

/// \copydoc Util::SplitString()
std::vector<std::string> Util::SplitString(const std::string &str, char delim)
{
    TRACE_OUT("Entering Util::SplitString()");

    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        result.push_back(item);
    }

    TRACE_OUT("Exiting Util::SplitString()");
    return result;
}

/// Get the modulus size in bytes of RSA key.
int RSA_get_size(EVP_PKEY *pkey)
{
    int rsaModulusSize = 0;
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    // It is OSSL >= 3.0
    // TODO: investigate why EVP_PKEY_get_size causes SIGSEGV in OSSL 3.0
    // rsaModulusSize = EVP_PKEY_get_size(pkey);

    // fallback to deprecated API until above issue is resolved.
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    rsaModulusSize = RSA_size(rsa);
#else
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    rsaModulusSize = RSA_size(rsa);
#endif

    return rsaModulusSize;
}

/// handle openssl errors
static void handle_openssl_errors(void)
{
    TRACE_OUT("Entering handle_openssl_errors()");

    std::cerr << "Error in OpenSSL" << std::endl;
    ERR_print_errors_fp(stderr);

    unsigned long error;
    while ((error = ERR_get_error()))
    {
        char error_str[120]{};
        ERR_error_string_n(error, error_str, sizeof(error_str));
        std::cerr << "Error: " << error_str << std::endl;
    }

    TRACE_OUT("Exiting handle_openssl_errors()");
    exit(-1);
}

/// Decrypt ciphertext using the key
static int decrypt_aes_key_unwrap(PBYTE key, PBYTE ciphertext, int ciphertext_len, PBYTE plaintext)
{
    TRACE_OUT("Entering decrypt_aes_key_unwrap()");

    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_openssl_errors();

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    /* Initialise the decryption operation. */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, NULL, NULL))
        handle_openssl_errors();
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
        handle_openssl_errors();

    // Set padding to PKCS#8
    /*if (1 != EVP_CIPHER_CTX_set_padding(ctx, 1)) {
        handle_openssl_errors();
    }*/

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_openssl_errors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_openssl_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    TRACE_OUT("Exiting decrypt_aes_key_unwrap()");
    return plaintext_len;
}

// Construct URL for secure key release.
// Format: https://<keyvaultname>.vault.azure.net/keys/<keyname>/<keyversion>/release?api-version=7.3
std::string Util::GetKeyVaultSKRurl(const std::string &KEKUrl)
{
    TRACE_OUT("Entering Util::GetKeyVaultSKRurl()");

    std::ostringstream requestUri;
    requestUri << KEKUrl;
    requestUri << "/"
               << "release";
    requestUri << "?"
               << "api-version";
    requestUri << "="
               << "7.3";
    TRACE_OUT("Request URI: %s\n", requestUri.str().c_str());

    TRACE_OUT("Exiting Util::GetKeyVaultSKRurl()");
    return requestUri.str();
}

std::string Util::GetKeyVaultResponse(const std::string &requestUri,
                                      const std::string &access_token,
                                      const std::string &attestation_token,
                                      const std::string &nonce)
{
    TRACE_OUT("Entering Util::GetKeyVaultResponse()");

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        TRACE_ERROR_EXIT("curl_easy_init() failed")
    }

    CURLcode curlRet = curl_easy_setopt(curl, CURLOPT_URL, requestUri.c_str());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for URL")
    }
    curlRet = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for POST")
    }

    curlRet = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for HTTP_VERSION")
    }

    struct curl_slist *headers = NULL;
    std::ostringstream bearerToken;
    bearerToken << "Authorization: Bearer " << access_token;
    headers = curl_slist_append(headers, bearerToken.str().c_str());
    TRACE_OUT("Bearer token: %s", Util::reduct_log(bearerToken.str()).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "User-Agent: AzureDiskEncryption");
    curlRet = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed\n")
    }

    std::ostringstream requestBody;

    std::string nonce_token;
    nonce_token.assign(nonce);
    if (nonce_token.empty())
    {
        // use some random nonce
        nonce_token.assign(Constants::NONCE);
    }

    requestBody << "{";
    requestBody << "\"nonce\": \"" + nonce_token + "\",";
    requestBody << "\"target\": \"" << attestation_token << "\",";
    requestBody << "\"enc\": \"CKM_RSA_AES_KEY_WRAP\"";
    requestBody << "}";
    std::string requestBodyStr(requestBody.str());
    // TRACE_OUT("requestBody: size=%d, '%s'", requestBodyStr.size(), requestBodyStr.c_str());
    curlRet = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBodyStr.c_str());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_POSTFIELDS\n")
    }
    curlRet = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)requestBodyStr.size());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_POSTFIELDSIZE\n")
    }

    // Enable verbose output from curl for debugging.
    /*
    curlRet = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_VERBOSE\n")
    }
    */

    char errbuf[CURL_ERROR_SIZE] = {
        0,
    };

    curlRet = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    if (curlRet != CURLE_OK)
    {
        size_t len = strlen(errbuf);
        std::cerr << "libcurl: " << curlRet << std::endl;
        if (len)
            std::cerr << errbuf << (errbuf[len - 1] != '\n') ? "\n" : "";
        std::cerr << curl_easy_strerror(curlRet) << std::endl;

        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_ERRORBUFFER\n")
    }

    // DEBUG only, when a proxy is needed such as Fiddler.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curlRet = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed")
    }

#ifndef PLATFORM_UNIX
    curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
#endif

    std::string responseStr;
    curlRet = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStr);
    if (curlRet != CURLE_OK)
    {
        std::ostringstream oss;
        oss << "curl_easy_setopt() failed: " << curl_easy_strerror(curlRet);
        TRACE_ERROR_EXIT(oss.str().c_str())
    }

    // Perform the request, check the return code
    curlRet = curl_easy_perform(curl);
    // Check for errors
    if (curlRet != CURLE_OK)
    {
        std::ostringstream oss;
        oss << "curl_easy_perform() failed: " << curl_easy_strerror(curlRet);
        TRACE_ERROR_EXIT(oss.str().c_str())
    }
    /*
    switch (code) {
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_CONNECT:
    case CURLE_WRITE_ERROR:
        STATSCOUNTER_INC(indexConFail, mutIndexConFail);
        return RS_RET_SUSPENDED;
    default:
        STATSCOUNTER_INC(indexSubmit, mutIndexSubmit);
        return RS_RET_OK;
    }
    */

    // Cleanup curl
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    TRACE_OUT("SKR response: %s", Util::reduct_log(responseStr).c_str());
    TRACE_OUT("Exiting Util::GetKeyVaultResponse()");
    return responseStr;
}

bool Util::doSKR(const std::string &attestation_url,
                 const std::string &nonce,
                 std::string KEKUrl,
                 EVP_PKEY **pkey,
                 const Util::AkvCredentialSource &akv_credential_source)
{
    TRACE_OUT("Entering Util::doSKR()");

    try
    {
        std::string attest_token(Util::GetMAAToken(attestation_url, nonce));
        TRACE_OUT("MAA Token: %s", Util::reduct_log(attest_token).c_str());

        // Get Akv access token either using IMDS or Service Principal
        std::string access_token;
        if (akv_credential_source == Util::AkvCredentialSource::EnvServicePrincipal)
        {
            access_token = std::move(Util::GetAADToken(KEKUrl));
        }
        else
        {
            access_token = std::move(Util::GetIMDSToken(KEKUrl));
        }

        TRACE_OUT("AkvMsiAccessToken: %s", Util::reduct_log(access_token).c_str());

        std::string requestUri = Util::GetKeyVaultSKRurl(KEKUrl);
        std::string responseStr = Util::GetKeyVaultResponse(requestUri, access_token, attest_token, nonce);

        // Parse the response:
        json skrJson = json::parse(responseStr.c_str());
        std::string skrToken = skrJson["value"];
        TRACE_OUT("SKR token: %s", Util::reduct_log(skrToken).c_str());
        std::vector<std::string> tokenParts = Util::SplitString(skrToken, '.');
        if (tokenParts.size() != 3)
        {
            TRACE_ERROR_EXIT("Invalid SKR token")
        }

        std::vector<BYTE> tokenPayload(Util::base64url_to_binary(tokenParts[1]));
        std::string tokenPayloadStr(tokenPayload.begin(), tokenPayload.end());
        TRACE_OUT("SKR token payload: %s", Util::reduct_log(tokenPayloadStr).c_str());
        json skrPayloadJson = json::parse(tokenPayloadStr.c_str());
        std::vector<BYTE> key_hsm = Util::base64url_to_binary(skrPayloadJson["response"]["key"]["key"]["key_hsm"]);
        TRACE_OUT("SKR key_hsm: %s", Util::reduct_log(Util::binary_to_base64url(key_hsm)).c_str());
        json cipherTextJson = json::parse(key_hsm);
        std::vector<BYTE> cipherText = Util::base64url_to_binary(cipherTextJson["ciphertext"]);
        TRACE_OUT("Encrypted bytes length: %ld", cipherText.size());
        std::string cipherTextStr(cipherText.begin(), cipherText.end());
        TRACE_OUT("Encrypted bytes: %s", Util::reduct_log(Util::binary_to_base64url(cipherText)).c_str());

        AttestationClient *attestation_client = nullptr;
        AttestationLogger *log_handle = new Logger(Util::get_trace());

        // Initialize attestation client
        if (!Initialize(log_handle, &attestation_client))
        {
            printf("Failed to create attestation client object\n");
            Uninitialize();
            exit(1);
        }
        // gsl::span<const BYTE> payload = { cipherText + headerSize, cipherText - headerSize };

        attest::AttestationResult result;
        int RSASize = 2048;
        int ModulusSize = RSASize / 8;
        uint8_t *decryptedAESBytes = nullptr;
        uint32_t decryptedBytesSize = 0;
        result = attestation_client->Decrypt(attest::EncryptionType::NONE,
                                             cipherText.data(),
                                             ModulusSize,
                                             NULL,
                                             0,
                                             &decryptedAESBytes,
                                             &decryptedBytesSize,
                                             attest::RsaScheme::RsaOaep, // mHSM uses RSA-OAEP wrapping
                                             attest::RsaHashAlg::RsaSha1 // mHSM uses SHA1 hashing
        );
        if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS)
        {
            printf("Failed to decrypt the AES key. Error code: %d, TPM error code=%d, Desc=%s\n", static_cast<int>(result.code_), result.tpm_error_code_, result.description_.c_str());
            exit(1);
        }
        else
        {
            std::vector<BYTE> decryptedAESBytesVec(decryptedAESBytes, decryptedAESBytes + decryptedBytesSize);
            TRACE_OUT("Decrypted Transfer key: %s\n", Util::reduct_log(Util::binary_to_base64url(decryptedAESBytesVec)).c_str());
        }

        // The remaining bytes are the encrypted CMK bytes with the decrypted AES key.
        // use openssl AES to decrypt the CMK bytes.
        BYTE private_key[8192];
        int private_key_len = 0;
        private_key_len = decrypt_aes_key_unwrap(decryptedAESBytes,
                                                 cipherText.data() + ModulusSize,
                                                 (int)(cipherText.size() - ModulusSize),
                                                 private_key);
        if (private_key_len == 0)
        {
            printf("Failed to decrypt the CMK\n");
            exit(1);
        }
        else
        {
            TRACE_OUT("CMK private key has length=%d", private_key_len);
            std::vector<BYTE> privateKeyVec(private_key, private_key + private_key_len);
            TRACE_OUT("Decrypted CMK in base64url: %s", Util::reduct_log(Util::binary_to_base64url(privateKeyVec)).c_str());
            TRACE_OUT("Decrypted CMK in hex: %s", Util::reduct_log(Util::binary_to_hex(privateKeyVec)).c_str());

            // PKCS#8
            BIO *bio_key = BIO_new_mem_buf(privateKeyVec.data(), (int)privateKeyVec.size());
            if (!bio_key)
            {
                std::cerr << "Error creating memory BIO" << std::endl;
                exit(-1);
            }
            *pkey = d2i_PrivateKey_bio(bio_key, NULL);
            if (!*pkey)
            {
                // error handling
                std::cout << "Failed to load the priv key" << std::endl;
                ERR_print_errors_fp(stderr);

                // input data is not in correct format
                char buf[120];
                ERR_error_string(ERR_get_error(), buf);
                printf("PKCS8 format check failed: %s\n", buf);
                exit(-1);
            }
            BIO_free(bio_key);

            return true;
        }

        // Cleanup
        Uninitialize();
        delete log_handle;
        log_handle = nullptr;
    }
    catch (std::exception &e)
    {
        printf("Exception occured. Details - %s", e.what());
        exit(1);
    }

    TRACE_OUT("Exiting Util::doSKR()");
    return true;
}

// A helper function to handle errors
void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// A function that encrypts a message with a public key using EVP_PKEY_encrypt
int rsa_encrypt(EVP_PKEY *pkey, const PBYTE msg, size_t msglen, PBYTE *enc, size_t *enclen)
{
    TRACE_OUT("Entering rsa_encrypt()");

    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;

    // Create the context for the encryption operation
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        handleErrors();

    // Initialize the encryption operation
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        handleErrors();

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
        // TODO: investiagate why setting padding and md algorithms causing SIGSEGV in OSSL 3.x
#else
    // Set the RSA padding mode to either PKCS #1 OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleErrors();

    // Set RSA signature scheme to SHA256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        handleErrors();
#endif
    // Determine the buffer length for the encrypted data
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, msg, msglen) <= 0)
        handleErrors();

    // Allocate memory for the encrypted data
    *enc = (PBYTE)OPENSSL_malloc(outlen);
    if (!*enc)
        handleErrors();

    // Perform the encryption operation
    if (EVP_PKEY_encrypt(ctx, *enc, &outlen, msg, msglen) <= 0)
        handleErrors();

    // Set the encrypted data length
    *enclen = outlen;

    // Clean up and return success
    ret = 0;
    EVP_PKEY_CTX_free(ctx);

    TRACE_OUT("Exiting rsa_encrypt()");
    return ret;
}

// A function that encrypts a message with a public key using EVP_PKEY_encrypt
int rsa_decrypt(EVP_PKEY *pkey, const PBYTE msg, size_t msglen, PBYTE *dec, size_t *declen)
{
    TRACE_OUT("Entering rsa_decrypt()");

    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;

    // Create the context for the encryption operation
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        handleErrors();

    // Initialize the encryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handleErrors();

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
        // TODO: investiagate why setting padding and md algorithms causing SIGSEGV in OSSL 3.x
#else
    // Set the RSA padding mode to PKCS #1 OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleErrors();

    // Set RSA signature scheme to SHA256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) // TODO: can be a parameter
        handleErrors();
#endif

    // Determine the buffer length for the encrypted data
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, msg, msglen) <= 0)
        handleErrors();

    // Allocate memory for the encrypted data
    *dec = (PBYTE)OPENSSL_malloc(outlen);
    if (!*dec)
        handleErrors();

    // Perform the encryption operation
    if (EVP_PKEY_decrypt(ctx, *dec, &outlen, msg, msglen) <= 0)
        handleErrors();

    // Set the encrypted data length
    *declen = outlen;

    // Clean up and return success
    ret = 0;
    EVP_PKEY_CTX_free(ctx);

    TRACE_OUT("Exiting rsa_decrypt()");
    return ret;
}

std::string Util::WrapKey(const std::string &attestation_url,
                          const std::string &nonce,
                          const std::string &sym_key,
                          const std::string &key_enc_key_url,
                          const Util::AkvCredentialSource &akv_credential_source)
{
    TRACE_OUT("Entering Util::WrapKey()");

    EVP_PKEY *pkey = nullptr;
    if (!Util::doSKR(attestation_url, nonce, key_enc_key_url, &pkey, akv_credential_source))
    {
        std::cerr << "Failed to release the private key" << std::endl;
        exit(-1);
    }
    int pkeyBaseId = EVP_PKEY_base_id(pkey);
    TRACE_OUT("Key release completed successfully. EVP_PKEY_base_id=%d", pkeyBaseId);

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey^M
    if (pkeyBaseId != EVP_PKEY_RSA /* PKCS1 */ &&
        pkeyBaseId != EVP_PKEY_RSA2 /* X500 */)
    {
        std::cerr << "The key is not of type RSA. Only RSA keys are supported for wrapKey/unwrapKey" << std::endl;
        exit(-1);
    }

    int rsaSize = RSA_get_size(pkey);
    TRACE_OUT("Wrapping: %s", Util::reduct_log(sym_key).c_str());

    size_t encrypted_length = 0;
    PBYTE encryptedKey;
    if (rsa_encrypt(pkey, (const PBYTE)sym_key.c_str(), sym_key.size(), &encryptedKey, &encrypted_length) == -1)
    {
        std::cerr << "Failed to wrap the symmetric key: " << std::endl;
        handle_openssl_errors();
        exit(-1);
    }

    TRACE_OUT("Wrapping the symmetric key succeeded: encrypted_length=%ld\n", encrypted_length);
    std::vector<BYTE> encryptedKeyVector(encryptedKey, encryptedKey + encrypted_length);
    std::string cipherText = Util::binary_to_base64(encryptedKeyVector);
    TRACE_OUT("Wrapped symmetric key in base64: %s\n", Util::reduct_log(cipherText).c_str());

    // Cleanup
    OPENSSL_free(encryptedKey);
    EVP_PKEY_free(pkey);

    TRACE_OUT("Exiting Util::WrapKey()");
    return cipherText;
}

std::string Util::UnwrapKey(const std::string &attestation_url,
                            const std::string &nonce,
                            const std::string &wrapped_key_base64,
                            const std::string &key_enc_key_url,
                            const Util::AkvCredentialSource &akv_credential_source)
{
    TRACE_OUT("Entering Util::UnwrapKey()");

    EVP_PKEY *pkey = nullptr;
    if (!Util::doSKR(attestation_url, nonce, key_enc_key_url, &pkey, akv_credential_source))
    {
        std::cerr << "Failed to release the private key" << std::endl;
        exit(-1);
    }
    int pkeyBaseId = EVP_PKEY_base_id(pkey);
    TRACE_OUT("Key release completed successfully. EVP_PKEY_base_id=%d", pkeyBaseId);

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey^M
    if (pkeyBaseId != EVP_PKEY_RSA /* PKCS1 */ &&
        pkeyBaseId != EVP_PKEY_RSA2 /* X500 */)
    {
        std::cerr << "The key is not of type RSA. Only RSA keys are supported for wrapKey/unwrapKey" << std::endl;
        exit(-1);
    }

    int rsaSize = RSA_get_size(pkey);
    TRACE_OUT("Unwrapping: %s\n", wrapped_key_base64.c_str());
    std::vector<BYTE> wrapped_key = Util::base64_to_binary(wrapped_key_base64);

    size_t decrypted_length = 0;
    PBYTE decryptedKey;
    if (rsa_decrypt(pkey, wrapped_key.data(), wrapped_key.size(), &decryptedKey, &decrypted_length) == -1)
    {
        std::cerr << "Failed to unwrap the symmetric key: " << std::endl;
        handle_openssl_errors();
        exit(-1);
    }

    TRACE_OUT("Unwrapping the symmetric key succeeded: decrypted_length=%lud", decrypted_length);
    std::vector<BYTE> decryptedKeyVector(decryptedKey, decryptedKey + decrypted_length);
    std::string plainText = Util::binary_to_base64(decryptedKeyVector);
    TRACE_OUT("Unwrapped symmetric key in base64: %s", Util::reduct_log(plainText).c_str());

    TRACE_OUT("Exiting Util::UnwrapKey()");

    // Cleanup
    OPENSSL_free(decryptedKey);
    EVP_PKEY_free(pkey);

    return Util::base64_decode(plainText);
}

bool Util::ReleaseKey(const std::string &attestation_url,
                      const std::string &nonce,
                      const std::string &key_enc_key_url,
                      const Util::AkvCredentialSource &akv_credential_source)
{
    TRACE_OUT("Entering Util::ReleaseKey()");

    EVP_PKEY *pkey = nullptr;
    if (!Util::doSKR(attestation_url, nonce, key_enc_key_url, &pkey, akv_credential_source))
    {
        std::cerr << "Failed to release the private key" << std::endl;
        return false;
    }

    TRACE_OUT("Key release completed successfully.");

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey
    switch (EVP_PKEY_base_id(pkey))
    {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        std::cout << "The released key is of type RSA. It can be used for wrapKey/unwrapKey operations." << std::endl;
        return true;
    case EVP_PKEY_EC:
        std::cout << "The released key is of type EC. It can be used for sign/verify operations." << std::endl;
        return true;
    default:
        std::cout << "The released key is of type " << EVP_PKEY_base_id(pkey) << ". Not sure what operations are supported." << std::endl;
        return false;
    }
}