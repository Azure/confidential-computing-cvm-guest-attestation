//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationUtil.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
//

// TODO: Use OPENSSL_cleanse(buffer, sizeof(buffer)) to clear sensitive data from memory.

#ifdef _MSC_VER
#pragma warning(disable : 4996) // suppress MSVC deprecation warning for std::getenv
#endif

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

#ifdef _WIN32
#include <winhttp.h>
#endif

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
        THROW_SKR_ERROR(EXIT_USAGE, std::string("Invalid resource suffix found in KEKUrl: " + KEKUrl))
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

    // ByPassing proxy for IMDS.
    // ref: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=windows
    curlRet = curl_easy_setopt(curl, CURLOPT_PROXY, "");
    if (curlRet != CURLE_OK)
    {
        std::ostringstream oss;
        oss << "curl_easy_setopt() failed: " << curl_easy_strerror(curlRet);
        TRACE_ERROR_EXIT(oss.str().c_str())
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
        std::string msg = std::string("IMDS curl_easy_perform() failed: ") + curl_easy_strerror(curlRet);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        throw skr_error(EXIT_NETWORK_FAIL, msg);
    }

    // Check HTTP status code
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    TRACE_OUT("IMDS HTTP status: %ld, Response: %s", http_code, Util::reduct_log(responseStr).c_str());

    if (http_code != 200)
    {
        // Try to extract the error_description from the IMDS error JSON
        std::string detail = responseStr;
        try
        {
            json errJson = json::parse(responseStr);
            if (errJson.contains("error_description"))
                detail = errJson["error_description"].get<std::string>();
            else if (errJson.contains("error"))
                detail = errJson["error"].get<std::string>();
        }
        catch (...) {} // use raw response if not JSON
        std::ostringstream oss;
        oss << "IMDS token request failed: HTTP " << http_code << ": " << detail;
        throw skr_error(EXIT_AUTH_FAIL, oss.str());
    }

    json json_object = json::parse(responseStr.c_str());
    if (!json_object.contains("access_token"))
    {
        throw skr_error(EXIT_AUTH_FAIL,
                        "IMDS response missing 'access_token' field: " + responseStr);
    }
    std::string access_token = json_object["access_token"].get<std::string>();

    TRACE_OUT("Access Token: %s", Util::reduct_log(access_token).c_str());
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

    if (!clientId || !clientSecret || !tenantId)
    {
        throw skr_error(EXIT_AUTH_FAIL,
                        "AAD service principal env vars not set. "
                        "Need AKV_SKR_CLIENT_ID, AKV_SKR_CLIENT_SECRET, AKV_SKR_TENANT_ID");
    }

    std::string resourceUrl = getResourceUrl(KEKUrl, false);
    std::string tokenUrl = "https://login.microsoftonline.com/" + std::string(tenantId) + "/oauth2/v2.0/token";
    std::string postData = "client_id=" + std::string(clientId) + "&client_secret=" + std::string(clientSecret) + "&grant_type=client_credentials&scope= " + resourceUrl;

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        throw skr_error(EXIT_NETWORK_FAIL, "AAD: curl_easy_init() failed");
    }

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
    if (result != CURLE_OK)
    {
        std::string msg = std::string("AAD curl_easy_perform() failed: ") + curl_easy_strerror(result);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        throw skr_error(EXIT_NETWORK_FAIL, msg);
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    TRACE_OUT("AAD HTTP status: %ld, Response: %s", http_code, Util::reduct_log(response).c_str());

    json jsonResponse = json::parse(response);
    if (jsonResponse.contains("access_token"))
    {
        std::string token = jsonResponse["access_token"].get<std::string>();
        TRACE_OUT("Response: %s", Util::reduct_log(token).c_str());
        TRACE_OUT("Exiting Util::GetAADToken()");
        return token;
    }

    // No access_token — extract the AAD error details
    std::string detail = response;
    if (jsonResponse.contains("error_description"))
        detail = jsonResponse["error_description"].get<std::string>();
    else if (jsonResponse.contains("error"))
        detail = jsonResponse["error"].get<std::string>();

    std::ostringstream oss;
    oss << "AAD token request failed: HTTP " << http_code << ": " << detail;
    throw skr_error(EXIT_AUTH_FAIL, oss.str());
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
        Uninitialize();
        throw skr_error(EXIT_ATTEST_FAIL, "Failed to create attestation client object");
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
    std::string jwt_str;
    if ((result = attestation_client->Attest(params, &jwt)).code_ != attest::AttestationResult::ErrorCode::SUCCESS)
    {
        std::string errDesc = result.description_.empty() ? "(no description)" : result.description_;
        fprintf(stderr, "MAA attestation failed: error code %d, description: %s\n",
                static_cast<int>(result.code_), errDesc.c_str());
        Uninitialize();
        throw skr_error(EXIT_ATTEST_FAIL, "MAA attestation failed: " + errDesc);
    }

    // Attestation succeeded
    jwt_str = std::string(reinterpret_cast<char *>(jwt));
    std::vector<std::string> tokens;
    boost::split(tokens, jwt_str, [](char c)
                 { return c == '.'; });
    if (tokens.size() < 3)
    {
        attestation_client->Free(jwt);
        Uninitialize();
        throw skr_error(EXIT_ATTEST_FAIL, "MAA returned invalid JWT token (fewer than 3 parts)");
    }

    json attestation_claims = json::parse(base64_decode(tokens[1]));
    try
    {
        std::string attestation_type = attestation_claims["x-ms-isolation-tee"]["x-ms-attestation-type"].get<std::string>();
        std::string compliance_status = attestation_claims["x-ms-isolation-tee"]["x-ms-compliance-status"].get<std::string>();
        if ((boost::iequals(attestation_type, "sevsnpvm") ||
             boost::iequals(attestation_type, "tdxvm")) &&
            boost::iequals(compliance_status, "azure-compliant-cvm"))
        {
            is_cvm = true;
        }
    }
    catch (...)
    {
        TRACE_OUT("TEE isolation claims not found in token (non-CVM or different token schema)");
    }

    attestation_client->Free(jwt);
    Uninitialize();

    TRACE_OUT("MAA attestation succeeded, is_cvm=%d, token length=%zu", is_cvm, jwt_str.length());

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

/// handle openssl errors
static void handle_openssl_errors(void)
{
    TRACE_OUT("Entering handle_openssl_errors()");

    std::ostringstream oss;
    oss << "OpenSSL error: ";
    ERR_print_errors_fp(stderr);

    unsigned long error;
    while ((error = ERR_get_error()))
    {
        char error_str[120]{};
        ERR_error_string_n(error, error_str, sizeof(error_str));
        oss << error_str << "; ";
    }

    TRACE_OUT("Exiting handle_openssl_errors()");
    throw skr_error(EXIT_CRYPTO_FAIL, oss.str());
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
    TRACE_OUT("Request URI: %s", requestUri.str().c_str());

    TRACE_OUT("Exiting Util::GetKeyVaultSKRurl()");
    return requestUri.str();
}

#ifdef _WIN32
/// <summary>
/// Windows-specific implementation of the SKR HTTP POST using WinHTTP.
/// WinHTTP is the preferred HTTP client on Windows — it supports system proxy
/// settings, Kerberos/NTLM auth, and does not require shipping a CA bundle.
/// </summary>
static std::string GetKeyVaultResponseWinHttp(const std::string &requestUri,
                                              const std::string &access_token,
                                              const std::string &requestBodyStr)
{
    TRACE_OUT("Entering GetKeyVaultResponseWinHttp()");

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string responseStr;

    try
    {
        // Parse the URL to extract host and path components
        URL_COMPONENTS urlComp = {0};
        urlComp.dwStructSize = sizeof(urlComp);

        WCHAR szHostName[256] = {0};
        WCHAR szUrlPath[1024] = {0};

        urlComp.lpszHostName = szHostName;
        urlComp.dwHostNameLength = sizeof(szHostName) / sizeof(WCHAR);
        urlComp.lpszUrlPath = szUrlPath;
        urlComp.dwUrlPathLength = sizeof(szUrlPath) / sizeof(WCHAR);

        // Convert URI to wide string
        std::wstring wRequestUri(requestUri.begin(), requestUri.end());
        TRACE_OUT("Cracking URL: %s", requestUri.c_str());

        if (!WinHttpCrackUrl(wRequestUri.c_str(), (DWORD)wRequestUri.length(), 0, &urlComp))
        {
            std::ostringstream oss;
            oss << "WinHttpCrackUrl failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Initialize WinHTTP session
        hSession = WinHttpOpen(L"AzureDiskEncryption/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME,
                               WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
        {
            std::ostringstream oss;
            oss << "WinHttpOpen failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Connect to the server
        hConnect = WinHttpConnect(hSession, szHostName, urlComp.nPort, 0);
        if (!hConnect)
        {
            std::ostringstream oss;
            oss << "WinHttpConnect failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Create an HTTP POST request
        DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(hConnect, L"POST", szUrlPath, NULL,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
        if (!hRequest)
        {
            std::ostringstream oss;
            oss << "WinHttpOpenRequest failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Add headers individually to avoid issues with very long bearer tokens
        std::string authHeader = "Authorization: Bearer " + access_token;
        std::wstring wAuthHeader(authHeader.begin(), authHeader.end());
        if (!WinHttpAddRequestHeaders(hRequest, wAuthHeader.c_str(), (DWORD)wAuthHeader.length(), WINHTTP_ADDREQ_FLAG_ADD))
        {
            std::ostringstream oss;
            oss << "WinHttpAddRequestHeaders (Authorization) failed: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        if (!WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD))
        {
            std::ostringstream oss;
            oss << "WinHttpAddRequestHeaders (Content-Type) failed: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        if (!WinHttpAddRequestHeaders(hRequest, L"Accept: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD))
        {
            std::ostringstream oss;
            oss << "WinHttpAddRequestHeaders (Accept) failed: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        if (!WinHttpAddRequestHeaders(hRequest, L"User-Agent: AzureDiskEncryption", -1, WINHTTP_ADDREQ_FLAG_ADD))
        {
            std::ostringstream oss;
            oss << "WinHttpAddRequestHeaders (User-Agent) failed: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        TRACE_OUT("HTTP headers added, sending request with body length: %d", (int)requestBodyStr.length());

        // Send the request
        BOOL bResults = WinHttpSendRequest(hRequest,
                                           WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                           (LPVOID)requestBodyStr.c_str(), (DWORD)requestBodyStr.length(),
                                           (DWORD)requestBodyStr.length(), 0);
        if (!bResults)
        {
            std::ostringstream oss;
            oss << "WinHttpSendRequest failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Wait for the response
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults)
        {
            std::ostringstream oss;
            oss << "WinHttpReceiveResponse failed with error: " << GetLastError();
            TRACE_ERROR_EXIT(oss.str().c_str())
        }

        // Check the HTTP status code
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

        // Read the response body
        DWORD dwDownloaded = 0;
        do
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                std::ostringstream oss;
                oss << "WinHttpQueryDataAvailable failed with error: " << GetLastError();
                TRACE_ERROR_EXIT(oss.str().c_str())
            }

            if (dwSize > 0)
            {
                char szBuffer[8192] = {0};
                DWORD dwToRead = (dwSize < sizeof(szBuffer) - 1) ? dwSize : (DWORD)(sizeof(szBuffer) - 1);
                if (!WinHttpReadData(hRequest, szBuffer, dwToRead, &dwDownloaded))
                {
                    std::ostringstream oss;
                    oss << "WinHttpReadData failed with error: " << GetLastError();
                    TRACE_ERROR_EXIT(oss.str().c_str())
                }
                szBuffer[dwDownloaded] = '\0';
                responseStr.append(szBuffer, dwDownloaded);
            }
        } while (dwSize > 0);

        TRACE_OUT("HTTP status=%d, response: %s", dwStatusCode, Util::reduct_log(responseStr).c_str());

        if (dwStatusCode != 200)
        {
            std::ostringstream oss;
            oss << "SKR HTTP request failed: HTTP " << dwStatusCode << ": " << responseStr;
            throw skr_error(EXIT_SKR_FAIL, oss.str());
        }
    }
    catch (...)
    {
        // Cleanup on exception and re-throw
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        throw;
    }

    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    TRACE_OUT("Exiting GetKeyVaultResponseWinHttp()");
    return responseStr;
}
#endif // _WIN32

#ifndef _WIN32
/// <summary>
/// Linux (and non-Windows) implementation of the SKR HTTP POST using libcurl.
/// </summary>
static std::string GetKeyVaultResponseCurl(const std::string &requestUri,
                                           const std::string &access_token,
                                           const std::string &requestBodyStr)
{
    TRACE_OUT("Entering GetKeyVaultResponseCurl()");

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
        TRACE_ERROR_EXIT("curl_easy_setopt() failed")
    }

    curlRet = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBodyStr.c_str());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_POSTFIELDS")
    }
    curlRet = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)requestBodyStr.size());
    if (curlRet != CURLE_OK)
    {
        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_POSTFIELDSIZE")
    }

    char errbuf[CURL_ERROR_SIZE] = {0};
    curlRet = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    if (curlRet != CURLE_OK)
    {
        size_t len = strlen(errbuf);
        std::cerr << "libcurl: " << curlRet << std::endl;
        if (len)
            std::cerr << errbuf << ((errbuf[len - 1] != '\n') ? "\n" : "");
        std::cerr << curl_easy_strerror(curlRet) << std::endl;

        TRACE_ERROR_EXIT("curl_easy_setopt() failed for CURLOPT_ERRORBUFFER")
    }

    curlRet = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Util::CurlWriteCallback);
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

    // Perform the request
    curlRet = curl_easy_perform(curl);
    if (curlRet != CURLE_OK)
    {
        std::string msg = std::string("SKR curl_easy_perform() failed: ") + curl_easy_strerror(curlRet);
        if (strlen(errbuf))
            msg += std::string(" (") + errbuf + ")";
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        throw skr_error(EXIT_NETWORK_FAIL, msg);
    }

    // Check HTTP status — AKV/MHSM errors (403, 404, etc.) come back as valid HTTP responses
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    // Cleanup curl
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    TRACE_OUT("SKR HTTP status: %ld, response: %s", http_code, Util::reduct_log(responseStr).c_str());

    if (http_code != 200)
    {
        std::ostringstream oss;
        oss << "SKR HTTP request failed: HTTP " << http_code << ": " << responseStr;
        throw skr_error(EXIT_SKR_FAIL, oss.str());
    }

    TRACE_OUT("Exiting GetKeyVaultResponseCurl()");
    return responseStr;
}
#endif // !_WIN32

std::string Util::GetKeyVaultResponse(const std::string &requestUri,
                                      const std::string &access_token,
                                      const std::string &attestation_token,
                                      const std::string &nonce)
{
    TRACE_OUT("Entering Util::GetKeyVaultResponse()");

    std::string nonce_token;
    nonce_token.assign(nonce);
    if (nonce_token.empty())
    {
        // use some random nonce
        nonce_token.assign(Constants::NONCE);
    }

    // Build the JSON request body (shared across both implementations)
    // RSA_AES_KEY_WRAP_256 uses RSA-OAEP with SHA-256 for the transfer key,
    // upgrading from CKM_RSA_AES_KEY_WRAP which used SHA-1.
    // See: https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release
    std::ostringstream requestBody;
    requestBody << "{";
    requestBody << "\"nonce\": \"" + nonce_token + "\",";
    requestBody << "\"target\": \"" << attestation_token << "\",";
    requestBody << "\"enc\": \"RSA_AES_KEY_WRAP_256\"";
    requestBody << "}";
    std::string requestBodyStr(requestBody.str());
    TRACE_OUT("SKR wrapping algorithm: RSA_AES_KEY_WRAP_256 (RSA-OAEP-SHA256)");

    TRACE_OUT("SKR request URI: %s", requestUri.c_str());
    TRACE_OUT("SKR request body length: %zu, target (attestation_token) length: %zu",
              requestBodyStr.length(), attestation_token.length());
    // Log first 200 chars of body for diagnostics (token is large)
    TRACE_OUT("SKR request body prefix: %.200s", requestBodyStr.c_str());

#ifdef _WIN32
    std::string result = GetKeyVaultResponseWinHttp(requestUri, access_token, requestBodyStr);
#else
    std::string result = GetKeyVaultResponseCurl(requestUri, access_token, requestBodyStr);
#endif

    TRACE_OUT("SKR response: %s", Util::reduct_log(result).c_str());
    TRACE_OUT("Exiting Util::GetKeyVaultResponse()");
    return result;
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

        if (attest_token.empty())
        {
            throw skr_error(EXIT_ATTEST_FAIL,
                            "MAA attestation returned an empty token. Cannot proceed with key release.");
        }

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
            throw skr_error(EXIT_SKR_FAIL, "Invalid SKR token (expected 3 dot-separated parts)");
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
        TRACE_OUT("Encrypted bytes: %s", Util::reduct_log(Util::binary_to_base64url(cipherText)).c_str());

        AttestationClient *attestation_client = nullptr;
        AttestationLogger *log_handle = new Logger(Util::get_trace());

        // Initialize attestation client
        if (!Initialize(log_handle, &attestation_client))
        {
            Uninitialize();
            // Note: do NOT delete log_handle — Initialize() wraps it in a
            // shared_ptr that takes ownership (see AttestationClient.cpp).
            throw skr_error(EXIT_SKR_FAIL, "Failed to create attestation client object for TPM decrypt");
        }

        attest::AttestationResult result;
        int RSASize = 2048;
        int ModulusSize = RSASize / 8;
        uint8_t *decryptedAESBytes = nullptr;
        uint32_t decryptedBytesSize = 0;
        TRACE_OUT("TPM decrypt: RSA-OAEP with SHA-256 (matching RSA_AES_KEY_WRAP_256)");
        result = attestation_client->Decrypt(attest::EncryptionType::NONE,
                                             cipherText.data(),
                                             ModulusSize,
                                             NULL,
                                             0,
                                             &decryptedAESBytes,
                                             &decryptedBytesSize,
                                             attest::RsaScheme::RsaOaep,   // RSA-OAEP wrapping
                                             attest::RsaHashAlg::RsaSha256 // SHA-256 to match RSA_AES_KEY_WRAP_256
        );
        if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS)
        {
            std::ostringstream oss;
            oss << "Failed to decrypt AES key: error code " << static_cast<int>(result.code_)
                << ", TPM error code=" << result.tpm_error_code_
                << ", Desc=" << result.description_;
            fprintf(stderr, "%s\n", oss.str().c_str());
            Uninitialize();
            throw skr_error(EXIT_CRYPTO_FAIL, oss.str());
        }
        {
            std::vector<BYTE> decryptedAESBytesVec(decryptedAESBytes, decryptedAESBytes + decryptedBytesSize);
            TRACE_OUT("Decrypted Transfer key: %s", Util::reduct_log(Util::binary_to_base64url(decryptedAESBytesVec)).c_str());
        }

        // The remaining bytes are the encrypted CMK bytes with the decrypted AES key.
        // use openssl AES to decrypt the CMK bytes.
        BYTE private_key[8192];
        int private_key_len = 0;
        private_key_len = decrypt_aes_key_unwrap(decryptedAESBytes,
                                                 cipherText.data() + ModulusSize,
                                                 (int)(cipherText.size() - ModulusSize),
                                                 private_key);

        // Securely zero and free the decrypted AES transfer key
        OPENSSL_cleanse(decryptedAESBytes, decryptedBytesSize);
        free(decryptedAESBytes);
        decryptedAESBytes = nullptr;

        if (private_key_len == 0)
        {
            OPENSSL_cleanse(private_key, sizeof(private_key));
            Uninitialize();
            throw skr_error(EXIT_CRYPTO_FAIL, "Failed to decrypt the CMK (AES key unwrap returned 0 bytes)");
        }

        TRACE_OUT("CMK private key has length=%d", private_key_len);

        // PKCS#8: parse the decrypted private key material
        BIO *bio_key = BIO_new_mem_buf(private_key, private_key_len);
        if (!bio_key)
        {
            OPENSSL_cleanse(private_key, sizeof(private_key));
            Uninitialize();
            throw skr_error(EXIT_CRYPTO_FAIL, "Error creating memory BIO for private key");
        }

        *pkey = d2i_PrivateKey_bio(bio_key, NULL);
        BIO_free(bio_key);

        if (!*pkey)
        {
            // Collect OpenSSL error details
            std::ostringstream oss;
            oss << "Failed to parse PKCS#8 private key: ";
            unsigned long oerr;
            while ((oerr = ERR_get_error()))
            {
                char buf[120];
                ERR_error_string_n(oerr, buf, sizeof(buf));
                oss << buf << "; ";
            }
            OPENSSL_cleanse(private_key, sizeof(private_key));
            Uninitialize();
            throw skr_error(EXIT_CRYPTO_FAIL, oss.str());
        }

        TRACE_OUT("Parsed private key: type=%d", EVP_PKEY_base_id(*pkey));

        // Securely zero the private key material on the stack
        OPENSSL_cleanse(private_key, sizeof(private_key));

        // Cleanup attestation client resources
        Uninitialize();
        // Note: do NOT delete log_handle — Initialize() wraps it in a
        // shared_ptr that takes ownership (see AttestationClient.cpp).

        TRACE_OUT("Exiting Util::doSKR()");
        return true;
    }
    catch (skr_error &)
    {
        throw; // let structured errors propagate to main()
    }
    catch (std::exception &e)
    {
        // Wrap unexpected exceptions with EXIT_SKR_FAIL
        throw skr_error(EXIT_SKR_FAIL, std::string("doSKR failed: ") + e.what());
    }

    return false;
}

// A helper function to handle errors
void handleErrors()
{
    std::ostringstream oss;
    oss << "OpenSSL error: ";
    unsigned long err;
    while ((err = ERR_get_error()))
    {
        char buf[120];
        ERR_error_string_n(err, buf, sizeof(buf));
        oss << buf << "; ";
    }
    ERR_print_errors_fp(stderr);
    throw skr_error(EXIT_CRYPTO_FAIL, oss.str());
}

// A function that encrypts a message with a public key using EVP_PKEY_encrypt
/// @brief Map a hash algorithm name to an OpenSSL EVP_MD.
/// Supported names (case-insensitive): sha1, sha256, sha384, sha512.
static const EVP_MD *get_evp_md_by_name(const std::string &name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    // Strip optional dashes (e.g. "sha-256" -> "sha256")
    lower.erase(std::remove(lower.begin(), lower.end(), '-'), lower.end());

    if (lower == "sha1")   return EVP_sha1();
    if (lower == "sha256") return EVP_sha256();
    if (lower == "sha384") return EVP_sha384();
    if (lower == "sha512") return EVP_sha512();
    throw std::runtime_error("Unsupported hash algorithm: " + name +
                             ". Supported: sha1, sha256, sha384, sha512");
}

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

    // Set the RSA padding mode to PKCS #1 OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleErrors();

    // Set RSA signature scheme to SHA256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        handleErrors();

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

/// @brief RSA-OAEP decrypt with caller-specified hash algorithms.
/// @param oaep_md  OAEP hash (e.g. EVP_sha256()).  Must not be NULL.
/// @param mgf1_md  MGF1 hash.  If NULL, defaults to oaep_md.
int rsa_decrypt(EVP_PKEY *pkey, const PBYTE msg, size_t msglen, PBYTE *dec, size_t *declen,
                const EVP_MD *oaep_md, const EVP_MD *mgf1_md)
{
    TRACE_OUT("Entering rsa_decrypt()");
    TRACE_OUT("  OAEP hash: %s, MGF1 hash: %s",
              EVP_MD_get0_name(oaep_md),
              mgf1_md ? EVP_MD_get0_name(mgf1_md) : EVP_MD_get0_name(oaep_md));

    if (mgf1_md == nullptr)
        mgf1_md = oaep_md;

    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;

    // Create the context for the decryption operation
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        handleErrors();

    // Initialize the decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handleErrors();

    // Set the RSA padding mode to PKCS #1 OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleErrors();

    // Set OAEP hash algorithm
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) <= 0)
        handleErrors();

    // Set MGF1 hash algorithm (explicit to avoid platform-dependent defaults)
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
        handleErrors();

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

/// @brief RSA-OAEP decrypt (exception-safe variant for batch operations).
/// Throws std::runtime_error on failure instead of calling abort().
static void rsa_decrypt_safe(EVP_PKEY *pkey, const PBYTE msg, size_t msglen,
                             PBYTE *dec, size_t *declen,
                             const EVP_MD *oaep_md, const EVP_MD *mgf1_md)
{
    if (mgf1_md == nullptr)
        mgf1_md = oaep_md;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new failed");

    // Use a lambda to ensure ctx cleanup on any exit path
    auto cleanup = [&]() { EVP_PKEY_CTX_free(ctx); };

    try
    {
        if (EVP_PKEY_decrypt_init(ctx) <= 0)
            throw std::runtime_error("EVP_PKEY_decrypt_init failed");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throw std::runtime_error("set_rsa_padding failed");
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) <= 0)
            throw std::runtime_error("set_rsa_oaep_md failed");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1_md) <= 0)
            throw std::runtime_error("set_rsa_mgf1_md failed");

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, msg, msglen) <= 0)
            throw std::runtime_error("EVP_PKEY_decrypt (size query) failed");

        *dec = (PBYTE)OPENSSL_malloc(outlen);
        if (!*dec)
            throw std::runtime_error("OPENSSL_malloc failed");

        if (EVP_PKEY_decrypt(ctx, *dec, &outlen, msg, msglen) <= 0)
        {
            OPENSSL_free(*dec);
            *dec = nullptr;
            throw std::runtime_error("EVP_PKEY_decrypt failed");
        }
        *declen = outlen;
    }
    catch (...)
    {
        cleanup();
        throw;
    }
    cleanup();
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
        throw skr_error(EXIT_SKR_FAIL, "WrapKey: Failed to release the private key");
    }
    int pkeyBaseId = EVP_PKEY_base_id(pkey);
    TRACE_OUT("Key release completed successfully. EVP_PKEY_base_id=%d", pkeyBaseId);

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey
    if (pkeyBaseId != EVP_PKEY_RSA /* PKCS1 */ &&
        pkeyBaseId != EVP_PKEY_RSA2 /* X500 */)
    {
        EVP_PKEY_free(pkey);
        throw skr_error(EXIT_CRYPTO_FAIL, "The key is not of type RSA. Only RSA keys are supported for wrapKey/unwrapKey");
    }

    int rsaSize = EVP_PKEY_get_size(pkey);
    TRACE_OUT("Wrapping: %s", Util::reduct_log(sym_key).c_str());

    size_t encrypted_length = 0;
    PBYTE encryptedKey;
    if (rsa_encrypt(pkey, (const PBYTE)sym_key.c_str(), sym_key.size(), &encryptedKey, &encrypted_length) == -1)
    {
        EVP_PKEY_free(pkey);
        handle_openssl_errors(); // throws skr_error(EXIT_CRYPTO_FAIL)
    }

    TRACE_OUT("Wrapping the symmetric key succeeded: encrypted_length=%ld", encrypted_length);
    std::vector<BYTE> encryptedKeyVector(encryptedKey, encryptedKey + encrypted_length);
    std::string cipherText = Util::binary_to_base64(encryptedKeyVector);
    TRACE_OUT("Wrapped symmetric key in base64: %s", Util::reduct_log(cipherText).c_str());

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
                            const Util::AkvCredentialSource &akv_credential_source,
                            const std::string &oaep_hash_alg,
                            const std::string &mgf1_hash_alg)
{
    TRACE_OUT("Entering Util::UnwrapKey()");
    TRACE_OUT("  OAEP hash: %s, MGF1 hash: %s",
              oaep_hash_alg.c_str(),
              mgf1_hash_alg.empty() ? oaep_hash_alg.c_str() : mgf1_hash_alg.c_str());

    EVP_PKEY *pkey = nullptr;
    if (!Util::doSKR(attestation_url, nonce, key_enc_key_url, &pkey, akv_credential_source))
    {
        throw skr_error(EXIT_SKR_FAIL, "UnwrapKey: Failed to release the private key");
    }
    int pkeyBaseId = EVP_PKEY_base_id(pkey);
    TRACE_OUT("Key release completed successfully. EVP_PKEY_base_id=%d", pkeyBaseId);

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey
    if (pkeyBaseId != EVP_PKEY_RSA /* PKCS1 */ &&
        pkeyBaseId != EVP_PKEY_RSA2 /* X500 */)
    {
        EVP_PKEY_free(pkey);
        throw skr_error(EXIT_CRYPTO_FAIL, "The key is not of type RSA. Only RSA keys are supported for wrapKey/unwrapKey");
    }

    int rsaSize = EVP_PKEY_get_size(pkey);
    TRACE_OUT("Unwrapping: %s", wrapped_key_base64.c_str());
    std::vector<BYTE> wrapped_key = Util::base64_to_binary(wrapped_key_base64);
    TRACE_OUT("RSA key size=%d bytes, wrapped_key decoded size=%zu bytes", rsaSize, wrapped_key.size());
    if ((int)wrapped_key.size() != rsaSize)
    {
        TRACE_OUT("WARNING: wrapped_key size (%zu) != RSA key size (%d). Possible base64 or key-size mismatch.",
                  wrapped_key.size(), rsaSize);
    }

    // Resolve hash algorithms
    const EVP_MD *oaep_md = get_evp_md_by_name(oaep_hash_alg);
    const EVP_MD *mgf1_md = mgf1_hash_alg.empty() ? nullptr : get_evp_md_by_name(mgf1_hash_alg);

    size_t decrypted_length = 0;
    PBYTE decryptedKey;
    if (rsa_decrypt(pkey, wrapped_key.data(), wrapped_key.size(), &decryptedKey, &decrypted_length,
                    oaep_md, mgf1_md) == -1)
    {
        EVP_PKEY_free(pkey);
        handle_openssl_errors(); // throws skr_error(EXIT_CRYPTO_FAIL)
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

std::string Util::UnwrapKeyBatch(const std::string &attestation_url,
                                  const std::string &nonce,
                                  const std::string &batch_json,
                                  const std::string &key_enc_key_url,
                                  const Util::AkvCredentialSource &akv_credential_source,
                                  const std::string &oaep_hash_alg,
                                  const std::string &mgf1_hash_alg)
{
    TRACE_OUT("Entering Util::UnwrapKeyBatch()");
    TRACE_OUT("  OAEP hash: %s, MGF1 hash: %s",
              oaep_hash_alg.c_str(),
              mgf1_hash_alg.empty() ? oaep_hash_alg.c_str() : mgf1_hash_alg.c_str());

    // --- Parse the input JSON ---
    json inputJson;
    try
    {
        inputJson = json::parse(batch_json);
    }
    catch (const json::parse_error &e)
    {
        throw skr_error(EXIT_USAGE, std::string("UnwrapKeyBatch: Invalid JSON input: ") + e.what());
    }

    if (!inputJson.contains("keys") || !inputJson["keys"].is_array())
    {
        throw skr_error(EXIT_USAGE, "UnwrapKeyBatch: JSON must contain a \"keys\" array");
    }

    const auto &keysArray = inputJson["keys"];
    TRACE_OUT("Batch contains %zu keys to unwrap", keysArray.size());

    // --- Single SKR call for the entire batch ---
    EVP_PKEY *pkey = nullptr;
    if (!Util::doSKR(attestation_url, nonce, key_enc_key_url, &pkey, akv_credential_source))
    {
        throw skr_error(EXIT_SKR_FAIL, "UnwrapKeyBatch: Failed to release the private key");
    }
    int pkeyBaseId = EVP_PKEY_base_id(pkey);
    TRACE_OUT("Key release completed successfully. EVP_PKEY_base_id=%d", pkeyBaseId);

    if (pkeyBaseId != EVP_PKEY_RSA && pkeyBaseId != EVP_PKEY_RSA2)
    {
        EVP_PKEY_free(pkey);
        throw skr_error(EXIT_CRYPTO_FAIL, "UnwrapKeyBatch: Released key is not RSA. Only RSA keys are supported for unwrap.");
    }

    // Resolve hash algorithms once for the whole batch
    const EVP_MD *oaep_md = get_evp_md_by_name(oaep_hash_alg);
    const EVP_MD *mgf1_md = mgf1_hash_alg.empty() ? nullptr : get_evp_md_by_name(mgf1_hash_alg);

    // --- Iterate and unwrap each key ---
    json resultsArray = json::array();
    int successCount = 0;
    int errorCount = 0;

    for (size_t i = 0; i < keysArray.size(); ++i)
    {
        const auto &entry = keysArray[i];
        json resultEntry;

        // Extract the id (optional — default to index)
        std::string id = entry.value("id", std::to_string(i));
        resultEntry["id"] = id;

        try
        {
            // "wrapped" field is required
            if (!entry.contains("wrapped") || !entry["wrapped"].is_string())
            {
                throw std::runtime_error("missing or invalid \"wrapped\" field");
            }

            std::string wrapped_key_base64 = entry["wrapped"].get<std::string>();
            TRACE_OUT("Unwrapping key [%s] (%zu/%zu)", id.c_str(), i + 1, keysArray.size());

            std::vector<BYTE> wrapped_key = Util::base64_to_binary(wrapped_key_base64);

            size_t decrypted_length = 0;
            PBYTE decryptedKey = nullptr;
            rsa_decrypt_safe(pkey, wrapped_key.data(), wrapped_key.size(),
                             &decryptedKey, &decrypted_length, oaep_md, mgf1_md);

            std::vector<BYTE> decryptedKeyVector(decryptedKey, decryptedKey + decrypted_length);
            std::string plainTextB64 = Util::binary_to_base64(decryptedKeyVector);
            OPENSSL_free(decryptedKey);

            resultEntry["unwrapped"] = Util::base64_decode(plainTextB64);
            ++successCount;
        }
        catch (const std::exception &e)
        {
            resultEntry["error"] = e.what();
            ++errorCount;
            TRACE_OUT("Key [%s] failed: %s", id.c_str(), e.what());
        }

        resultsArray.push_back(resultEntry);
    }

    EVP_PKEY_free(pkey);

    TRACE_OUT("Batch unwrap complete: %d succeeded, %d failed out of %zu",
              successCount, errorCount, keysArray.size());
    TRACE_OUT("Exiting Util::UnwrapKeyBatch()");

    json outputJson;
    outputJson["results"] = resultsArray;
    return outputJson.dump(2); // pretty-print with 2-space indent
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
        throw skr_error(EXIT_SKR_FAIL, "Failed to release the private key");
    }

    TRACE_OUT("Key release completed successfully.");

    // Check if the key is of type RSA. If not, exit because EC keys do not support wrapKey/unwrapKey
    bool releaseOk = false;
    switch (EVP_PKEY_base_id(pkey))
    {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        std::cerr << "The released key is of type RSA. It can be used for wrapKey/unwrapKey operations." << std::endl;
        releaseOk = true;
        break;
    case EVP_PKEY_EC:
        std::cerr << "The released key is of type EC. It can be used for sign/verify operations." << std::endl;
        releaseOk = true;
        break;
    default:
        std::cerr << "The released key is of type " << EVP_PKEY_base_id(pkey) << ". Not sure what operations are supported." << std::endl;
        break;
    }
    EVP_PKEY_free(pkey);
    return releaseOk;
}
