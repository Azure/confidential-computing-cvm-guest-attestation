#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <ctime>
#include <thread>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <AttestationClient.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "Utils.h"

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_IMDS_UPDATING 404
#define HTTP_STATUS_IMDS_THROTTLE_LIMIT 429
#define HTTP_STATUS_IMDS_TRANSIENT_ERRORS 500
#define MAX_RETRIES 3

static std::string GetMSIQureyUrl() {
    constexpr char msi_query_endpoint[] = "http://169.254.169.254/metadata/identity/oauth2/token?";
    constexpr char msi_query_api_version[] = "api-version=2018-02-01";
    constexpr char msi_query_resource[] = "resource=https%3a%2f%2fattest.azure.net";

    std::string url = std::string(msi_query_endpoint) +
                      std::string(msi_query_api_version) +
                      std::string("&") +
                      std::string(msi_query_resource);
    return url;
}

static size_t WriteResponseCallback(void *contents, size_t size, size_t nmemb, void *response)
{
    if(response == nullptr ||
       contents == nullptr) {
        return 0;
    }
    std::string *responsePtr = reinterpret_cast<std::string*>(response);

    char *contentsStr = (char*)contents;
    size_t contentsSize = size * nmemb;

    responsePtr->insert(responsePtr->end(), contentsStr, contentsStr + contentsSize);
    return contentsSize;
}

std::string GetMSI() {
    std::string msi_token;
    CURL *curl = curl_easy_init();

    // Set the the HTTPHEADER object to send Metadata in the response.
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Metadata:true");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Send a pointer to a std::string to hold the response from the end
    // point along with the handler function.
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    std::string url = GetMSIQureyUrl();
    // Set the url of the end point that we are trying to talk to.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    CURLcode res = CURLE_OK;
    uint8_t retries = 0;
    while((res = curl_easy_perform(curl)) == CURLE_OK) {
        long response_code = HTTP_STATUS_OK;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if(response_code == HTTP_STATUS_OK) {
            nlohmann::json token = nlohmann::json::parse(response);
            msi_token = token["access_token"].get_ref<std::string&>();
            if(msi_token.size() == 0) {
                printf("MSI token not found\n");
                break;
            }
            break;
        } else if(response_code == HTTP_STATUS_IMDS_UPDATING || response_code == HTTP_STATUS_IMDS_THROTTLE_LIMIT || response_code >= HTTP_STATUS_IMDS_TRANSIENT_ERRORS) {
            //If we receive any of these responses from IMDS, we can retry
            //after an exponential backoff time.
            // Sleep for the backoff period and try again.
            if(retries == MAX_RETRIES) {
                printf("Failed to get MSI token. Maximum retries exceeded\n");
                break;
            }
            printf("Request to query MSI token failed with error code:%ld description:%s\n",
                   response_code,
                   response.c_str());
            printf("Retrying:%d\n", retries);
            std::this_thread::sleep_for(
                std::chrono::seconds(
                    static_cast<long long>(5 * pow(2.0, static_cast<double>(retries++)))
                ));
            continue;
        } else {
            printf("Request to query MSI token failed with error code:%ld description:%s\n",
                             response_code,
                             response.c_str());
            break;
        }
    }
    if(res != CURLE_OK) {
        printf("curl_easy_perform() failed:%s", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return msi_token;
}

std::vector<unsigned char> base64_to_binary(const std::string& base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::vector<unsigned char>(It(std::begin(base64_data)), It(std::end(base64_data))), [](char c) {
        return c == '\0';
        });
}

std::string binary_to_base64(const std::vector<unsigned char>& binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));
    return tmp.append((3 - binary_data.size() % 3) % 3, '=');
}

std::string binary_to_base64url(const std::vector<unsigned char>& binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));

    // For encoding to base64url, replace "+" with "-" and "/" with "_"
    boost::replace_all(tmp, "+", "-");
    boost::replace_all(tmp, "/", "_");

    // We do not need to add padding characters while url encoding.
    return tmp;
}

std::vector<unsigned char> base64url_to_binary(const std::string& base64_data)
{
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and 
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return base64_to_binary(stringData);
}