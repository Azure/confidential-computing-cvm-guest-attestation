#include <curl/curl.h>
#include <math.h>
#include <ctime>
#include <thread>
#include <json/json.h>

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

static size_t WriteResponseCallback(void* contents, size_t size, size_t nmemb, void* response)
{
    if (response == nullptr ||
        contents == nullptr) {
        return 0;
    }
    std::string* responsePtr = reinterpret_cast<std::string*>(response);

    char* contentsStr = (char*)contents;
    size_t contentsSize = size * nmemb;

    responsePtr->insert(responsePtr->end(), contentsStr, contentsStr + contentsSize);
    return contentsSize;
}

std::string GetMSI() {
    std::string msi_token;
    CURL* curl = curl_easy_init();

    // Set the the HTTPHEADER object to send Metadata in the response.
    struct curl_slist* headers = NULL;
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
    while ((res = curl_easy_perform(curl)) == CURLE_OK) {

        long response_code = HTTP_STATUS_OK;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == HTTP_STATUS_OK) {
            Json::Reader reader;
            Json::Value root;
            bool success = reader.parse(response.c_str(), root);

            msi_token = root["access_token"].asString();
            if (msi_token.size() == 0) {
                printf("MSI token not found\n");
                break;
            }
            break;
        }
        else if (response_code == HTTP_STATUS_IMDS_UPDATING ||
            response_code == HTTP_STATUS_IMDS_THROTTLE_LIMIT ||
            response_code >= HTTP_STATUS_IMDS_TRANSIENT_ERRORS) {

            //If we receive any of these responses from IMDS, we can retry
            //after an exponential backoff time.

            // Sleep for the backoff period and try again.
            if (retries == MAX_RETRIES) {
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
        }
        else {
            printf("Request to query MSI token failed with error code:%ld description:%s\n",
                response_code,
                response.c_str());
            break;
        }
    }
    if (res != CURLE_OK) {
        printf("curl_easy_perform() failed:%s", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return msi_token;
}