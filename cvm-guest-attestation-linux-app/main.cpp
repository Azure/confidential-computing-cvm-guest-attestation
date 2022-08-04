#include <iostream>
#include <AttestationClient.h>
#include <stdarg.h>
#include <vector>
#include <algorithm>
#include <thread>
#include <curl/curl.h>
#include "Utils.h"
#include <fstream>
#include <string>
#include <iostream>


class Logger : public attest::AttestationLogger {
public:
    void Log(const char* log_tag,
        LogLevel level,
        const char* function,
        const int line,
        const char* fmt,
        ...) override {
        va_list args;
        va_start(args, fmt);
        size_t len = std::vsnprintf(NULL, 0, fmt, args);
        va_end(args);

        std::vector<char> str(len + 1);

        va_start(args, fmt);
        std::vsnprintf(&str[0], len + 1, fmt, args);
        va_end(args);

        printf("Level: %s Tag: %s %s:%d:%s\n", attest::AttestationLogger::LogLevelStrings[level].c_str(), log_tag, function, line, &str[0]);
    }
};

// Attestation URL + Guest attestation path + API version
//std::string attestation_url = "https://sharedeus.eus.test.attest.azure.net/attest/AzureGuest?api-version=2020-10-01";
std::string attestation_url = "https://sharedeus2.eus2.attest.azure.net/attest/AzureGuest?api-version=2020-10-01";

int main() {
    try {
        printf("Initiating Guest Attestation\n");
        AttestationClient* attestation_client = nullptr;
        Logger* log_handle = new Logger();

        // Initialize attestation client
        if (!Initialize(log_handle, &attestation_client)) {
            printf("Failed to create attestation client object\n");
            Uninitialize();
            exit(1);
        }

        // parameters for Attest call
        attest::ClientParameters params = {};
        params.attestation_endpoint_url = (unsigned char*)attestation_url.c_str();
        std::string client_payload_str = "{\"nonce\":\"1234\"}";
        params.client_payload = (unsigned char*)client_payload_str.c_str();
        // structure version
        params.version = CLIENT_PARAMS_VERSION;
        unsigned char* jwt = nullptr;
        attest::AttestationResult result;

        // make attestation call
        if ((result = attestation_client->Attest(params, &jwt)).code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
            printf("Attestation call failed with following error code: %d and description: %s\n", (int)result.code_, result.description_.c_str());
            Uninitialize();
            exit(1);
        }

        std::string jwt_str = reinterpret_cast<char*>(jwt);
        //printf("Guest attestation passed successfully!! Printing the attestation token in next line....\n");
	std::ofstream file("jwt_encoded");
	file << jwt_str.c_str();
        printf("%s\n", jwt_str.c_str());
        attestation_client->Free(jwt);

        // Uninitialize attestation client
        Uninitialize();
    }
    catch (std::exception& e) {
        printf("Unexpected exception occured. Details - %s", e.what());
    }
}
