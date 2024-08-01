//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClient.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <cstring>
#include "Logging.h"
#include "AttestationClientImpl.h"
#include "AttestationClient.h"

AttestationClient* attestation_client = nullptr;

bool Initialize(attest::AttestationLogger* attestation_logger,
                AttestationClient** client) {
    if (attestation_logger == nullptr ||
        client == nullptr) {
        fprintf(stderr, "Invalid input argument");
        return false;
    }

    std::shared_ptr<attest::AttestationLogger> logger(attestation_logger);
    
    try {
        if (attestation_client == nullptr) {
            attestation_client = new AttestationClientImpl(logger);
        }
        *client = attestation_client;
    }
    catch (...) {
        // Set the logger handle here since we need to use it to log the error.
        // Under normal operation, this is called from the
        // AttestatoinClientImpl constructor.
        attest::SetLogger(logger);

        // Failed to create an object. Memory allocation failed.
        CLIENT_LOG_ERROR("Failed to create Attestation client: Memory Allocation failed");
        return false;
    }

    return true;
}

void Uninitialize() {
    if (attestation_client == nullptr) {
        return;
    }

    free(attestation_client);
    attestation_client = nullptr;
    return;
}


class DefaultLogger : public attest::AttestationLogger {
public:
    void Log(const char* log_tag,
        LogLevel level,
        const char* function,
        const int line,
        const char* fmt,
        ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    std::vector<char> str(len + 1);

    va_start(args, fmt);
    std::vsnprintf(&str[0], len + 1, fmt, args);
    va_end(args);

    if(level <= attest::AttestationLogger::Info)
      printf("[Attest][%s][%s]<%s:%d> %s\n", attest::AttestationLogger::LogLevelStrings[level].c_str(), log_tag, function, line, &str[0]);
  }
};

int32_t get_attestation_token(const uint8_t* app_data, uint32_t pcr, uint8_t* token, size_t* jwt_len) {
    AttestationClient* attestation_client = nullptr;
    attest::AttestationLogger* logger = nullptr;
    attest::ClientParameters params = {};
    unsigned char* jwt = nullptr;

    try {
        logger = new DefaultLogger();
        std::shared_ptr<attest::AttestationLogger> slogger(logger);
        attestation_client = new AttestationClientImpl(slogger);

        params.version = CLIENT_PARAMS_VERSION;
        params.attestation_endpoint_url = (const unsigned char*)"https://sharedeus2.eus2.attest.azure.net/";
        params.client_payload = app_data;
        params.pcr_selector = pcr;

        attest::AttestationResult::ErrorCode err = attestation_client->Attest(params, &jwt).code_;
        if(err != attest::AttestationResult::ErrorCode::SUCCESS)
          return (int32_t)err;

        std::string jwt_str = reinterpret_cast<char*>(jwt);
        *jwt_len = jwt_str.length();
        if(*jwt_len >= 32*1024)
          return (int32_t)attest::AttestationResult::ErrorCode::ERROR_FAILED_MEMORY_ALLOCATION;

        std::strcpy((char*)token, (const char*)jwt_str.c_str());
        attestation_client->Free(jwt);
        return 0;
    }
    catch (...) {
        return (int32_t)attest::AttestationResult::ErrorCode::ERROR_FAILED_MEMORY_ALLOCATION;
    }
}