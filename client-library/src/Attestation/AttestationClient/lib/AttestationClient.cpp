//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClient.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

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
