//-------------------------------------------------------------------------------------------------
// <copyright file="Main.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

// TODO: Run CodeQL, static analysis on the native code. Also enable it in the repo.

#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <vector>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include <AttestationClient.h>
#include "AttestationUtil.h"
#include "Constants.h"

void usage(char *programName)
{
    printf("Usage: \n");
    printf("\tRelease RSA or EC key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KeyURL -c (imds|sp) -r \n", programName);
    printf("\n");
    printf("\tRelease RSA key and wrap/unwrap symmetric key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s symkey|base64(wrappedSymKey) -w|-u (Wrap|Unwrap) \n", programName);
}

enum class Operation
{
    None,
    WrapKey,
    UnwrapKey,
    ReleaseKey,
    Undefined
};

// Check if tracing is to be enabled for SKR in the env.
void set_tracing(void)
{
    size_t envTraceFlagLen;
    errno_t err = getenv_s(&envTraceFlagLen, nullptr, 0, "SKR_TRACE_ON");
    if (envTraceFlagLen > 0)
    {
        char* skr_trace_flag = nullptr;
        skr_trace_flag = (char*)malloc(envTraceFlagLen);
        if (skr_trace_flag == nullptr)
        {
            std::cerr << "Failed to allocate memory for env variable SKR_TRACE_ON" << std::endl;
            exit(EXIT_FAILURE);
        }
        err = getenv_s(&envTraceFlagLen, skr_trace_flag, envTraceFlagLen, "SKR_TRACE_ON");
        if (err != 0)
        {
            std::cerr << "Failed to get env variable SKR_TRACE_ON" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (strcmp(skr_trace_flag, "1") == 0)
        {
            std::cout << "Tracing is enabled" << std::endl;
            Util::set_trace(true);
        }
        free(skr_trace_flag);
    }
}

int main(int argc, char *argv[])
{
    set_tracing();
    
    TRACE_OUT("Main started");
    std::string attestation_url;
    std::string nonce;
    std::string sym_key;
    std::string key_enc_key_url;
    Operation op = Operation::None;
    Util::AkvCredentialSource akv_credential_source = Util::AkvCredentialSource::Imds;

    int opt;
    while ((opt = getopt(argc, argv, "a:n:k:c:s:uwr")) != -1)
    {
        switch (opt)
        {
        case 'a':
            attestation_url.assign(optarg);
            TRACE_OUT("attestation_url: %s", attestation_url.c_str());
            break;
        case 'n':
            nonce.assign(optarg);
            TRACE_OUT("nonce: %s", nonce.c_str());
            break;
        case 'k':
            key_enc_key_url.assign(optarg);
            TRACE_OUT("key_enc_key_url: %s", key_enc_key_url.c_str());
            break;
        case 'c':
            if (strcmp(optarg, "imds") == 0)
            {
                akv_credential_source = Util::AkvCredentialSource::Imds;
            }
            else if (strcmp(optarg, "sp") == 0)
            {
                akv_credential_source = Util::AkvCredentialSource::EnvServicePrincipal;
            }
            TRACE_OUT("akv_credential_source: %d", static_cast<int>(akv_credential_source));
            break;
        case 'u':
            op = Operation::UnwrapKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 'w':
            op = Operation::WrapKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 's':
            sym_key.assign(optarg);
            TRACE_OUT("sym_key: %s", sym_key.c_str());
            break;
        case 'r':
            op = Operation::ReleaseKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case ':':
            std::cerr << "Option needs a value" << std::endl;
            return EXIT_FAILURE;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    bool success = false;
    int retVal = 0;
    try
    {
        std::string result;
        switch (op)
        {
        case Operation::WrapKey:
            result = Util::WrapKey(attestation_url, nonce, sym_key, key_enc_key_url, akv_credential_source);
            std::cout << result << std::endl;
            break;
        case Operation::UnwrapKey:
            result = Util::UnwrapKey(attestation_url, nonce, sym_key, key_enc_key_url, akv_credential_source);
            std::cout << result << std::endl;
            break;
        case Operation::ReleaseKey:
            success = Util::ReleaseKey(attestation_url, nonce, key_enc_key_url, akv_credential_source);
            retVal = success ? EXIT_SUCCESS : EXIT_FAILURE;
            break;
        default:
            usage(argv[0]);
            retVal = EXIT_FAILURE;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception occured. Details: " << e.what() << std::endl;
        retVal = EXIT_FAILURE;
    }

    return retVal;
}
