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
    printf("Usage: %s -a <attestation-endpoint> -k KEK -s symkey|base64(wrappedSymKey) -w|-u (Wrap|Unwrap) \n", programName);
}

enum class Operation
{
    None,
    WrapKey,
    UnwrapKey,
    Undefined
};

int main(int argc, char *argv[])
{
    TRACE_OUT("Main started");

    std::string attestation_url;
    std::string nonce;
    std::string sym_key;
    std::string key_enc_key_url;
    Operation op = Operation::None;

    int opt;
    while ((opt = getopt(argc, argv, "a:n:k:s:uw")) != -1)
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
        case ':':
            std::cerr << "Option needs a value" << std::endl;
            return -2;
        default:
            usage(argv[0]);
            return -3;
        }
    }

    try
    {
        std::string result;
        switch (op)
        {
        case Operation::WrapKey:
            result = Util::WrapKey(attestation_url, nonce, sym_key, key_enc_key_url);
            std::cout << result << std::endl;
            break;
        case Operation::UnwrapKey:
            result = Util::UnwrapKey(attestation_url, nonce, sym_key, key_enc_key_url);
            std::cout << result << std::endl;
            break;
        default:
            usage(argv[0]);
            return -4;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception occured. Details: " << e.what() << std::endl;
        return -5;
    }

    return 0;
}
