#include <iostream>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include "Utils.h"
#include "Logger.h"
using json = nlohmann::json;


#define OUTPUT_TYPE_JWT "token"
#define OUTPUT_TYPE_BOOL "bool"

// default guest attestation url
std::string default_attestation_url = "https://sharedeus2.eus2.attest.azure.net/";

#ifndef PLATFORM_UNIX
static char* optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char* const argv[], const char* optstring)
{
    //Error and -1 returns are the same as for getopt(), plus '?'
    // for an ambiguous match or an extraneous parameter.
    if (
        (argv == nullptr) ||
        (optind >= argc) ||
        (argv[optind][0] != '-') ||
        (argv[optind][0] == 0)
        )
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char* p = strchr(optstring, opt);

    if (p == NULL)
    {
        return '?';
    }
    if (p[1] == ':')
    {
        optind++;
        if (optind >= argc)
        {
            return '?';
        }
        optarg = argv[optind];
        optind++;
    }
    return opt;
}
#endif //!PLATFORM_UNIX

void usage(char* programName) {
    printf("Usage: %s -a <attestation-endpoint> -n <nonce> -o <%s|%s>\n", programName, OUTPUT_TYPE_BOOL, OUTPUT_TYPE_JWT);
}

int main(int argc, char* argv[]) {
    std::string attestation_url;
    std::string nonce;
    std::string output_type;

    int opt;
    while ((opt = getopt(argc, argv, ":a:n:o:")) != -1) {
        switch (opt) {
        case 'a':
            attestation_url.assign(optarg);
            break;
        case 'n':
            nonce.assign(optarg);
            break;
        case 'o':
            output_type.assign(optarg);
            break;
        case ':':
            fprintf(stderr, "Option needs a value\n");
            exit(1);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    try {
        if (attestation_url.empty()) {
            // use the default attestation url
            attestation_url.assign(default_attestation_url);
        }

        if (output_type.empty()) {
            // set the default output type to boolean
            output_type = OUTPUT_TYPE_BOOL;
        }

        AttestationClient* attestation_client = nullptr;
        Logger* log_handle = new Logger();

        // Initialize attestation client
        if (!Initialize(log_handle, &attestation_client)) {
            printf("Failed to create attestation client object\n");
            Uninitialize();
            exit(1);
        }

        // parameters for the Attest call       
        attest::ClientParameters params = {};
        params.attestation_endpoint_url = (unsigned char*)attestation_url.c_str();
        std::string client_payload_str = "{\"nonce\":\"" + nonce + "\"}"; // nonce is optional
        params.client_payload = (unsigned char*) client_payload_str.c_str();
        params.version = CLIENT_PARAMS_VERSION;
        unsigned char* jwt = nullptr;
        attest::AttestationResult result;
        
        bool is_cvm = false;
        bool attestation_success = true;
        std::string jwt_str;
        // call attest
        if ((result = attestation_client->Attest(params, &jwt)).code_ 
                != attest::AttestationResult::ErrorCode::SUCCESS) {
            attestation_success = false;
        }
	
        if (attestation_success) {
            jwt_str = reinterpret_cast<char*>(jwt);
            attestation_client->Free(jwt);
            // Prase attestation token to extract isolation tee details
            std::vector<std::string> tokens;
            boost::split(tokens, jwt_str, [](char c) {return c == '.'; });
            if (tokens.size() < 3) {
                printf("Invalid JWT token");
                exit(1);
            }

            json attestation_claims = json::parse(base64_decode(tokens[1]));
            try {
                std::string attestation_type 
                    = attestation_claims["x-ms-isolation-tee"]["x-ms-attestation-type"].get<std::string>();
                std::string compliance_status 
                    = attestation_claims["x-ms-isolation-tee"]["x-ms-compliance-status"].get<std::string>();
                if (boost::iequals(attestation_type, "sevsnpvm") &&
                    boost::iequals(compliance_status, "azure-compliant-cvm")){
                    is_cvm = true;
                }
            }
            catch (...) { } // sevsnp claim does not exist in the token
        }

        if (boost::iequals(output_type, OUTPUT_TYPE_JWT)) {
            printf("%s", attestation_success ? jwt_str.c_str() : result.description_.c_str());   
        }
        else {
            printf("%s", is_cvm ? "true" : "false");
        }

        Uninitialize();
    }
    catch (std::exception& e) {
        printf("Exception occured. Details - %s", e.what());
        exit(1);
    }
}
