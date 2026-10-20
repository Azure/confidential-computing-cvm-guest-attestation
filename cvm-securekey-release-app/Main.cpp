//-------------------------------------------------------------------------------------------------
// <copyright file="Main.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

// TODO: Run CodeQL, static analysis on the native code. Also enable it in the repo.

#ifdef _MSC_VER
#pragma warning(disable : 4996) // suppress MSVC deprecation of getenv
#endif

#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <fstream>
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

#ifdef PLATFORM_UNIX
#include <unistd.h> // getopt, optarg, optind, symlink
#include <sys/stat.h>

// ---------------------------------------------------------------------------
// The attestation library (libazguestattestation.so) was built on Ubuntu
// where curl's compiled-in CA path is /etc/ssl/certs/ca-certificates.crt.
// Inside the library, AttestationLibUtils.cpp does:
//
//   curl_easy_getinfo(curl, CURLINFO_CAINFO, &cainfo);   // Ubuntu default
//   if (cainfo && stat(cainfo, &buf) == 0)
//       curl_easy_setopt(curl, CURLOPT_CAINFO, cainfo);  // use it
//   else
//       curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt"); // CWD
//
// On RHEL/Fedora the Ubuntu path doesn't exist, and neither does
// curl-ca-bundle.crt, so every HTTPS call (MAA, AAD) fails with
// "Problem with the SSL CA cert (path? access rights?)".
//
// Because the library explicitly sets CURLOPT_CAINFO, the CURL_CA_BUNDLE
// env var is ignored.
//
// Fix: create a curl-ca-bundle.crt symlink in CWD pointing to the real
// system CA bundle.  The library resolves the bare relative path from CWD.
// ---------------------------------------------------------------------------
static void ensure_ca_bundle()
{
    struct stat st;

    // If curl-ca-bundle.crt already exists in CWD, nothing to do.
    if (stat("curl-ca-bundle.crt", &st) == 0)
        return;

    // Ordered list of CA bundle paths across distros.
    static const char *candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",   // Debian / Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL / Fedora / CentOS
        "/etc/ssl/ca-bundle.pem",               // SUSE
        "/etc/pki/tls/cacert.pem",              // older RHEL
        "/etc/ssl/cert.pem",                    // Alpine / macOS
        nullptr
    };

    for (const char **p = candidates; *p; ++p)
    {
        if (stat(*p, &st) == 0 && S_ISREG(st.st_mode))
        {
            if (symlink(*p, "curl-ca-bundle.crt") == 0)
                fprintf(stderr, "Info: created CA symlink ./curl-ca-bundle.crt -> %s\n", *p);
            return;
        }
    }
}
#endif // PLATFORM_UNIX

#ifndef PLATFORM_UNIX
// Simple getopt implementation for Windows (getopt is POSIX-only)
static char *optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char *const argv[], const char *optstring)
{
    if ((argv == nullptr) ||
        (optind >= argc) ||
        (argv[optind][0] != '-') ||
        (argv[optind][0] == 0))
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char *p = strchr(optstring, opt);

    if (p == nullptr)
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
    else
    {
        optind++;
    }
    return opt;
}
#endif // !PLATFORM_UNIX

void usage(char *programName)
{
    printf("Usage: \n");
    printf("\tRelease RSA or EC key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KeyURL -c (imds|sp) -r \n", programName);
    printf("\n");
    printf("\tRelease RSA key and wrap symmetric key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s symkey -w \n", programName);
    printf("\n");
    printf("\tRelease RSA key and unwrap symmetric key:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s base64(wrappedSymKey) -u [-H oaep_hash] [-G mgf1_hash]\n", programName);
    printf("\n");
    printf("\tSecurely unwrap with a non-exportable Key Vault / Managed HSM key into this attested VM:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s base64url(wrappedKey) -U [-A algorithm]\n", programName);
    printf("\t\t-A <algorithm>  Secure unwrap algorithm (default: A256KWPAD; use RSA-OAEP-256 for RSA-HSM keys)\n");
    printf("\n");
    printf("\tSecurely unwrap a batch (one attestation, one secureunwrapkey call per key):\n");
    printf("\t\t%s -a <attestation-endpoint> -k KEYURL -c (imds|sp) -S <json-file|-|inline> [-A algorithm] [-j concurrency] [-N count] [-X] [-R retries]\n", programName);
    printf("\n");
    printf("\tSecure unwrap performance test (emits latency JSON, never key material):\n");
    printf("\t\t%s -a <attestation-endpoint> -k KEYURL -c (imds|sp) -P <json-file|-|inline> [-A algorithm] [-j concurrency] [-N count] [-i iterations] [-W warmup] [-X] [-R retries]\n", programName);
    printf("\t\t-j <n>  Max parallel secureunwrapkey calls (default: 2; 1 = sequential; 0 = one per key; capped at 64)\n");
    printf("\t\t-N <n>  Replicate input keys cyclically to n keys (simulate n disks)\n");
    printf("\t\t-i <n>  Measured iterations (default: 10)\n");
    printf("\t\t-W <n>  Warmup iterations (default: 1)\n");
    printf("\t\t-X      Disable HTTP connection reuse (new TLS connection per call)\n");
    printf("\t\t-K      Disable attestation-library DecryptBatch()/key reuse (per-key Decrypt())\n");
    printf("\t\t-R <n>  Max retries on 429/5xx (default: 3)\n");
    printf("\n");
    printf("\tRelease an exportable Managed HSM AES key and unwrap locally:\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -s base64url(wrappedKey) -L [-A algorithm]\n", programName);
    printf("\n");
    printf("\tBatch unwrap from JSON file (one SKR, many unwraps):\n");
    printf("\t\t%s -a <attestation-endpoint> -n <optional-nonce> -k KEYURL -c (imds|sp) -B <json-file|-|inline> [-H oaep_hash] [-G mgf1_hash]\n", programName);
    printf("\n");
    printf("\tBatch JSON format (input):\n");
    printf("\t  { \"keys\": [ { \"id\": \"label\", \"wrapped\": \"base64...\" }, ... ] }\n");
    printf("\tBatch JSON format (output on stdout):\n");
    printf("\t  { \"results\": [ { \"id\": \"label\", \"unwrapped\": \"plaintext\" }, ... ] }\n");
    printf("\n");
    printf("\tHash algorithm options (for -u/-B unwrap only):\n");
    printf("\t\t-H <hash>  OAEP hash algorithm: sha1, sha256, sha384, sha512 (default: sha256)\n");
    printf("\t\t-G <hash>  MGF1 hash algorithm: sha1, sha256, sha384, sha512 (default: same as -H)\n");
}

enum class Operation
{
    None,
    WrapKey,
    UnwrapKey,
    SecureUnwrapKey,
    SecureUnwrapBatch,
    SecureUnwrapPerf,
    LocalAesUnwrap,
    BatchUnwrap,
    ReleaseKey,
    Undefined
};

// Check if tracing is to be enabled for SKR in the env.
void set_tracing(void)
{
    auto skr_trace_flag = std::getenv("SKR_TRACE_ON");
    if(skr_trace_flag != nullptr && strlen(skr_trace_flag) > 0)
    {
        if(strcmp(skr_trace_flag, "1") ==0 || strcmp(skr_trace_flag, "2") ==0)
        {
            std::cerr<< "Tracing is enabled" <<std::endl;
            Util::set_trace(true);
            Util::set_trace_level(atoi(skr_trace_flag));
        }
        else
        {
            std::cerr<<"Invalid value for SKR_TRACE_ON!"<<std::endl;
            exit(-1);
        }
    }
}

// Read batch JSON: from file, stdin ("-"), or inline JSON string.
static bool read_batch_input(const std::string &batch_input, std::string &batch_json)
{
    if (batch_input == "-")
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        batch_json = ss.str();
        return true;
    }
    if (!batch_input.empty() && batch_input[0] == '{')
    {
        batch_json = batch_input; // inline JSON on command line
        return true;
    }
    std::ifstream ifs(batch_input);
    if (!ifs.is_open())
    {
        std::cerr << "Failed to open batch JSON file: " << batch_input << std::endl;
        return false;
    }
    std::ostringstream ss;
    ss << ifs.rdbuf();
    batch_json = ss.str();
    return true;
}

static bool parse_unsigned(const char *value, unsigned &out)
{
    try
    {
        size_t pos = 0;
        unsigned long parsed = std::stoul(value, &pos);
        if (pos != strlen(value) || parsed > 100000)
        {
            return false;
        }
        out = static_cast<unsigned>(parsed);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

int main(int argc, char *argv[])
{
#ifdef PLATFORM_UNIX
    ensure_ca_bundle();
#endif
    set_tracing();
    TRACE_OUT("Main started");
    std::string attestation_url;
    std::string nonce;
    std::string sym_key;
    std::string key_enc_key_url;
    std::string oaep_hash = "sha256"; // default OAEP hash
    std::string mgf1_hash;            // empty = same as oaep_hash
    std::string secure_unwrap_algorithm = "A256KWPAD";
    std::string batch_input;           // -B/-S/-P: JSON file path, "-" for stdin, or inline JSON
    SecureUnwrapBatchOptions secure_batch_options;
    unsigned perf_iterations = 10;
    unsigned perf_warmup = 1;
    Operation op = Operation::None;
    Util::AkvCredentialSource akv_credential_source = Util::AkvCredentialSource::Imds;

    int opt;
    while ((opt = getopt(argc, argv, "a:n:k:c:s:uULwrB:H:G:A:S:P:j:N:i:W:XKR:")) != -1)
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
        case 'U':
            op = Operation::SecureUnwrapKey;
            TRACE_OUT("op: %d", static_cast<int>(op));
            break;
        case 'L':
            op = Operation::LocalAesUnwrap;
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
        case 'B':
            batch_input.assign(optarg);
            op = Operation::BatchUnwrap;
            TRACE_OUT("op: BatchUnwrap, input: %s", batch_input.c_str());
            break;
        case 'H':
            oaep_hash.assign(optarg);
            TRACE_OUT("oaep_hash: %s", oaep_hash.c_str());
            break;
        case 'G':
            mgf1_hash.assign(optarg);
            TRACE_OUT("mgf1_hash: %s", mgf1_hash.c_str());
            break;
        case 'A':
            secure_unwrap_algorithm.assign(optarg);
            TRACE_OUT("secure_unwrap_algorithm: %s", secure_unwrap_algorithm.c_str());
            break;
        case 'S':
            batch_input.assign(optarg);
            op = Operation::SecureUnwrapBatch;
            TRACE_OUT("op: SecureUnwrapBatch, input: %s", batch_input.c_str());
            break;
        case 'P':
            batch_input.assign(optarg);
            op = Operation::SecureUnwrapPerf;
            TRACE_OUT("op: SecureUnwrapPerf, input: %s", batch_input.c_str());
            break;
        case 'j':
        case 'N':
        case 'i':
        case 'W':
        case 'R':
        {
            unsigned value = 0;
            if (!parse_unsigned(optarg, value))
            {
                std::cerr << "Invalid numeric value for -" << static_cast<char>(opt) << ": " << optarg << std::endl;
                return EXIT_USAGE;
            }
            if (opt == 'j')
                secure_batch_options.concurrency = value;
            else if (opt == 'N')
                secure_batch_options.replicate_to = value;
            else if (opt == 'i')
                perf_iterations = value;
            else if (opt == 'W')
                perf_warmup = value;
            else
                secure_batch_options.max_retries = value;
            break;
        }
        case 'X':
            secure_batch_options.reuse_connections = false;
            break;
        case 'K':
            secure_batch_options.reuse_tpm_key = false;
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
            result = Util::UnwrapKey(attestation_url, nonce, sym_key, key_enc_key_url, akv_credential_source,
                                    oaep_hash, mgf1_hash);
            std::cout << result << std::endl;
            break;
        case Operation::SecureUnwrapKey:
        {
            std::vector<BYTE> unwrapped = Util::SecureUnwrapKey(
                attestation_url, nonce, sym_key, key_enc_key_url,
                secure_unwrap_algorithm, akv_credential_source);
            std::cout.write(reinterpret_cast<const char *>(unwrapped.data()),
                            static_cast<std::streamsize>(unwrapped.size()));
            std::cout.flush();
            OPENSSL_cleanse(unwrapped.data(), unwrapped.size());
            break;
        }
        case Operation::LocalAesUnwrap:
        {
            std::vector<BYTE> unwrapped = Util::UnwrapKeyWithReleasedAesKey(
                attestation_url, nonce, sym_key, key_enc_key_url,
                secure_unwrap_algorithm, akv_credential_source);
            std::cout.write(reinterpret_cast<const char *>(unwrapped.data()),
                            static_cast<std::streamsize>(unwrapped.size()));
            std::cout.flush();
            OPENSSL_cleanse(unwrapped.data(), unwrapped.size());
            break;
        }
        case Operation::BatchUnwrap:
        {
            std::string batch_json;
            if (!read_batch_input(batch_input, batch_json))
            {
                return EXIT_FAILURE;
            }
            result = Util::UnwrapKeyBatch(attestation_url, nonce, batch_json,
                                          key_enc_key_url, akv_credential_source,
                                          oaep_hash, mgf1_hash);
            std::cout << result << std::endl;
            break;
        }
        case Operation::SecureUnwrapBatch:
        {
            std::string batch_json;
            if (!read_batch_input(batch_input, batch_json))
            {
                return EXIT_FAILURE;
            }
            result = Util::SecureUnwrapKeyBatch(attestation_url, nonce, batch_json,
                                                key_enc_key_url, secure_unwrap_algorithm,
                                                akv_credential_source, secure_batch_options);
            std::cout << result << std::endl;
            OPENSSL_cleanse(&result[0], result.size());
            break;
        }
        case Operation::SecureUnwrapPerf:
        {
            std::string batch_json;
            if (!read_batch_input(batch_input, batch_json))
            {
                return EXIT_FAILURE;
            }
            result = Util::SecureUnwrapPerf(attestation_url, nonce, batch_json,
                                            key_enc_key_url, secure_unwrap_algorithm,
                                            akv_credential_source, secure_batch_options,
                                            perf_iterations, perf_warmup);
            std::cout << result << std::endl;
            break;
        }
        case Operation::ReleaseKey:
            success = Util::ReleaseKey(attestation_url, nonce, key_enc_key_url, akv_credential_source);
            retVal = success ? EXIT_SUCCESS : EXIT_FAILURE;
            break;
        default:
            usage(argv[0]);
            retVal = EXIT_FAILURE;
        }
    }
    catch (skr_error &e)
    {
        std::cerr << e.what() << std::endl;
        retVal = e.exit_code;
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception occured. Details: " << e.what() << std::endl;
        retVal = EXIT_FAILURE;
    }

    return retVal;
}
