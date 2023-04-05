//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationLibTypes.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <string>
#include <unordered_map>

#define CLIENT_PARAMS_VERSION 1 // V1 contains version, attestation_endpoint_url, client_payload

namespace attest {

    class AttestationResult {
    public:

        /**
         * Enum to represent error codes returned by the attestation client lib.
         */
        enum class ErrorCode {
            SUCCESS = 0,
            ERROR_CURL_INITIALIZATION = -1,
            ERROR_RESPONSE_PARSING = -2,
            ERROR_MSI_TOKEN_NOT_FOUND = -3,
            ERROR_HTTP_REQUEST_EXCEEDED_RETRIES = -4,
            ERROR_HTTP_REQUEST_FAILED = -5,
            ERROR_ATTESTATION_FAILED = -6,
            ERROR_SENDING_CURL_REQUEST_FAILED = -7,
            ERROR_INVALID_INPUT_PARAMETER = -8,
            ERROR_ATTESTATION_PARAMETERS_VALIDATION_FAILED = -9,
            ERROR_FAILED_MEMORY_ALLOCATION = -10,
            ERROR_FAILED_TO_GET_OS_INFO = -11,
            ERROR_TPM_INTERNAL_FAILURE = -12,
            ERROR_TPM_OPERATION_FAILURE = -13,
            ERROR_JWT_DECRYPTION_FAILED = -14,
            ERROR_JWT_DECRYPTION_TPM_ERROR = -15,
            ERROR_INVALID_JSON_RESPONSE = -16,
            ERROR_EMPTY_VCEK_CERT = -17,
            ERROR_EMPTY_RESPONSE = -18,
            ERROR_EMPTY_REQUEST_BODY = -19,
            ERROR_HCL_REPORT_PARSING_FAILURE = -20,
            ERROR_HCL_REPORT_EMPTY = -21,
            ERROR_EXTRACTING_JWK_INFO = -22,
            ERROR_CONVERTING_JWK_TO_RSA_PUB = -23,
            ERROR_EVP_PKEY_ENCRYPT_INIT_FAILED = -24,
            ERROR_EVP_PKEY_ENCRYPT_FAILED = -25,
            ERROR_DATA_DECRYPTION_TPM_ERROR = -26,
            ERROR_PARSING_DNS_INFO = -27,
            ERROR_PARSING_ATTESTATION_RESPONSE = -28
        };

        AttestationResult() = default;
        ~AttestationResult() = default;

        AttestationResult(ErrorCode e): code_(e) {}

        ErrorCode code_ = ErrorCode::SUCCESS;
        uint32_t tpm_error_code_ = 0;
        std::string description_;
    };


    /**
     * @brief Structure to hold information the caller needs to send to the client
     * lib.
     */
    struct ClientParameters {
        /**
         * Struct version
         */
        uint32_t version;

        /**
         * Attestation service endpoint to which the attestation request will be sent.
         * This is expected to be null terminated string.
         */
        const unsigned char* attestation_endpoint_url = nullptr;

        /**
         * key-value pair of data to be included in MAA token. For example - nonce
         * This is expected to be null terminated JSON string. 
         * Sample client_payload: "{\"key1\":\"value1\",\"key2\":\"value2\"}"
         */
        const unsigned char* client_payload = nullptr;
    };

    enum class OsType {
        LINUX,
        WINDOWS,
        INVALID
    };

#ifndef RsaScheme_enum
#define RsaScheme_enum
    // Borrowed from tss2_tpm2_types.h, which is not public
    enum RsaScheme : uint16_t
    {
        RsaNull = 0x0010, // TPM2_ALG_NULL
        RsaEs = 0x0015,   // TPM2_ALG_RSAES
        RsaOaep = 0x0017, // TPM2_ALG_OAEP
    };

    enum RsaHashAlg : uint16_t
    {
        RsaSha1 = 0x0004, // TPM2_ALG_SHA1
        RsaSha256 = 0x000B, // TPM2_ALG_SHA256
        RsaSha384 = 0x000C, // TPM2_ALG_SHA384
        RsaSha512 = 0x000D, // TPM2_ALG_SHA512
    };
#endif

    enum class EncryptionType {
        NONE
    };

    /**
     *@brief Structure to hold OS information.
     */
    struct OsInfo {
        OsType type = OsType::INVALID; /**< Type of OS, Linux or Windows*/
        std::string distro_name; /**< Name of the distribution. Application only for Linux OS. For Windows, this field is given a static value that is not consumed.*/
        std::string build; /**< Build number of the OS. Application only for Windows. For Linux, this field is given a static value that is not consumed.*/
        uint32_t distro_version_major = 0; /**< Distro version major number.*/
        uint32_t distro_version_minor = 0; /**< Distro version minor number.*/
    };
} // attest
