//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationLibUtils.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <fstream>
#include <unordered_map>

#include <AttestationTypes.h>

#include "AttestationLibTypes.h"

namespace attest {

const attest::HashAlg attestation_hash_alg = attest::HashAlg::Sha256;

/**
 * @brief This function will be use the list of PCRs that will be used for attestation.
 * This list is different based on whether the client is running on Windows or Linux.
 * @return attest::PcrList that contains the pcr indices to be used for attestation.
 */
PcrList GetAttestationPcrList();

namespace os {

#ifdef PLATFORM_UNIX

/**
 * @brief This function will be used to retrieve the os information from a file
 * stream.
 * @param[in] os_release_path The path of the file we need to parse.
 * @param[in] delim The expected separator in the key value pair.
 * @param[out] entries The map of all key value pairs present in the file.
 * @return On success, the function returns true and the map entries are filled
 * accordingly. On failure. false is returned.
 */
bool ParseOSReleaseFile(const char* os_release_path,
                        const std::string& delim,
                        std::unordered_map<std::string, std::string>& entries);

/**
 * @brief Thie function will be used to retrieve the OS version.
 * @param[in] str The version string that will be used to extract the version
 * numbers.
 * @param[out] major_version The major version that is extracted from str.
 * @param[out] minor_version The minor version that is extracted from str.
 * @return On sucess, the function returns true and the output parameters are
 * set to valid values. On failure, it returns false.
 */
bool ParseVersionString(const std::string& str,
                        uint32_t& major_version,
                        uint32_t& minor_version);

#else

/**
 * @brief Thie function will be used to retrieve the Windows OS version and build
 * number.
 * @param[out] major_version The major version of the OS.
 * @param[out] minor_version The minor version of the OS
 * @param[out] build The build number of the OS.
 * @return On sucess, the function return true and the output parameters are
 * set to valid values. On failure, it returns false.
 */
bool GetWindowsVersion(uint32_t& major_version,
                       uint32_t& minor_version,
                       std::string& os_build);

#endif

} // os

namespace curl {

/**
 * @brief Thie function will be used to send a http request to a provided
 * endpoint.
 * @param[in] url The url of the end point to which the request will be sent.
 * @param[in] payload The payload to be sent.
 * @param[out] http_response The response received from the endpoint.
 * @return On sucess, the function returns
 * AttestationResult::ErrorCode::SUCCESS and the http_response is set to the
 * response from the end point. On failure, AttestationResult::ErrorCode is
 * returned.
 */
AttestationResult SendRequest(const std::string& url,
                              const std::string& payload,
                              std::string& http_response);
} // curl

namespace jwt {
    /**
     * @brief This function will be used to retrieve the JWK Info
     * from the attestation JWT
     * @param[in] jwt The attestation JWT.
     * @param[out] n The modulus value of the RSA public key
     * @param[out] e The exponent value of the RSA public key
     * @return On success, the function return true and the output parameters are
     * set to valid values. On failure, it returns false.
     */
    bool ExtractJwkInfoFromAttestationJwt(std::string jwt,
                                          std::string& n,
                                          std::string& e);
} // jwt

namespace crypto {
    /**
     * @brief This function will be used to encrypt the input buffer
     * using the RSA public key 
     * @param[in] pkey_bio The RSA public key BIO.
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id.
     * @param[in] input_data The input buffer to be encrypted
     * @param[out] encrypted_data The encrypted output buffer
     * @return On sucess, the function returns
     * AttestationResult::ErrorCode::SUCCESS and the encrypted_data buffer
     * is set. On failure, AttestationResult::ErrorCode is
     * returned.
     */
    AttestationResult EncryptDataWithRSAPubKey(BIO* pkey_bio,
                                               const attest::RsaScheme rsaWrapAlgId,
                                               const attest::RsaHashAlg rsaHashAlgId,
                                               const Buffer& input_data,
                                               Buffer& encrypted_data);

    /**
     * @brief This function will be used to convert the JWK to RSA
     * public key
     * @param[in] pkey_bio The RSA public key BIO.
     * @param[out] n The modulus value of the RSA public key
     * @param[out] e The exponent value of the RSA public key
     * @return On sucess, the function returns
     * AttestationResult::ErrorCode::SUCCESS and pkey_bio BIO
     * is set. On failure, AttestationResult::ErrorCode is
     * returned.
     */
    AttestationResult ConvertJwkToRsaPubKey(BIO* pkey_bio,
                                            const std::string& n,
                                            const std::string& e);
} // crypto

namespace url {
    /**
     * @brief This function will be to parse the URL and extract the
     * domain name info
     * @param[in] url The URL
     * @param[out] domain The domain name extracted from the URL
     * @return On sucess, the function returns
     * AttestationResult::ErrorCode::SUCCESS and domain string
     * is set. On failure, AttestationResult::ErrorCode is
     * returned.
     */
    AttestationResult ParseURL(const std::string& url,
                               std::string& domain);
} // url
} //attest
