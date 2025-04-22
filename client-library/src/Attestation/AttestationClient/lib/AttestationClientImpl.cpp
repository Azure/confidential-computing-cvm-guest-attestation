//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClientImpl.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <math.h>
#include <numeric>
#include <cstring>
#ifdef PLATFORM_UNIX
#include <unistd.h>
#else
#include <windows.h>
#include <versionhelpers.h>
#endif

#include <curl/curl.h>
#include <json/json.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "Exceptions.h"
#include "AttestationHelper.h"

#include "Logging.h"
#include "AttestationClientImpl.h"
#include "AttestationLibUtils.h"
#include "AttestationLibConst.h"
#include "TpmUnseal.h"
#include "ImdsOperations.h"
#include "HclReportParser.h"
#include "TpmCertOperations.h"

#define MAX_ATTESTATION_RETRIES 3

#ifdef PLATFORM_UNIX


#ifdef G_TEST
constexpr char g_os_release_path[] = "./test-os-release";
#else
constexpr char g_os_release_path[] = "/etc/os-release";
#endif

constexpr char g_distro_name_key[] = "NAME";
constexpr char g_distro_version_key[] = "VERSION_ID";

// For Linux OS, this field is not application and will be ignored by the
// attestation service.
constexpr char g_os_build_str[] = "NotApplication";

#else

constexpr char g_distro_name_str[] = "Microsoft";

#endif

constexpr char azure_guest_protocol[] = "https://";
constexpr char azure_guest_url[] = "/attest/AzureGuest?api-version=2020-10-01";

using namespace attest;

AttestationClientImpl::AttestationClientImpl(const std::shared_ptr<AttestationLogger>& logger) {
    SetLogger(logger);
}

AttestationResult AttestationClientImpl::Attest(const ClientParameters& client_params,
                                                unsigned char** jwt_token_out) noexcept {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    // Validate the token to make sure that the input parameter is not empty.
    // Check the Version of the structure.
    if (client_params.version > CLIENT_PARAMS_VERSION ||
        client_params.attestation_endpoint_url == nullptr ||
        jwt_token_out == nullptr) {
        CLIENT_LOG_ERROR("Invalid input parameter");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid input parameter");
        return result;
    }

    TpmCertOperations tpm_cert_ops;
    bool is_ak_cert_renewal_required = false;
    if ((result = tpm_cert_ops.IsAkCertRenewalRequired(is_ak_cert_renewal_required)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failure while checking AkCert Renewal state %s", result.description_.c_str());
        if (result.tpm_error_code_ != 0) {
            CLIENT_LOG_ERROR("Internal TPM Error occurred, Tpm Error Code: %d", result.tpm_error_code_);
            return result;
        } else if (result.code_ == attest::AttestationResult::ErrorCode::ERROR_AK_CERT_PROVISIONING_FAILED) {
            CLIENT_LOG_ERROR("Attestation Key cert provisioning delayed. Please try attestation after some time.");
            result.description_ = std::string("AK cert provisioning delayed. Please try attestation after some time.");
            return result;
        }
    }

    result = AttestationResult::ErrorCode::SUCCESS;
    if (is_ak_cert_renewal_required) {
        if ((result = tpm_cert_ops.RenewAndReplaceAkCert()).code_ != AttestationResult::ErrorCode::SUCCESS) {
            CLIENT_LOG_ERROR("Failed to renew AkCert, description: %s with error code: %d", result.description_, static_cast<int>(result.code_));
            if (telemetry_reporting.get() != nullptr) {
                telemetry_reporting->UpdateEvent("AkRenew", 
                                                "Failed to renew AkCert, error description: " + result.description_, 
                                                TelemetryReportingBase::EventLevel::AK_RENEW_UNEXPECTED_ERROR);
            }
        }
    }

    result = AttestationResult::ErrorCode::SUCCESS;

    std::string url = std::string(const_cast<char*>(reinterpret_cast<const char*>(client_params.attestation_endpoint_url)));
    // parse the url and extract the dns
    std::string dns;
    if ((result = url::ParseURL(url, dns)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        return result;
    }

    // Copy attestation endpoint and access token to member variables.
    attestation_url_ = std::string(std::string(azure_guest_protocol))
                                  .append(dns)
                                  .append(std::string(azure_guest_url));
    CLIENT_LOG_INFO("Attestation URL - %s", attestation_url_.c_str());
 
    AttestationParameters params = {};
    std::unordered_map<std::string, std::string> client_payload_map;
    if (client_params.client_payload != nullptr) {
        if ((result = ParseClientPayload(client_params.client_payload, client_payload_map)).code_ != 
                                                    AttestationResult::ErrorCode::SUCCESS) {
            return result;
        }
    }

    uint32_t pcr_selector = client_params.version < 2 ? 0 : client_params.pcr_selector;
    if((result = getAttestationParameters(client_payload_map, pcr_selector,
                                          params)).code_ !=
                                                    AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to get attestation parameters with error:%s",
            result.description_.c_str());
        return result;
    }

    if(!params.Validate()) {
        // One or more parameters are invalid. Log error indicating validation
        // failed along with function name and error string.
        CLIENT_LOG_ERROR("Failed to validate attestation parameters");
        result = AttestationResult::ErrorCode::ERROR_ATTESTATION_PARAMETERS_VALIDATION_FAILED;
        result.description_ = std::string("Failed to validate parameters for attestation request.");
        return result;
    }

    std::string maa_response;
    std::string token_encrypted;
    std::string token_decrypted;
    uint8_t attestation_retries = 0;
    while(true) {
        if((result = sendAttestationRequest(params, maa_response)).code_ !=
            AttestationResult::ErrorCode::SUCCESS) {
            CLIENT_LOG_ERROR("Failed to send attestation request with error:%s",
                result.description_.c_str());
            return result;
        }

        if((result = ParseMaaResponse(maa_response, token_encrypted)).code_ !=
            AttestationResult::ErrorCode::SUCCESS){
            CLIENT_LOG_ERROR("Failed to parse the MAA response: %s",
                result.description_.c_str());
            return result;
        }

        if((result = DecryptMaaToken(pcr_selector, token_encrypted, token_decrypted)).code_ != AttestationResult::ErrorCode::SUCCESS) {
            CLIENT_LOG_ERROR("Failed to Decrypt with error:%d description:%s\n",
                static_cast<int>(result.code_),
                result.description_.c_str());

            // If decryption of the jwt fails, retrying attestation to make sure this is not
            // a transient failure. This will prevent false positive reporting the VM health.
            if(attestation_retries < MAX_ATTESTATION_RETRIES) {
                CLIENT_LOG_INFO("Retyring Attestation");
                std::this_thread::sleep_for(
                    std::chrono::seconds(
                        static_cast<long long>(5 * pow(2.0, static_cast<double>(attestation_retries++)))));
                continue;
            }

            CLIENT_LOG_ERROR("Maximum attestation retries exceeded");
            return result;
        }

        CLIENT_LOG_INFO("Successfully attested and decrypted response.");
        break;
    }

    unsigned char *jwt_token = (unsigned char*) malloc((sizeof(unsigned char) * token_decrypted.size()) + 1); // allocating an extra byte for the null char at the end
    std::memcpy(jwt_token, token_decrypted.data(), token_decrypted.size());
    jwt_token[token_decrypted.size()] = '\0';
    *jwt_token_out = jwt_token;
    return result;
}

AttestationResult AttestationClientImpl::Encrypt(const attest::EncryptionType encryption_type,
                                                 const unsigned char* jwt_token,
                                                 const unsigned char* data,
                                                 uint32_t data_size,
                                                 unsigned char** encrypted_data,
                                                 uint32_t* encrypted_data_size,
                                                 unsigned char** encryption_metadata,
                                                 uint32_t* encryption_metadata_size,
                                                 const attest::RsaScheme rsaWrapAlgId,
                                                 const attest::RsaHashAlg rsaHashAlgId) noexcept {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (jwt_token == nullptr ||
        data == nullptr ||
        data_size <= 0 ||
        encrypted_data == nullptr ||
        encrypted_data_size == nullptr ||
        encryption_metadata == nullptr ||
        encryption_metadata_size == nullptr ||
        encryption_type != attest::EncryptionType::NONE) {
        CLIENT_LOG_ERROR("Invalid input parameter");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid input parameter");
        return result;
    }

    std::string jwt_token_str(const_cast<char*>(reinterpret_cast<const char*>(jwt_token)));
    // Extract JWK info from attestation JWT
    std::string n_base64url, e_base64url;
    if (!jwt::ExtractJwkInfoFromAttestationJwt(jwt_token_str, n_base64url, e_base64url)) {
        CLIENT_LOG_ERROR("Error while extracting JWK info from JWT");
        result.code_ = AttestationResult::ErrorCode::ERROR_EXTRACTING_JWK_INFO;
        result.description_ = std::string("Error while extracting JWK info from JWT");
        return result;
    }

    // Convert JWK to RSA public key
    BIO* pkey_bio = BIO_new(BIO_s_mem());
    if ((result = crypto::ConvertJwkToRsaPubKey(pkey_bio, n_base64url, e_base64url)).code_ != 
                                                                AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to convert JWK to RSA Public key");
        BIO_free(pkey_bio);
        return result;
    }

    // For encryption type 'NONE', the data is expected to be the symmetric key
    std::vector<unsigned char> in_data(data, data + data_size);
    std::vector<unsigned char> out_data;
    // Use RSA public key to encrypt the input data
    if ((result = crypto::EncryptDataWithRSAPubKey(pkey_bio, rsaWrapAlgId, rsaHashAlgId, in_data, out_data)).code_ !=
        AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to encrypt the buffer");
        BIO_free(pkey_bio);
        return result;
    }

    *encrypted_data = (unsigned char*)malloc(sizeof(unsigned char) * out_data.size());
    std::memcpy((void*)*encrypted_data, (void*)out_data.data(), out_data.size());
    *encrypted_data_size = out_data.size();
    *encryption_metadata = nullptr;
    *encryption_metadata_size = 0;

    BIO_free(pkey_bio);
    return result;
}

AttestationResult AttestationClientImpl::Decrypt(const attest::EncryptionType encryption_type,
                                                 const unsigned char* encrypted_data,
                                                 uint32_t encrypted_data_size,
                                                 const unsigned char* ,
                                                 uint32_t ,
                                                 unsigned char** decrypted_data,
                                                 uint32_t* decrypted_data_size,
                                                 const attest::RsaScheme rsaWrapAlgId,
                                                 const attest::RsaHashAlg rsaHashAlgId,
                                                 uint32_t pcr_bitmask) noexcept {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (encrypted_data == nullptr ||
        encrypted_data_size <= 0  ||
        decrypted_data == nullptr ||
        decrypted_data_size == nullptr ||
        encryption_type != attest::EncryptionType::NONE) {
        CLIENT_LOG_ERROR("Invalid input parameter");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid input parameter");
        return result;
    }
    try {
        Tpm tpm;
        PcrList list = attest::GetAttestationPcrList(pcr_bitmask);
        PcrSet pcrValues = tpm.GetPCRValues(list, attestation_hash_alg);

        // For encryption type 'NONE', the encrypted data is expected to be the encrypted symmetric key
        std::vector<unsigned char> in_data(encrypted_data, encrypted_data + encrypted_data_size);
        std::vector<unsigned char> out_data;
        out_data = tpm.DecryptWithEphemeralKey(pcrValues, in_data, rsaWrapAlgId, rsaHashAlgId);

        *decrypted_data = (unsigned char*)malloc(sizeof(unsigned char) * out_data.size());
        std::memcpy((void*)*decrypted_data, (void*)out_data.data(), out_data.size());
        *decrypted_data_size = out_data.size();
    }
    catch (const Tss2Exception& e) {
        // Since tss2 errors are throw Tss2Exception exception. Catch it here.
        result.code_ = AttestationResult::ErrorCode::ERROR_DATA_DECRYPTION_TPM_ERROR;
        result.tpm_error_code_ = e.get_rc();
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Failed Tpm operation:%d Error:%s",
            result.tpm_error_code_,
            result.description_.c_str());
        return result;
    }
    catch (const std::exception& e) {
        // Since tss2 errors are throw runtime error exception. Catch it here.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Tpm internal error:%s",
            result.description_.c_str());
        return result;
    }
    catch (...) {
        // Unknown exception.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string("Error: Unknown internal error");

        CLIENT_LOG_ERROR("Tpm internal error:%s",
            result.description_.c_str());
        return result;
    }
    return result;
}

void AttestationClientImpl::Free(void* ptr) noexcept {
    if (ptr == nullptr) {
        return;
    }

    free(ptr);
}

AttestationResult AttestationClientImpl::DecryptMaaToken(uint32_t pcr_selector, const std::string& jwt_token_encrypted,
                                                         std::string& jwt_token_decrypted) noexcept {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    jwt_token_decrypted = std::string();

    //Validate jwt_token to make sure its not empty.
    if(jwt_token_encrypted.empty()){
        CLIENT_LOG_ERROR("Invalid JWT");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = std::string("Invalid JWT");
        return result;
    }
    
    std::string jwt = jwt_token_encrypted;

    // Decode the encrypted jwt since its base64url encoded by the service.
    attest::Buffer jwt_encrypted_decoded = attest::base64::base64url_to_binary(jwt);
    std::string jwt_encrypted_str(jwt_encrypted_decoded.begin(), jwt_encrypted_decoded.end());

    Json::Value response;
    Json::Reader reader;
    bool success = reader.parse(jwt_encrypted_str.c_str(), response);
    if(!success) {
        CLIENT_LOG_ERROR("Failed to parse AAS response");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = std::string("Failed to parse AAS response");
        return result;
    }

    attest::Buffer encrypted_inner_key;
    std::string err;
    if(!GetEncryptedInnerKey(response,
                              encrypted_inner_key,
                              err)){
        CLIENT_LOG_ERROR("Failed to get encrypted inner key from AAS response");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = err;
        return result;
    }

    EncryptionParameters encryption_params;
    if(!GetEncryptionParameters(response,
                                encryption_params,
                                err)) {
        CLIENT_LOG_ERROR("Failed to get encryption parameters for decryption");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = err;
        return result;
    }

    attest::Buffer decrypted_key;
    if((result = DecryptInnerKey(pcr_selector,
                                 encrypted_inner_key,
                                 decrypted_key,
                                 attest::RsaScheme::RsaEs,
                                 attest::RsaHashAlg::RsaSha256)).code_ !=
                                                            AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to decrypt inner key");
        return result;
    }

    CLIENT_LOG_INFO("Successfully Decrypted inner key");

    attest::Buffer jwt_encrypted;
    if(!GetEncryptedJwt(response,
                        jwt_encrypted,
                        err)) {
        CLIENT_LOG_ERROR("Failed to get encrypted jwt from response");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = err;
        return result;
    }

    if(!DecryptJwt(encryption_params,
                   decrypted_key,
                   jwt_encrypted,
                   jwt_token_decrypted,
                   err)) {
        CLIENT_LOG_ERROR("Failed to decrypt jwt");
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_FAILED;
        result.description_ = err;
        return result;
    }
    return result;
}

AttestationResult AttestationClientImpl::ParseClientPayload(const unsigned char* client_payload,
                                                            std::unordered_map<std::string, 
                                                                               std::string>& client_payload_map) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (client_payload == nullptr) {
        CLIENT_LOG_ERROR("Invalid input parameter");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid input parameter");
        return result;
    }

    Json::Value root;
    Json::Reader reader;
    std::string client_payload_str(const_cast<char*>(reinterpret_cast<const char*>(client_payload)));
    bool parsing_successful = reader.parse(client_payload_str, root);
    if (!parsing_successful) {
        CLIENT_LOG_ERROR("Error parsing the client payload Json");
        result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid client payload Json");
        return result;
    }

    for (Json::Value::iterator it = root.begin(); it != root.end(); ++it) {
        client_payload_map[it.key().asString()] = it->asString();
    }

    return result;
}

AttestationResult AttestationClientImpl::getAttestationParameters(
                                                const std::unordered_map<std::string,
                                                                         std::string>& client_payload,
                                                uint32_t pcr_selector,
                                                AttestationParameters& params) {


    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    OsInfo os_info;
    if((result = GetOSInfo(os_info)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to get OS information with error:%s",
                         result.description_.c_str());
        return result;
    }

    IsolationInfo isolation_info;
    if ((result = GetIsolationInfo(isolation_info)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to get the isolation information with error:%s",
            result.description_.c_str());
        return result;
    }

    // Create a MeasurementType to indicate we are asking for TCG logs.Going forward,
    // we can take the log type as an parameter to this function.
    MeasurementType log_type = MeasurementType::TCG;
    Buffer tcg_logs;

    // Note: This function should never fail. It will return empty logs in
    // case logs were not found.
    if((result = GetMeasurements(log_type, tcg_logs)).code_ !=
                                                AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to get measurement logs with error:%s",
                         result.description_.c_str());
        return result;
    }

    TpmInfo tpm_info;
    if((result = GetTpmInfo(pcr_selector, tpm_info)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to get Tpm information with error:%s",
                         result.description_.c_str());
        return result;
    }

    params.client_payload_ = client_payload;
    params.os_info_ = os_info;
    params.tcg_logs_ = tcg_logs;
    params.tpm_info_ = tpm_info;
    params.isolation_info_ = isolation_info;

    return result;
}

AttestationResult AttestationClientImpl::sendAttestationRequest(
                                                          const AttestationParameters& params,
                                                          std::string& jwt_token_encrypted) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    jwt_token_encrypted = std::string();

    std::string payload;
    if((result = CreatePayload(params, payload)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to create attestation payload with error:%s",
                         result.description_.c_str());
        return result;
    }

    std::string response;
    if((result = sendHttpRequest(payload, response)).code_ !=
                                                AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to send http request with error:%s",
                         result.description_.c_str());
        return result;
    }

    jwt_token_encrypted = response;
    
    return result;
}

AttestationResult AttestationClientImpl::GetMeasurements(
                                            const AttestationClientImpl::MeasurementType& type,
                                            Buffer& measurement_logs) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    // Note: This function will be used to get logs from the device. The
    // measurements that will be retrieved can either be tcg logs for bios
    // measurements or IMA logs for kernel measurements. Currently, we only
    // support tcg logs, support for ima logs will be added to this function
    // later.
    if(type == MeasurementType::TCG) {
        // Note:This function will never return failure. In case Tcg logs are not
        // found, empty logs will be returned to the caller that will indicate that
        // TCG logs are not present for the OS type.

        try {
            Tpm tpm;
            measurement_logs = tpm.GetTcgLog();
        }
        catch(...) {
            CLIENT_LOG_WARN("TCG logs not found on device");
        }
        return result;
    }

    // For now, the MeasurementType should always be TCG. We will add support for IMA
    // logs later.
    CLIENT_LOG_ERROR("Invalid input parameter");
    result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
    result.description_ = std::string("Invalid input parameter");
    return result;
}

AttestationResult AttestationClientImpl::GetTpmInfo(uint32_t pcr_selector, TpmInfo& tpm_info) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    try {

        Tpm tpm;
        Buffer aik_cert = tpm.GetAIKCert();

        Buffer aik_pub = tpm.GetAIKPub();

        attest::PcrList pcrs = attest::GetAttestationPcrList(pcr_selector);

        // Unpack the PCR quote to get the raw quote and arrange the quote
        // signature in a format expected by AAS.
        PcrQuote pcr_quote_marshaled = tpm.GetPCRQuote(pcrs, attestation_hash_alg);
        PcrQuote pcr_quote = tpm.UnpackPcrQuoteToRSA(pcr_quote_marshaled);

        // We get the pcr values from the SHA256 bank since we expect the TCG logs
        // to also have SHA256 hash entries.
        PcrSet pcr_values = tpm.GetPCRValues(pcrs, attestation_hash_alg);

        EphemeralKey enc_key = tpm.GetEphemeralKey(pcr_values);

        tpm_info.aik_cert_ = aik_cert;
        tpm_info.aik_pub_ = aik_pub;
        tpm_info.pcr_values_ = pcr_values;
        tpm_info.pcr_quote_ = pcr_quote;
        tpm_info.encryption_key_ = enc_key;
    }
    catch(const Tss2Exception& e) {
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_OPERATION_FAILURE;
        result.tpm_error_code_ = e.get_rc();
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Failed Tpm operation:%d Error:%s",
                          result.tpm_error_code_,
                          result.description_.c_str());
        return result;
    }
    catch(const std::exception& e) {
        // Since tss2 errors are throw runtime error exception. Catch it here.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Tpm internal error:%s",
                          result.description_.c_str());
        return result;
    }
    catch(...) {
        // Unknown exception.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string("Unknown error");

        CLIENT_LOG_ERROR("Tpm internal error:%s",
                          result.description_.c_str());
        return result;
    }
    return result;
}

AttestationResult AttestationClientImpl::GetOSInfo(OsInfo& os_info) {

    CLIENT_LOG_INFO("Retrieving OS Info");
    os_info = OsInfo();

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

#ifdef PLATFORM_UNIX
    std::unordered_map<std::string, std::string> os_release_entries;
    if(!os::ParseOSReleaseFile(g_os_release_path, std::string("="), os_release_entries)) {
        CLIENT_LOG_ERROR("Failed to parse file path to retrieve OS info");
        result.code_ = AttestationResult::ErrorCode::ERROR_FAILED_TO_GET_OS_INFO;
        result.description_ = std::string("Failed to parse file path to retrieve OS info");

        return result;
    }

    auto entry = os_release_entries.find(std::string(g_distro_name_key));
    if(entry == os_release_entries.end()) {
        CLIENT_LOG_ERROR("Distro name not found");
        result.code_ = AttestationResult::ErrorCode::ERROR_FAILED_TO_GET_OS_INFO;
        result.description_ = std::string("Distro name not found");
        return result;
    }
    std::string distro_name = entry->second;

    entry = os_release_entries.find(std::string(g_distro_version_key));
    std::string version_str =  std::string("1.0");
    if(entry == os_release_entries.end()) {
        CLIENT_LOG_ERROR("Distro version not found, using default version");
    } else {
        version_str = entry->second;
    }

    uint32_t major_version = 0;
    uint32_t minor_version = 0;
    if(!os::ParseVersionString(version_str, major_version, minor_version)) {
        CLIENT_LOG_ERROR("Failed to process distro version, using default version");
        major_version = 1;
        minor_version = 0;
    }
    os_info.type = OsType::LINUX;
    os_info.distro_name = distro_name;
    os_info.distro_version_major = major_version;
    os_info.distro_version_minor = minor_version;
    os_info.build = std::string(g_os_build_str);
#else
    os_info.type = OsType::WINDOWS;

    // For windows, distro name will be an a static string "Microsoft".
    os_info.distro_name = std::string(g_distro_name_str);

    std::string build;
    uint32_t major_version = 0;
    uint32_t minor_version = 0;
    if(!os::GetWindowsVersion(major_version, minor_version, build)) {
        CLIENT_LOG_ERROR("Failed to get windows version");
        result.code_ = AttestationResult::ErrorCode::ERROR_FAILED_TO_GET_OS_INFO;
        result.description_ = std::string("Failed to get windows version");
        return result;
    }

    os_info.distro_version_major = major_version;
    os_info.distro_version_minor = minor_version;
    os_info.build = build;
#endif
    return result;
}

AttestationResult AttestationClientImpl::GetIsolationInfo(IsolationInfo& isolation_info) {
    CLIENT_LOG_INFO("Retrieving Isolation Info");
    isolation_info = IsolationInfo();
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    Buffer hcl_report;
    std::string isolation_info_str = std::string();
    try {
        Tpm tpm;
        hcl_report = tpm.GetHCLReport();
        // If HCL report exists, then it's a CVM
        isolation_info.isolation_type_ = attest::IsolationType::SEV_SNP;
        isolation_info_str = "CVM";
    }
    catch (...) {
        isolation_info.isolation_type_ = attest::IsolationType::TRUSTED_LAUNCH;
        isolation_info_str = "TVM";
    }

    if(telemetry_reporting.get() != nullptr) {
        telemetry_reporting->UpdateEvent("IsolationInfo", 
                                            isolation_info_str, 
                                            attest::TelemetryReportingBase::EventLevel::VM_SECURITY_TYPE);
    }

    if (isolation_info.isolation_type_ == attest::IsolationType::SEV_SNP) {
        Buffer snp_report, runtime_data;
        HclReportParser hcl_report_parser;
        if ((result = hcl_report_parser.ExtractSnpReportAndRuntimeDataFromHclReport(hcl_report,
                                                                                    snp_report,
                                                                                    runtime_data)).code_ != AttestationResult::ErrorCode::SUCCESS) {
            return result;
        }

        isolation_info.snp_report_ = snp_report;
        isolation_info.runtime_data_ = runtime_data;
        ImdsOperations imds_ops;
        std::string vcek_cert;
        if ((result = imds_ops.GetVCekCert(vcek_cert)).code_ != AttestationResult::ErrorCode::SUCCESS) {
            CLIENT_LOG_ERROR("Failed to retrieve the VCek Cert from THIM");
            return result;
        }

        isolation_info.vcek_cert_ = vcek_cert;
    }
    return result;
}

AttestationResult AttestationClientImpl::CreatePayload(const AttestationParameters& params,
                                                       std::string& payload) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    Json::Value attestation_info = params.ToJson();

    Json::StreamWriterBuilder builder;
    const std::string attestation_info_str = Json::writeString(builder, attestation_info);

    std::string attestation_info_str_encoded = base64::
                                               binary_to_base64url(Buffer(attestation_info_str.begin(),
                                                                          attestation_info_str.end()));
    Json::Value root;
    root[JSON_ATTESTATION_INFO_KEY] = attestation_info_str_encoded;

    const std::string payload_str = Json::writeString(builder, root);

    payload = payload_str;
    return result;
}

AttestationResult AttestationClientImpl::sendHttpRequest(const std::string& payload,
                                                         std::string& jwt_encrypted) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    std::string http_response;
   if((result = curl::SendRequest(attestation_url_,
                                   payload,
                                   http_response)).code_ != AttestationResult::ErrorCode::SUCCESS) {
        CLIENT_LOG_ERROR("Failed to send http request with error:%s",
                         result.description_.c_str());
        return result;
    }

    // TODO: Explore having a common json schema between client and service.

    // Return the http response to the caller. The response will be
    // interpretted and decrypted jwt returned in the Decrypt() call.
    jwt_encrypted = http_response;
    return result;
}

AttestationResult AttestationClientImpl::ParseMaaResponse(const std::string& maa_response,
                                                          std::string& token) {

    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    // The response from MAA is in the form of a Json string
    // To get the encrypted token we parse the json string and return the token
    Json::Value response;
    Json::Reader reader;
    bool success = reader.parse(maa_response.c_str(), response);

    if (!success) {
        // Error while parsing the Json
        CLIENT_LOG_ERROR("Failed to parse the Attestation response");
        result.code_ = AttestationResult::ErrorCode::ERROR_PARSING_ATTESTATION_RESPONSE;
        result.description_ = std::string("Failed to parse MAA response Json file");
        return result;
    }
    const std::string parsed_token = response["token"].asString();

    // return the encrypted token
    token = parsed_token;
    return result;
}

