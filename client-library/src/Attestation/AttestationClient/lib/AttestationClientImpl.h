//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClientImpl.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <vector>

#include "AttestationLibTypes.h"
#include "AttestationParameters.h"
#include "Tpm.h"
#include "AttestationClient.h"
#include "IsolationInfo.h"
#include "AttestationLibTelemetry.h"

class AttestationClientImpl : public AttestationClient {
public:
    AttestationClientImpl(const std::shared_ptr<attest::AttestationLogger>& log_handle);

    ~AttestationClientImpl() = default;

    /**
     * @brief Enum to indicate the type of logs being retrieved.
     */
    enum class MeasurementType {
        TCG = 0,
        IMA
    };

    /**
     * @brief This function will be used to initiate an attestation request
     * with the Attestation Client lib
     * @param[in] client_params Struct ClientParameters object containing the
     * parameters from the client needed for attestation.
     * @param[out] jwt_token The decrypted jwt token that will be returned by MAA as
     * a response to the attestation request. The memory is allocated by the method
     * and the caller is expected to free this memory by calling Attest::Free() method
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult Attest(const attest::ClientParameters& client_params,
                                     unsigned char** jwt_token) noexcept override;

    /**
     * @brief This API encrypts the data based on the EncryptionType
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the
     * caller to pass symmetric key as the data to be encrypted. The RSA Public key
     * present in the JWT is used to perform the encryption.
     * @param[in] jwt_token: the attestation JWT (null terminated string)
     * @param[in] data: the data to be encrypted
     * @param[in] data_size: the size of the data to be encrypted
     * @param[out] encrypted_data: the encrypted data (the memory is allocated by the method and the
     * caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] encrypted_data_size: the size of the encrypted data
     * @param[out] encryption_metadata: the encryption metadata in form of base64 encoded JSON (the memory 
     * is allocated by the method and the caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] encryption_metadata_size: the size of the encryption metadata
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id.
     * @return In case of success, AttestationResult object with error code ErrorCode::Success
     * will be returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    attest::AttestationResult Encrypt(const attest::EncryptionType encryption_type,
                                      const unsigned char* jwt_token,
                                      const unsigned char* data,
                                      uint32_t data_size,
                                      unsigned char** encrypted_data,
                                      uint32_t* encrypted_data_size,
                                      unsigned char** encryption_metadata,
                                      uint32_t* encryption_metadata_size,
                                      const attest::RsaScheme rsaWrapAlgId = attest::RsaScheme::RsaEs,
                                      const attest::RsaHashAlg rsaHashAlgId = attest::RsaHashAlg::RsaSha1) noexcept override;

    /**
     * @brief This API decrypts the data based on the EncryptionType
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the
     * caller to pass the encrypted symmetric key as input. The RSA Private key
     * present in the TPM is used to perform the decryption.
     * @param[in] encrypted_data: The encrypted data
     * @param[in] encrypted_data_size: The size of encrypted data
     * @param[in] encryption_metadata: The encryption metadata
     * @param[in] encryption_metadata_size: The size of encryption metadata
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id.
     * @param[out] decrypted_data: The decrypted data (the memory is allocated by the method and the
     * caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] decrypted_data_size: The size of decrypted data
     * @return In case of success, AttestationResult object with error code ErrorCode::Success
     * will be returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    attest::AttestationResult Decrypt(const attest::EncryptionType encryption_type,
                                      const unsigned char* encrypted_data,
                                      uint32_t encrypted_data_size,
                                      const unsigned char* encryption_metadata,
                                      uint32_t encryption_metadata_size,
                                      unsigned char** decrypted_data,
                                      uint32_t* decrypted_data_size,
                                      const attest::RsaScheme rsaWrapAlgId = attest::RsaScheme::RsaEs,
                                      const attest::RsaHashAlg rsaHashAlgId = attest::RsaHashAlg::RsaSha1) noexcept override;

    /*
     * @brief This API deallocates the memory previously allocated by the library
     * @param[in] ptr: Pointer to memory block previously allocated
     */
    virtual void Free(void* ptr) noexcept override;

    /**
     * @brief This function will be used to Decrypt a JWT token received from
     * AAS.
     * @param[in] pcr_selector Bitfield representing the selected PCRs
     * @param[in] jwt_token_encrypted The encrypted jwt token received from AAS.
     * @param[out] jwt_token_decrypted The decrypted jwt token.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult DecryptMaaToken(uint32_t pcr_selector, const std::string& jwt_token_encrypted,
                                              std::string& jwt_token_decrypted) noexcept;

    /**
     * @brief This function will be used to retrieve the measurement logs from the guest OS
     * the lib is running on.
     * Note: This function should NOT be called from outside the library. It is
     * made public only for testing purposes.
     * @param[in] type Enum to indicate which log type to retrieve from the
     * system.
     * @param[out] logs The logs will be copied into this parameter.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult GetMeasurements(const MeasurementType& type,
                                              std::vector<unsigned char>& measurement_logs);

    /**
     * @brief This function will be used to retrieve the OS version/type from
     * the guestOS the lib is running on.
     * @param[out] os_info The name and version of OS running on the guest system.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult GetOSInfo(attest::OsInfo& os_info);

    /**
     * @brief This function will be used to retrieve the Tpm related
     * information from the guest system.
     * @param[in] pcr_selector Bitfield of PCRs included in quote
     * @param[out] tpm_info The TpmInfo structure that will be filled by the
     * function.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult GetTpmInfo(uint32_t pcr_selector, attest::TpmInfo& tpm_info);

    /**
     * @brief This function will be used to retrieve the isolation information
     * which include the isolation type and the evidence
     * @param[out] isolation_info The IsolationInfo structure that will be filled by the
     * function.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult GetIsolationInfo(attest::IsolationInfo& isolation_info);

    /**
     * @brief This function will be used to create a payload from the
     * attestation parameters that will be sent to AAS for attestation.
     * @param[in] params The AttestationParameters structure that contains the
     * info that needs to be sent with the attestation request.
     * @param[out] payload json string that will be sent to AAS for
     * attestation.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult CreatePayload(const attest::AttestationParameters& params,
                                            std::string& payload);

    /**
     * @brief This function will be used to parse the client_payload (which is a
     * null termated json string) and populate the key-value pairs in a map
     * @param[in] client_payload The client payload which is a null terminated json string
     * @param[out] client_payload_map The client payload map that will be filled by this function
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult ParseClientPayload(const unsigned char* client_payload,
                                                 std::unordered_map<std::string, std::string>& client_payload_map);
    /**
     * @brief This function will be used to parse the JSON response
     * received after attestation
     * @param[in] json response string received from MAA.
     * @param[out] The encrypted token parsed from the JSON response
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult ParseMaaResponse(const std::string& jsonResponse,
        std::string& token);

private:
    /**
     * @brief Get the list of PCR from the client configuration & platform
     */
    attest::PcrList GetAttestationPcrList();

    /**
     * @brief This function will be used to retrieve the attestation parameters
     * needed to send with the attestation request to AAS.
     * @param[in] client_payload The client payload that will be copied over to
     * the params object.
     * @param[in] pcr_selector Bitfield of PCRs included in the TPM quote
     * @param[out] params The AttestationParameters structure that will be
     * filled by the function.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult getAttestationParameters(const std::unordered_map<std::string,
                                                                                std::string>& client_payload,
                                                       uint32_t pcr_selector,
                                                       attest::AttestationParameters& params);

    /**
     * @brief This function will be used to send the attestation request to the
     * AAS endpoint.
     * @param[in] params The AttestationParameters structure that contains the
     * info that needs to be sent with the attestation request..
     * @param[out] jwt_token_encrypted The jwt token that will be returned by AAS will be
     * copied to this parameter
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult sendAttestationRequest(const attest::AttestationParameters& params,
                                                     std::string& jwt_token_encrypted);

    /**
     * @brief This function will be used to create and send a HTTP request to
     * AAS for attestation.
     * @param[in] payload json string that will be sent to AAS for
     * attestation.
     * @param[out] response The response string received from AAS.
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    attest::AttestationResult sendHttpRequest(const std::string& payload,
                                              std::string& response);  

    std::string attestation_url_;
};
