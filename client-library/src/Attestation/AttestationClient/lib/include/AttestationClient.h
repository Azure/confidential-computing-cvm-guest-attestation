//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationClient.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <memory>

#include "AttestationLogger.h"
#include "AttestationLibTypes.h"
#include "TelemetryReportingBase.h"

#ifdef ATTESTATIONLIB_EXPORTS
#define DllExports __declspec(dllexport)
#else
#define DllExports
#endif

class AttestationClient {
public:

    /**
     * @brief This API initiates an attestation request to Microsoft Azure Attestation Service (MAA)
     * @param[in] client_params: ClientParameters object containing the following parameters needed 
     * for attestation - attestation url and client payload.
     * @param[out] jwt_token: The decrypted jwt token (null terminated string) returned by MAA as a
     * response to the attestation request. The memory for jwt_token is allocated by the method and
     * the caller is expected to free this memory by calling Attest::Free() method
     * @return In case of success, AttestationResult object with error code ErrorCode::Success is 
     * returned. In case of failure, an appropriate ErrorCode will be set in the AttestationResult 
     * object and error description will be provided.
     */
    virtual attest::AttestationResult Attest(const attest::ClientParameters& client_params,
                                             unsigned char** jwt_token) noexcept = 0;

    /**
     * @brief This API encrypts the data based on the EncryptionType paramter
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the caller to pass
     * symmetric key as the data to be encrypted. The RSA Public key present in the JWT will be 
     * used to perform the encryption.
     * @param[in] jwt_token: the attestation JWT (null terminated string)
     * @param[in] data: the data to be encrypted
     * @param[in] data_size: the size of the data to be encrypted
     * @param[out] encrypted_data: the encrypted data (the memory is allocated by the method and
     * the caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] encrypted_data_size: the size of the encrypted data
     * @param[out] encryption_metadata: the encryption metadata in form of base64 encoded JSON 
     * (the memory is allocated by the method and the caller is expected to free this memory by 
     * calling Attest::Free() method)
     * @param[out] encryption_metadata_size: the size of the encryption metadata
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id.
     * @return In case of success, AttestationResult object with error code ErrorCode::Success is
     * returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    virtual attest::AttestationResult Encrypt(const attest::EncryptionType encryption_type,
                                              const unsigned char* jwt_token,
                                              const unsigned char* data,
                                              uint32_t data_size,
                                              unsigned char** encrypted_data,
                                              uint32_t* encrypted_data_size,
                                              unsigned char** encryption_metadata,
                                              uint32_t* encryption_metadata_size,
                                              const attest::RsaScheme tpm2RsaAlgId = attest::RsaScheme::RsaEs,
                                              const attest::RsaHashAlg tpm2HashAlgId = attest::RsaHashAlg::RsaSha1) noexcept = 0;

    /**
     * @brief This API decrypts the data based on the EncryptionType paramter
     * @param[in] encryption_type: the type of encryption
     * currently the only encryption type supported is 'NONE', which expects the
     * caller to pass the encrypted symmetric key as input. The RSA Private key
     * present in the TPM will be used to perform the decryption.
     * @param[in] encrypted_data: The encrypted data
     * @param[in] encrypted_data_size: The size of encrypted data
     * @param[in] encryption_metadata: The encryption metadata
     * @param[in] encryption_metadata_size: The size of encryption metadata
     * @param[out] decrypted_data: The decrypted data (the memory is allocated by the method and the
     * @param[in] rsaWrapAlgId: Rsa wrap algorithm id. Defaults to RSAES for backcompat with MAA.
     * @param[in] rsaHashAlgId: Rsa hash algorithm id. Defaults to SHA1 for backcompat with mHSM.
     * caller is expected to free this memory by calling Attest::Free() method)
     * @param[out] decrypted_data_size: The size of decrypted data
     * @return In case of success, AttestationResult object with error code ErrorCode::Success
     * will be returned. In case of failure, an appropriate ErrorCode and description will be returned.
     */
    virtual attest::AttestationResult Decrypt(const attest::EncryptionType encryption_type,
                                              const unsigned char* encrypted_data,
                                              uint32_t encrypted_data_size,
                                              const unsigned char* encryption_metadata,
                                              uint32_t encryption_metadata_size,
                                              unsigned char** decrypted_data,
                                              uint32_t* decrypted_data_size,
                                              const attest::RsaScheme tpm2RsaAlgId = attest::RsaScheme::RsaEs,
                                              const attest::RsaHashAlg tpm2HashAlgId = attest::RsaHashAlg::RsaSha1) noexcept = 0;

    /**
     * @brief This API deallocates the memory previously allocated by the library
     * @param[in] ptr: Pointer to memory block previously allocated
     */
    virtual void Free(void* ptr) noexcept = 0;
};

extern "C" {
    /**
     * @brief This function intializes the attestation client library
     * @param[in] attestation_logger: The handle that will be used for logging.
     * @param[out] client: AttestationClient object that will be populated and
     * @param[in] telemetry_reporting: Optional handle that will be used to report telemetry events.
     * returned when Initialize() succeeds.
     * Initialize returns a singleton pointer and the method should not be called
     * again unless Uninitialize() is called.
     * @return In case the initialization is successful, return True.
     * Otherwise, return False.
     */
    DllExports
    bool Initialize(attest::AttestationLogger* attestation_logger,
                    AttestationClient** client);

    /**
     * @brief This API uninitializes or deallocates the AttestationClient object
     */
    DllExports
    void Uninitialize();

    /**
    * @brief Single shot C function for Rust FFI
    * @param[in] app_data: JSON user data quoted by the TPM and reported by MAA in runtime claim
    * @param[in] pcr: bitfield representing the PCRs used in the TPM quote and reported by MAA
    * @param[out] jwt: 32k buffer where the MAA token will be written
    * @param[out] jwt_len: size of the written MAA token
    * @return 0 on success, error code on failure (see AttestationLibTypes.h for mapping)
    */
    DllExports
    int32_t get_attestation_token(const uint8_t* app_data, uint32_t pcr, uint8_t* jwt, size_t* jwt_len, const char* endpoint_url);

    /**
    * @brief Start an attestation session
    * @param[in] st will be set to the 
    * @return 0 on success, error code on failure (see AttestationLibTypes.h for mapping)
    */
    DllExports
    int32_t ga_create(void **st);

    /**
    * @brief Free the state of an attestation session
    * @param[in] st: attestation session
    */
    DllExports
    void ga_free(void *st);

    /**
    * @brief Get an attestation token from a session
    * @param[in] app_data: JSON user data quoted by the TPM and reported by MAA in runtime claim
    * @param[in] pcr: bitfield representing the PCRs used in the TPM quote and reported by MAA
    * @param[out] jwt: 32k buffer where the MAA token will be written
    * @param[out] jwt_len: size of the written MAA token
    * @return NULL on error, attestation object on success
    */
    DllExports
    int32_t ga_get_token(void *st, const uint8_t* app_data, uint32_t pcr, uint8_t* jwt, size_t* jwt_len, const char* endpoint_url);

    /**
    * @brief decrypt a value encrypted with the ephemeral attested key
    * This MUST use RSA[2048]-OEAP-SHA256, and decryption is done in-place.
    * @param[inout] cipher: encrypted value, plaintext will be written in place
    * @param[inout] len: encrypted value length, plaintext length will be written
    * @return 0 on success, error code on failure (see AttestationLibTypes.h for mapping)
    */
    DllExports
    int32_t ga_decrypt(void *st, uint8_t *cipher, size_t* len);

}