//-------------------------------------------------------------------------------------------------
// <copyright file="TpmUnseal.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <json/json.h>
#include <Exceptions.h>
#include <AttestationTypes.h>

#include "AttestationHelper.h"
#include "AttestationLibTypes.h"

namespace attest {

/**
 * @brief This enum represents the block mode to be used for encryption/decryption of data.
 */
enum class BlockCipherMode {
    CHAINING_MODE_GCM,
    Invalid
};

/**
 * @brief This enum represents the algorithm to be used for encryption/decryption of data.
 */
enum class CipherAlgorithm {
    AES,
    Invalid
};

/**
 * @brief This enum represents the padding scheme to be used for encryption/decryption of data.
 */
enum class BlockCipherPadding {
    PKCS7,
    Invalid
};

/**
 * @brief Encryption parameters of the encrypted data that will be used for decryption.
 */
struct EncryptionParameters {
    BlockCipherMode block_mode = BlockCipherMode::Invalid; /**<* Block mode used for symmetric encryption/decryption of the jwt */
    BlockCipherPadding block_padding = BlockCipherPadding::Invalid; /**<* The padding scheme used for symmetric encryption/decryption of the jwt */
    CipherAlgorithm cipher_alg = CipherAlgorithm::Invalid; /**< Symmetric encryption/decryption algorithm used for the jwt. */
    size_t key_size = 0; /**< Key size in bit of the symmetric key using to encrypt the jwt */
    attest::Buffer iv; /**< Initialization vector used for encyption of the jwt */
    attest::Buffer authentication_data; /**< Auth data used for encryption of the jwt */
};

/**
 * @brief The function will be used to extract the Encryption parameters from the json response from AAS.
 * @param[in] json_obj The Json::Value object that represents the encryption parameter element in the json response.
 * @param[out] encryption_params The EncryptionParameter object that will hold the encryption parameters to be used for
 * decryption of the jwt.
 * @param[out] err In case of failure scenarios, err will be used to return the error description.
 * @return On success, true will be returned and false will be returned on failure.
 */
bool GetEncryptionParameters(const Json::Value& json_obj,
                             EncryptionParameters& encryption_params,
                             std::string& err);

/**
 * @brief The function will be used to extract the encrypted jwt from the json response from AAS.
 * @param[in] json_obj The Json::Value object that represents the jwt element in the json response.
 * @param[out] jwt_encrypted The Buffer object that will hold the encrypted jwt extracted from the response.
 * @param[out] err In case of failure scenarios, err will be used to return the error description.
 * @return On success, true will be returned and false will be returned on failure.
 */
bool GetEncryptedJwt(const Json::Value& json_obj,
                     attest::Buffer& jwt_encrypted,
                     std::string& err);

/**
 * @brief The function will be used to decrypt the inner symmetric key that was used to encrypt the jwt.
 * @param[in] encrypted_inner_key The encrypted symmetric inner key that was used to encrypt the jwt.
 * @param[out] decrypted_key The Buffer object that will hold the decrypted symmetric key.
 * @return On success, AttestatitionResult object is returned with error_code set to ErrorCode::SUCCESS. On failure,
 * AttestationResult object is returned with appropriate error code set.
 */
attest::AttestationResult DecryptInnerKey(const attest::Buffer& encrypted_inner_key,
                                          attest::Buffer& decrypted_key);

/**
 * @brief The function will be used to decrypt the jwt using the inner symmetric key.
 * @param[in] encryption_params The EncryptionParams object that holds the encryption parameters to be used for decryption.
 * @param[in] key The symmertic key to be used for decrypting the jwt.
 * @param[in] jwt_encrypted The Buffer that holds the encrypted jwt.
 * @param[out] jwt_decrypted The Buffer that will hold the decrypted jwt.
 * @param[out] err In case of failure scenarios, err will be used to return the error description.
 * @return On success, true will be returned and false will be returned on failure.
 */
bool DecryptJwt(const EncryptionParameters& encryption_params,
                const attest::Buffer& key,
                const attest::Buffer& jwt_encrypted,
                std::string& jwt_decrypted,
                std::string& err);

/**
 * @brief The function will be used to extract the symmetric inner key in the AAS response.
 * @param[in] json_obj The Json::Value object that represent the symmetric inner key element in the json response.
 * @param[out] encrypted_inner_key The Buffer that will hold the encrypted symmetric inner key.
 * @param[out] err In case of failure scenarios, err will be used to return the error description.
 * @return On success, true will be returned and false will be returned on failure.
 */
bool GetEncryptedInnerKey(const Json::Value& json_obj,
                          attest::Buffer& encrypted_inner_key,
                          std::string& err);
}// attest
