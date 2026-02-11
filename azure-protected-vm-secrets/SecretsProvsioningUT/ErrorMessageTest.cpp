// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include "../SecretsProvisioningLibrary.h"
#include "../ReturnCodes.h"  // For test-only direct access to error codes

TEST(ErrorMessageTest, ErrorCodeMapping) {
    // Test success case
    EXPECT_STREQ(get_error_message(0), "Success");
    
    // Test various error categories
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::ParsingError)), 
                "ParsingError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::GeneralError_Memory_AllocError)), 
                "GeneralError_Memory_AllocError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::TpmError_Context_tctiInitError)), 
                "TpmError_Context_tctiInitError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::CryptographyError_AES_encryptError)), 
                "CryptographyError_AES_encryptError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::LibraryError_Bcrypt_propertyError)), 
                "LibraryError_Bcrypt_propertyError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::PolicyMismatchError)), 
                "PolicyMismatchError");
    EXPECT_STREQ(get_error_message(static_cast<long>(ErrorCode::UnknownError)), 
                "UnknownError");
    
    // Test an invalid error code
    EXPECT_STRNE(get_error_message(-99999), "");  // Should return something, not empty
}

TEST(ErrorMessageTest, AllErrorCodesHaveMessages) {
    // Spot check a few error codes from each category
    std::vector<ErrorCode> codesToCheck = {
        ErrorCode::Success,
        ErrorCode::ParsingError,
        // Add a few more from your actual enum
        ErrorCode::GeneralError_Memory_AllocError,
        ErrorCode::TpmError_Auth_setAuthError,
        ErrorCode::TpmError_Handles_handlePresentError,
        ErrorCode::TpmError_Handles_evictControlError,
        ErrorCode::TpmError_Objects_createError,
        ErrorCode::TpmError_Context_tctiInitError,
        ErrorCode::TpmError_Context_esysFinalError,
        ErrorCode::TpmError_Context_esysInitError,
        ErrorCode::TpmError_Handles_esysNvReadError,
        ErrorCode::CryptographyError_AES_encryptError,
        ErrorCode::CryptographyError_AES_decryptError,
        ErrorCode::CryptographyError_ECC_keyError,
        ErrorCode::CryptographyError_ECC_keyGenError,
        ErrorCode::CryptographyError_HKDF_extractError,
        ErrorCode::CryptographyError_HKDF_expandError,
        ErrorCode::CryptographyError_X509_certChainError,
        ErrorCode::CryptographyError_X509_sigErrorError,
        ErrorCode::CryptographyError_TpmRsa_encryptError,
        ErrorCode::CryptographyError_TpmRsa_decryptError,
        ErrorCode::CryptographyError_Hash_hashError,
        ErrorCode::CryptographyError_Signing_verifyError,
        ErrorCode::CryptographyError_Signing_certChainError,
        ErrorCode::ParsingError_Jwt_invStructureError,
        ErrorCode::ParsingError_Jwt_jsonParseError,
        ErrorCode::ParsingError_Jwt_timeError,
        ErrorCode::ParsingError_Jwt_missingFieldError,
        ErrorCode::ParsingError_Jwt_invalidFieldError,
        ErrorCode::ParsingError_X509_certParseError,
        ErrorCode::ParsingError_X509_certChainError,
        ErrorCode::ParsingError_X509_certLoadError,
        ErrorCode::ParsingError_X509_certStoreError,
        ErrorCode::ParsingError_Asn1_x509PrivKeyError,
        ErrorCode::ParsingError_Asn1_x509PubKeyError,
        ErrorCode::ParsingError_Unicode_utf8Error,
        ErrorCode::LibraryError_Bcrypt_propertyError,
        ErrorCode::LibraryError_Bcrypt_providerError,
        ErrorCode::LibraryError_Bcrypt_handleError,
        ErrorCode::LibraryError_Bcrypt_keyError,
        ErrorCode::LibraryError_WinCrypt_certStoreError,
        ErrorCode::LibraryError_WinCrypt_certLoadError,
        ErrorCode::LibraryError_WinCrypt_certChainError,
        ErrorCode::LibraryError_JsonHpp_jsonParseError,
        ErrorCode::PolicyMismatchError,
        ErrorCode::UnknownError
    };
    
    for (const auto& code : codesToCheck) {
        const char* message = get_error_message(static_cast<long>(code));
        EXPECT_NE(message, nullptr) << "Null message for error code " << static_cast<long>(code);
        EXPECT_STRNE(message, "") << "Empty message for error code " << static_cast<long>(code);
    }
}