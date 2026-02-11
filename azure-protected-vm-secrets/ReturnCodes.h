// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

enum class ErrorCode {
	Success = 0,

    TpmError = -1 * 0x1000,
    TpmError_Auth_setAuthError = TpmError - 1,
    TpmError_Handles_handlePresentError = TpmError - 2,
    TpmError_Handles_evictControlError = TpmError - 3,
    TpmError_Objects_createError = TpmError - 4,
    TpmError_Context_tctiInitError = TpmError - 5,
    TpmError_Context_esysFinalError = TpmError - 6,
    TpmError_Context_esysInitError = TpmError - 7,
    TpmError_Handles_esysNvReadError = TpmError - 8,

    CryptographyError = -1 * 0x2000,
    CryptographyError_AES_encryptError = CryptographyError - 1,
    CryptographyError_AES_decryptError = CryptographyError - 2,
    CryptographyError_ECC_keyError = CryptographyError - 3,
    CryptographyError_ECC_keyGenError = CryptographyError - 4,
    CryptographyError_HKDF_extractError = CryptographyError - 5,
    CryptographyError_HKDF_expandError = CryptographyError - 6,
    CryptographyError_X509_certChainError = CryptographyError - 7,
    CryptographyError_X509_sigErrorError = CryptographyError - 8,
    CryptographyError_TpmRsa_encryptError = CryptographyError - 9,
    CryptographyError_TpmRsa_decryptError = CryptographyError - 10,
    CryptographyError_Hash_hashError = CryptographyError - 11,
    CryptographyError_Signing_verifyError = CryptographyError - 12,
    CryptographyError_Signing_certChainError = CryptographyError - 13,

    ParsingError = -1 * 0x3000,
    ParsingError_Jwt_invStructureError = ParsingError - 1,
    ParsingError_Jwt_jsonParseError = ParsingError - 2,
    ParsingError_Jwt_timeError = ParsingError - 3,
    ParsingError_Jwt_missingFieldError = ParsingError - 4,
    ParsingError_Jwt_invalidFieldError = ParsingError - 5,
    ParsingError_X509_certParseError = ParsingError - 6,
    ParsingError_X509_certChainError = ParsingError - 7,
    ParsingError_X509_certLoadError = ParsingError - 8,
    ParsingError_X509_certStoreError = ParsingError - 9,
    ParsingError_Asn1_x509PrivKeyError = ParsingError - 10,
    ParsingError_Asn1_x509PubKeyError = ParsingError - 11,
    ParsingError_Unicode_utf8Error = ParsingError - 12,
    ParsingError_Base64_b64Error = ParsingError - 13,

    LibraryErrors = -1 * 0x4000,
    LibraryError_Bcrypt_propertyError = LibraryErrors - 1,
    LibraryError_Bcrypt_providerError = LibraryErrors - 2,
    LibraryError_Bcrypt_handleError = LibraryErrors - 3,
    LibraryError_Bcrypt_keyError = LibraryErrors - 4,
    LibraryError_WinCrypt_certStoreError = LibraryErrors - 5,
    LibraryError_WinCrypt_certLoadError = LibraryErrors - 6,
    LibraryError_WinCrypt_certChainError = LibraryErrors - 7,
	LibraryError_JsonHpp_jsonParseError = LibraryErrors - 8,

    PolicyMismatchError = -1 * 0x5000,

    GeneralError = -1 * 0x6000,
    GeneralError_Memory_AllocError = GeneralError - 1,

    UnknownError = -1 * 0x7000
};

inline const char* error_code_name(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::Success:                                return "Success";

        case ErrorCode::TpmError:                               return "TpmError";
        case ErrorCode::TpmError_Auth_setAuthError:             return "TpmError_Auth_setAuthError";
        case ErrorCode::TpmError_Handles_handlePresentError:    return "TpmError_Handles_handlePresentError";
        case ErrorCode::TpmError_Handles_evictControlError:     return "TpmError_Handles_evictControlError";
        case ErrorCode::TpmError_Objects_createError:           return "TpmError_Objects_createError";
        case ErrorCode::TpmError_Context_tctiInitError:         return "TpmError_Context_tctiInitError";
        case ErrorCode::TpmError_Context_esysFinalError:        return "TpmError_Context_esysFinalError";
        case ErrorCode::TpmError_Context_esysInitError:         return "TpmError_Context_esysInitError";
        case ErrorCode::TpmError_Handles_esysNvReadError:       return "TpmError_Handles_esysNvReadError";

        case ErrorCode::CryptographyError:                      return "CryptographyError";
        case ErrorCode::CryptographyError_AES_encryptError:     return "CryptographyError_AES_encryptError";
        case ErrorCode::CryptographyError_AES_decryptError:     return "CryptographyError_AES_decryptError";
        case ErrorCode::CryptographyError_ECC_keyError:         return "CryptographyError_ECC_keyError";
        case ErrorCode::CryptographyError_ECC_keyGenError:      return "CryptographyError_ECC_keyGenError";
        case ErrorCode::CryptographyError_HKDF_extractError:    return "CryptographyError_HKDF_extractError";
        case ErrorCode::CryptographyError_HKDF_expandError:     return "CryptographyError_HKDF_expandError";
        case ErrorCode::CryptographyError_X509_certChainError:  return "CryptographyError_X509_certChainError";
        case ErrorCode::CryptographyError_X509_sigErrorError:   return "CryptographyError_X509_sigErrorError";
        case ErrorCode::CryptographyError_TpmRsa_encryptError:  return "CryptographyError_TpmRsa_encryptError";
        case ErrorCode::CryptographyError_TpmRsa_decryptError:  return "CryptographyError_TpmRsa_decryptError";
        case ErrorCode::CryptographyError_Hash_hashError:       return "CryptographyError_Hash_hashError";
        case ErrorCode::CryptographyError_Signing_verifyError:  return "CryptographyError_Signing_verifyError";
        case ErrorCode::CryptographyError_Signing_certChainError: return "CryptographyError_Signing_certChainError";

        case ErrorCode::ParsingError:                           return "ParsingError";
        case ErrorCode::ParsingError_Jwt_invStructureError:     return "ParsingError_Jwt_invStructureError";
        case ErrorCode::ParsingError_Jwt_jsonParseError:        return "ParsingError_Jwt_jsonParseError";
        case ErrorCode::ParsingError_Jwt_timeError:             return "ParsingError_Jwt_timeError";
        case ErrorCode::ParsingError_Jwt_missingFieldError:     return "ParsingError_Jwt_missingFieldError";
        case ErrorCode::ParsingError_Jwt_invalidFieldError:     return "ParsingError_Jwt_invalidFieldError";
        case ErrorCode::ParsingError_X509_certParseError:       return "ParsingError_X509_certParseError";
        case ErrorCode::ParsingError_X509_certChainError:       return "ParsingError_X509_certChainError";
        case ErrorCode::ParsingError_X509_certLoadError:        return "ParsingError_X509_certLoadError";
        case ErrorCode::ParsingError_X509_certStoreError:       return "ParsingError_X509_certStoreError";
        case ErrorCode::ParsingError_Asn1_x509PrivKeyError:     return "ParsingError_Asn1_x509PrivKeyError";
        case ErrorCode::ParsingError_Asn1_x509PubKeyError:      return "ParsingError_Asn1_x509PubKeyError";
        case ErrorCode::ParsingError_Unicode_utf8Error:         return "ParsingError_Unicode_utf8Error";
        case ErrorCode::ParsingError_Base64_b64Error:           return "ParsingError_Base64_b64Error";

        case ErrorCode::LibraryErrors:                          return "LibraryErrors";
        case ErrorCode::LibraryError_Bcrypt_propertyError:      return "LibraryError_Bcrypt_propertyError";
        case ErrorCode::LibraryError_Bcrypt_providerError:      return "LibraryError_Bcrypt_providerError";
        case ErrorCode::LibraryError_Bcrypt_handleError:        return "LibraryError_Bcrypt_handleError";
        case ErrorCode::LibraryError_Bcrypt_keyError:           return "LibraryError_Bcrypt_keyError";
        case ErrorCode::LibraryError_WinCrypt_certStoreError:   return "LibraryError_WinCrypt_certStoreError";
        case ErrorCode::LibraryError_WinCrypt_certLoadError:    return "LibraryError_WinCrypt_certLoadError";
        case ErrorCode::LibraryError_WinCrypt_certChainError:   return "LibraryError_WinCrypt_certChainError";
        case ErrorCode::LibraryError_JsonHpp_jsonParseError:    return "LibraryError_JsonHpp_jsonParseError";

        case ErrorCode::PolicyMismatchError:                    return "PolicyMismatchError";

        case ErrorCode::GeneralError:                           return "GeneralError";
        case ErrorCode::GeneralError_Memory_AllocError:         return "GeneralError_Memory_AllocError";

        case ErrorCode::UnknownError:                           return "UnknownError";
    }
    return "UnknownError";
}