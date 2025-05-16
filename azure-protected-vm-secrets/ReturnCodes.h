#pragma once

enum class ErrorCode {
	Success = 0,
    GeneralError = 0,
    GeneralError_Memory_AllocError = GeneralError - 1,

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

    UnknownError = -1 * 0x5000
};