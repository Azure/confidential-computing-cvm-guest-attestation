#include "..\pch.h"
#ifndef PLATFORM_UNIX
#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <bcrypt.h>
#ifndef _NTSTATUS_
#include <ntstatus.h>
#endif
#include "..\BcryptError.h"
#else
#endif
#include <memory>
#include <vector>
#include "..\AesWrapper.h"
#include "BcryptAesWrapper.h"
#include "..\ReturnCodes.h"

__inline long long __round_up(long long numToRound, long long multiple) {
    return ((numToRound + multiple - 1) / multiple) * multiple;
}

GcmChainingInfo::GcmChainingInfo(BCRYPT_ALG_HANDLE algHandle)
{
    DWORD bytesDone = 0;
    this->authInfo = { 0 };
    BCRYPT_INIT_AUTH_MODE_INFO(this->authInfo);
    NTSTATUS bcryptResult = STATUS_SUCCESS;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
    DWORD blockLength = 0;
    // Get properties and throw excpetion if it fails.
    // No clean up needed since no resources are allocated until after this point.
    bcryptResult = BCryptGetProperty(
        algHandle,
        BCRYPT_AUTH_TAG_LENGTH,
        (BYTE*)&(authTagLengths),
        sizeof(authTagLengths),
        &bytesDone, 0
    );
    if (!BCRYPT_SUCCESS(bcryptResult)) {
		// LibraryErrors class, Bcrypt subclass, property not found
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_AUTH_TAG_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }
    bcryptResult = BCryptGetProperty(
        algHandle,
        BCRYPT_BLOCK_LENGTH,
        (BYTE*)&(blockLength),
        sizeof(blockLength),
        &bytesDone, 0);
    if (!BCRYPT_SUCCESS(bcryptResult)) {
        // LibraryErrors class, Bcrypt subclass, property not found
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_BLOCK_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }
    this->authTag = std::vector<unsigned char>(authTagLengths.dwMaxLength);
    this->macContext = std::vector<unsigned char>(authTagLengths.dwMaxLength);
    // init vector is the same length as the block length.
    // In GCM the IV is the nonce, but still needs to be provided to BCryptEncrypt/Decrypt
    this->initVector = std::vector<unsigned char>(blockLength);

    this->authInfo.pbTag = this->authTag.data();
    this->authInfo.cbTag = this->authTag.size();
    this->authInfo.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    this->authInfo.pbMacContext = this->macContext.data();
    this->authInfo.cbMacContext = this->macContext.size();
    this->authInfo.cbAAD = 0;
    this->authInfo.cbData = 0;
    this->authInfo.cbAuthData = 0;
    this->authInfo.pbAuthData = nullptr;
}

GcmChainingInfo::~GcmChainingInfo()
{
}

void GcmChainingInfo::SetNonce(const std::vector<unsigned char> &nonce) noexcept
{
    this->nonce = std::vector<unsigned char>(nonce.data(), nonce.data() + nonce.size());
    this->authInfo.pbNonce = this->nonce.data();
    this->authInfo.cbNonce = this->nonce.size();
}

std::vector<unsigned char> GcmChainingInfo::GetNonce() noexcept
{
    return this->nonce;
}

void GcmChainingInfo::SetInitVector(const std::vector<unsigned char> &initVector) noexcept
{
    this->initVector = std::vector<unsigned char>(initVector.data(), initVector.data() + initVector.size());
}

BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* GcmChainingInfo::GetAuthInfo() noexcept
{
    return &(this->authInfo);
}

std::vector<unsigned char> GcmChainingInfo::GetInitVector() noexcept
{
    return this->initVector;
}

GcmWrapper::GcmWrapper()
{
#ifndef PLATFORM_UNIX
    this->hAesHandle = nullptr;
    DWORD bytesDone = 0;
    NTSTATUS bcryptResult = BCryptOpenAlgorithmProvider(
        &(this->hAesHandle), BCRYPT_AES_ALGORITHM, 0, 0);
    if (STATUS_SUCCESS != bcryptResult) {
		// LibraryErrors class, Bcrypt subclass, provider/handler error
        throw BcryptError(bcryptResult, "BCryptOpenAlgorithmProvider failed",
            ErrorCode::LibraryError_Bcrypt_providerError);
    }
    this->hAesKey = nullptr;
    this->authTagLengths = { 0 };
    this->authInfo = { 0 };

    bcryptResult = BCryptSetProperty(
        this->hAesHandle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (!BCRYPT_SUCCESS(bcryptResult)) {
		// LibraryErrors class, Bcrypt subclass, propertyError
        throw BcryptError(bcryptResult, "BCryptSetProperty(BCRYPT_CHAINING_MODE) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }
    bcryptResult = BCryptGetProperty(this->hAesHandle, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&(this->authTagLengths), sizeof(authTagLengths), &bytesDone, 0);
    if (!BCRYPT_SUCCESS(bcryptResult)) {
        // LibraryErrors class, Bcrypt subclass, propertyError
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_AUTH_TAG_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }

    bcryptResult = BCryptGetProperty(this->hAesHandle, BCRYPT_BLOCK_LENGTH, (BYTE*)&(this->blockLength), sizeof(blockLength), &bytesDone, 0);
    if (!BCRYPT_SUCCESS(bcryptResult)) {
        // LibraryErrors class, Bcrypt subclass, propertyError
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_BLOCK_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }

    bcryptResult = BCryptGetProperty(
        this->hAesHandle,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR) & (this->objectLength),
        sizeof(this->objectLength),
        &bytesDone,
        0
    );
    if (!BCRYPT_SUCCESS(bcryptResult)) {
        // LibraryErrors class, Bcrypt subclass, propertyError
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }
    this->objectValue = std::vector<unsigned char>(this->objectLength);
#else
#endif // !PLATFORM_UNIX
}

GcmWrapper::~GcmWrapper()
{
#ifndef PLATFORM_UNIX
    NTSTATUS bcryptResult = STATUS_SUCCESS;
    if (this->hAesHandle != nullptr) {
        bcryptResult = BCryptCloseAlgorithmProvider(this->hAesHandle, 0);
        if (STATUS_SUCCESS != bcryptResult) {
			// LibraryErrors class, Bcrypt subclass, handleError
            throw BcryptError(bcryptResult, "BCryptCloseAlgorithmProvider failed",
                ErrorCode::LibraryError_Bcrypt_handleError);
        }
    }
    if (this->hAesKey != nullptr) {
        bcryptResult = BCryptDestroyKey(this->hAesKey);
        if (STATUS_SUCCESS != bcryptResult) {
			// LibraryErrors class, Bcrypt subclass, handleError
            throw BcryptError(bcryptResult, "BCryptDestroyKey failed",
                ErrorCode::LibraryError_Bcrypt_handleError);
        }
    }

#else
#endif // !PLATFORM_UNIX
}

void GcmWrapper::SetKey(std::vector<unsigned char> &key)
{
#ifndef PLATFORM_UNIX
    NTSTATUS bcryptResult = STATUS_SUCCESS;
    bcryptResult = BCryptGenerateSymmetricKey(
        this->hAesHandle,
        &this->hAesKey,
        this->objectValue.data(),
        this->objectLength,
        key.data(),
        key.size(),
        0
    );
    if (STATUS_SUCCESS != bcryptResult) {
		// LibraryErrors class, Bcrypt subclass, keyError
        throw BcryptError(bcryptResult, "BCryptGetProperty(BCRYPT_AUTH_TAG_LENGTH) failed",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }
#else
#endif // !PLATFORM_UNIX
}


std::unique_ptr<AesChainingInfo> GcmWrapper::SetChainingInfo(const std::vector<unsigned char> &nonce)
{
    std::unique_ptr<AesChainingInfo> chainingInfo;
    try {
        chainingInfo = std::make_unique<GcmChainingInfo>(this->hAesHandle);
        chainingInfo->SetNonce(nonce);
    }
    catch (BcryptError e) {
        // From a BcryptError inside the GcmChainingInfo constructor
        throw e;
    }
    catch (std::exception& e) {
        throw e;
    }
    return chainingInfo;
}

std::vector<unsigned char> GcmWrapper::Encrypt(const std::vector<unsigned char> &data, AesChainingInfo *chainingInfo) const
{
    DWORD bytesDone = 0;
    long long ciphertextSize = 0;
    long long ptxOffset = 0;
    if (chainingInfo == nullptr) {
        throw std::exception("Chaining info must be set before calling Encrypt");
    }
    long long dataLength = data.size();
    long long encryptedDataLength = __round_up(dataLength, this->blockLength);
    long numBlocks = encryptedDataLength / this->blockLength;
    GcmChainingInfo* gcmChainingInfo = dynamic_cast<GcmChainingInfo*>(chainingInfo);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* authInfo = gcmChainingInfo->GetAuthInfo();
    encryptedDataLength += authInfo->cbTag;
    std::vector<unsigned char> result(encryptedDataLength);
    std::vector<unsigned char> initVector = gcmChainingInfo->GetInitVector();

#ifndef PLATFORM_UNIX
    NTSTATUS bcryptResult = STATUS_SUCCESS;
    // init aad
    bcryptResult = BCryptEncrypt(
        this->hAesKey,
        nullptr,
        0,
        authInfo,
        initVector.data(),
        initVector.size(),
        nullptr,
        0,
        &bytesDone,
        0
    );
    if (STATUS_SUCCESS != bcryptResult) {
		// CryptographyError class, AES subclass, encryptError
        throw BcryptError(bcryptResult, "BCryptEncrypt failed",
            ErrorCode::CryptographyError_AES_encryptError);
    }

    authInfo->cbAuthData = 0;
    authInfo->pbAuthData = nullptr;
    
    for (long i = 0; i < numBlocks - 1; i++) {
        bytesDone = 0;
        bcryptResult = BCryptEncrypt(
            this->hAesKey,
            (unsigned char *)data.data() + ptxOffset,
            this->blockLength,
            authInfo,
            initVector.data(),
            initVector.size(),
            result.data() + ciphertextSize,
            this->blockLength,
            &bytesDone,
            0
        );
        if (STATUS_SUCCESS != bcryptResult) {
            // CryptographyError class, AES subclass, encryptError
            throw BcryptError(bcryptResult, "BCryptEncrypt failed",
                ErrorCode::CryptographyError_AES_encryptError);
        }
        ciphertextSize += this->blockLength;
        ptxOffset += bytesDone;
    }
    bytesDone = 0;
    authInfo->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

    bcryptResult = BCryptEncrypt(
        this->hAesKey,
        (unsigned char*)data.data() + ptxOffset,
        data.size() - ptxOffset,
        authInfo,
        initVector.data(),
        initVector.size(),
        result.data() + ciphertextSize,
        this->blockLength,
        &bytesDone,
        0
    );
    if (STATUS_SUCCESS != bcryptResult) {
        // CryptographyError class, AES subclass, encryptError
        throw BcryptError(bcryptResult, "BCryptEncrypt failed",
            ErrorCode::CryptographyError_AES_encryptError);
    }
    ciphertextSize += bytesDone;

    result.resize(ciphertextSize + authInfo->cbTag);

    std::copy(
        authInfo->pbTag,
        authInfo->pbTag + authInfo->cbTag,
        result.data() + ciphertextSize
    );
    
#else
#endif // !PLATFORM_UNIX
    return result;
}

std::vector<unsigned char> GcmWrapper::Decrypt(const std::vector<unsigned char> &ciphertext, AesChainingInfo *chainingInfo) const
{
    DWORD bytesDone = 0;    
    long long returnDataLength = 0;
    long long ctxOffset = 0;
    if (chainingInfo == nullptr) {
        throw std::exception("Chaining info must be set before calling Encrypt");
    }
    long long encryptedDataLength = ciphertext.size() - this->authTagLengths.dwMaxLength;
    std::vector<unsigned char> result(encryptedDataLength);
    long numBlocks = __round_up(encryptedDataLength, this->blockLength) / this->blockLength;
    GcmChainingInfo* gcmChainingInfo = dynamic_cast<GcmChainingInfo*>(chainingInfo);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* authInfo = gcmChainingInfo->GetAuthInfo();
    std::vector<unsigned char> initVector = gcmChainingInfo->GetInitVector();

#ifndef PLATFORM_UNIX
    NTSTATUS bcryptResult = STATUS_SUCCESS;
    // Peel off the auth tag
    std::vector<unsigned char> authTag(this->authTagLengths.dwMaxLength);
    std::copy(
        ciphertext.data() + encryptedDataLength,
        ciphertext.data() + encryptedDataLength + this->authTagLengths.dwMaxLength,
        authTag.data()
    );
    // init aad
    bcryptResult = BCryptDecrypt(
        this->hAesKey,
        nullptr,
        0,
        authInfo,
        initVector.data(),
        initVector.size(),
        nullptr,
        0,
        &bytesDone,
        0
    );
    if (STATUS_SUCCESS != bcryptResult) {
		// CryptographyError class, AES subclass, decryptError
        throw BcryptError(bcryptResult, "BCryptDecrypt failed",
            ErrorCode::CryptographyError_AES_decryptError);
    }

    authInfo->cbAuthData = 0;
    authInfo->pbAuthData = nullptr;

    for (long i = 0; i < numBlocks - 1; i++) {
        bytesDone = 0;
        ctxOffset = i * this->blockLength;
        bcryptResult = BCryptDecrypt(
            this->hAesKey,
            (unsigned char*)ciphertext.data() + ctxOffset,
            this->blockLength,
            authInfo,
            initVector.data(),
            initVector.size(),
            result.data() + returnDataLength,
            this->blockLength,
            &bytesDone,
            0
        );
        if (STATUS_SUCCESS != bcryptResult) {
			// CryptographyError class, AES subclass, decryptError
            throw BcryptError(bcryptResult, "BCryptDecrypt failed",
                ErrorCode::CryptographyError_AES_decryptError);
        }
        returnDataLength += bytesDone;
        ctxOffset += this->blockLength;
    }

    authInfo->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

    bytesDone = 0;
    authInfo->pbTag = authTag.data();
    authInfo->cbTag = authTag.size();

    bcryptResult = BCryptDecrypt(
        this->hAesKey,
        (unsigned char*)ciphertext.data() + ctxOffset,
        encryptedDataLength - ctxOffset,
        authInfo,
        initVector.data(),
        initVector.size(),
        result.data() + returnDataLength,
        this->blockLength,
        &bytesDone,
        0
    );

    if (STATUS_SUCCESS != bcryptResult) {
		// CryptographyError class, AES subclass, decryptError
        throw BcryptError(bcryptResult, "BCryptDecrypt failed",
            ErrorCode::CryptographyError_AES_decryptError);
    }
    returnDataLength += bytesDone;

    return result;
#else
#endif // !PLATFORM_UNIX
}