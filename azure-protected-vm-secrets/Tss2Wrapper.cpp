#include "pch.h"
#include <fstream>
#include <string>
#include <vector>
#include <iostream>
#include "DebugInfo.h"

#include <tss2/tss2_esys.h>
#include "TpmError.h"
#include "TssCtx.h"
#include "Tss2Wrapper.h"
#include "LibraryLogger.h"
#include "ReturnCodes.h"

#ifndef PLATFORM_UNIX
#include <windows.h>
#include <../shared/tbs.h>
#pragma comment(lib, "Tbs.lib")
#endif // PLATFORM_UNIX

#define SRKHANDLE 0x81000001
#define KEYHANDLE SRKHANDLE + 3
#define RSA_PUBLIC_EXPONENT 0x00010001



Tss2Wrapper::Tss2Wrapper()
{
    this->ctx = std::make_unique<TssCtx>();
}

TPM2_RC Tss2Wrapper::RemoveKey() {
    ESYS_TR object_handle = {};
    TPM2_RC ret = TSS2_RC_SUCCESS;

    // Get Esys object for handle.
    ret = Esys_TR_FromTPMPublic(
        this->ctx->Get(), KEYHANDLE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &object_handle);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Handles, handlePresentError
        throw TpmError(ret, "Failed to get object from handle",
            ErrorCode::TpmError_Handles_handlePresentError);
    }

    // Evict the key
    ret = Esys_EvictControl(this->ctx->Get(),
        ESYS_TR_RH_OWNER,
        object_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        KEYHANDLE,
        &object_handle);
    if (ret != TSS2_RC_SUCCESS) {
		// TpmError, Subclass Handles, evictControlError
        throw TpmError(ret, "Failed to Evict object at handle",
            ErrorCode::TpmError_Handles_evictControlError);
    }
    return ret;
}

TPM2B_PUBLIC* Tss2Wrapper::GenerateGuestKey()
{
    TPM2B_PUBLIC inPub = { 0 };

    TPM2B_SENSITIVE_CREATE inPriv = { 0 };
    TPM2B_DATA inOutsideInfo = { 0 };
    TPML_PCR_SELECTION inPcr = { 0 };
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR persistObjHandle = ESYS_TR_NONE;

    TPM2B_AUTH authValuePrimary = {
        0, // size
        {} // buffer
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        0, // size
        {  // sensitive
            { // userAuth
                 0,   //size
                 {0}, // buffer
             },
            { // data
                 0,   // size 
                 {0}, // buffer
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    inPub.publicArea.type = TPM2_ALG_RSA;
    inPub.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPub.publicArea.objectAttributes = (
        TPMA_OBJECT_DECRYPT |
        TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN);

    inPub.publicArea.unique.rsa.size = 256;
    // Set the alg to TPM2_ALG_NULL so the caller can specify the alg such as TPM2_ALG_OAEP or TPM2_ALG_RSAES
    inPub.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPub.publicArea.parameters.rsaDetail.exponent = RSA_PUBLIC_EXPONENT;
    inPub.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    inPub.publicArea.authPolicy = { 0 };
    inPub.publicArea.authPolicy.size = 0;

    TPM2B_PUBLIC* outPub;

    // Create primary
    TSS2_RC ret = Esys_CreatePrimary(
        this->ctx->Get(),
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inPriv,
        &inPub,
        &inOutsideInfo,
        &inPcr,
        &primaryHandle,
        &outPub,
        nullptr,
        nullptr,
        nullptr);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Objects, createError
        throw TpmError(ret, "Failed to create primary object under storage hierarchy",
            ErrorCode::TpmError_Objects_createError);
    }
    LIBSECRETS_LOG(SecretsLogger::LogLevel::Debug, "Create Pimary",
        "Public key info %s",
        formatHexBuffer(outPub->publicArea.unique.rsa.buffer, outPub->publicArea.unique.rsa.size).c_str());

    ret = Esys_EvictControl(
        this->ctx->Get(),
        ESYS_TR_RH_OWNER,
        primaryHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        KEYHANDLE,
        &persistObjHandle);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Handles, evictControlError
        throw TpmError(ret, "Failed to EvictControl key",
            ErrorCode::TpmError_Handles_evictControlError);
    }

    return outPub;
}

bool Tss2Wrapper::IsKeyPresent() {
    ESYS_TR object_handle = {};
    TPM2_RC ret = TSS2_RC_SUCCESS;

    // Get Esys object for handle.
    ret = Esys_TR_FromTPMPublic(
        this->ctx->Get(), KEYHANDLE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &object_handle);
    if (ret != TSS2_RC_SUCCESS) {
        return false;
    }
    return true;
}

#define RSA_KEY_SIZE 2048

std::vector<unsigned char> Tss2Wrapper::Tss2RsaEncrypt(std::vector<unsigned char> const&plaintextData) {
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR persistObjHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC* outPublic = nullptr;
    TPM2B_CREATION_DATA* creationData = nullptr;
    TPM2B_DIGEST* creationHash = nullptr;
    TPMT_TK_CREATION* creationTicket = nullptr;
    TPM2B_PUBLIC_KEY_RSA* cipher = nullptr;
    TPM2B_PUBLIC_KEY_RSA* plain2 = nullptr;
    TPM2B_DATA* null_data = nullptr;
    std::vector<unsigned char> retval = std::vector<unsigned char>();


    TPM2B_AUTH authValuePrimary = {
        0, // size
        {} // buffer
    };

    r = Esys_TR_FromTPMPublic(
        this->ctx->Get(), KEYHANDLE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &primaryHandle);
    if (r != TSS2_RC_SUCCESS)
    {
        // TpmError, Subclass Handles, handlePresentError
        throw TpmError(r, "Failed to read tpm object from handle",
            ErrorCode::TpmError_Handles_handlePresentError);
    }

    r = Esys_TR_SetAuth(this->ctx->Get(), primaryHandle,
        &authValuePrimary);
    if (r != TSS2_RC_SUCCESS)
    {
		// TpmError, Subclass Auth, setAuthError
        throw TpmError(r, "Failed to set auth",
            ErrorCode::TpmError_Auth_setAuthError);
    }

    size_t plain_size = 3;
    TPM2B_PUBLIC_KEY_RSA plain = { 0 };
    std::copy(plaintextData.begin(), plaintextData.end(), plain.buffer);
    plain.size = plaintextData.size();

    TPMT_RSA_DECRYPT scheme;
    scheme.scheme = TPM2_ALG_RSAES;
    r = Esys_RSA_Encrypt(this->ctx->Get(), primaryHandle, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
        null_data, &cipher);
    if (r != TSS2_RC_SUCCESS)
    {
		// CryptoError, Subclass TpmRsa, encryptError
        throw TpmError(r, "Failed to Encrypt data",
            ErrorCode::CryptographyError_TpmRsa_encryptError);
    }
    Esys_Free(null_data);
    retval.insert(retval.end(), cipher->buffer, cipher->buffer + cipher->size); 
    return retval;
}

std::vector<unsigned char> Tss2Wrapper::Tss2RsaDecrypt(std::vector<unsigned char> const&encryptedData) {

    TPM2B_PUBLIC* out_public = 0;
    ESYS_TR ephemeral_handle = ESYS_TR_NONE;

    std::vector<unsigned char> retval = std::vector<unsigned char>();

    ESYS_TR object_handle = {};
    ESYS_TR srk_handle = {};

    ESYS_TR keyHandle, session;
    
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC_KEY_RSA cipher = { 0 };
    TPM2B_PUBLIC_KEY_RSA* plain2 = nullptr;
    TPM2B_DATA* null_data = nullptr;

    TPM2B_AUTH authValue = {
        0, // size
        {} // buffer
    };

    r = Esys_TR_SetAuth(this->ctx->Get(), ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS)
    {
        // TpmError, Subclass Auth, setAuthError
        throw TpmError(r, "Failed to set auth",
            ErrorCode::TpmError_Auth_setAuthError);
    }

    r = Esys_TR_FromTPMPublic(
        this->ctx->Get(), KEYHANDLE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &primaryHandle);
    if (r != TSS2_RC_SUCCESS)
    {
        // TpmError, Subclass Handles, handlePresentError
        throw TpmError(r, "Failed to read tpm object from handle",
            ErrorCode::TpmError_Handles_handlePresentError);
    }

    r = Esys_TR_SetAuth(this->ctx->Get(), primaryHandle,
        &authValue);
    if (r != TSS2_RC_SUCCESS)
    {
        // TpmError, Subclass Auth, setAuthError
        throw TpmError(r, "Failed to set auth",
            ErrorCode::TpmError_Auth_setAuthError);
    }

    // Set plaintext data
    TPM2B_PUBLIC_KEY_RSA plain = { 0 };
    std::copy(encryptedData.begin(), encryptedData.end(), cipher.buffer);
    cipher.size = encryptedData.size();
    
    // Set scheme
    TPMT_RSA_DECRYPT scheme;
    scheme.scheme = TPM2_ALG_RSAES;
 
    // Execute decrypt
    r = Esys_RSA_Decrypt(this->ctx->Get(), primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &cipher, &scheme, null_data, &plain2);
    if (r != TSS2_RC_SUCCESS)
    {
        // CryptoError, Subclass TpmRsa, decryptError
        throw TpmError(r, "Failed to Decrypt data",
            ErrorCode::CryptographyError_TpmRsa_decryptError);
    }
    retval.insert(retval.end(), plain2->buffer, plain2->buffer + plain2->size);

    Esys_Free(null_data);
    Esys_Free(plain2);
    
    return retval;
}