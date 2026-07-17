// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <tss2/tss2_sys.h>

#include "CommonTypes.h"
#include "DebugInfo.h"
#include "LibraryLogger.h"
#include "ReturnCodes.h"
#include "TpmError.h"
#include "TssCtx.h"
#include "Tss2Wrapper.h"

#ifndef PLATFORM_UNIX
#include <windows.h>
#include <../shared/tbs.h>
#pragma comment(lib, "Tbs.lib")
#endif // PLATFORM_UNIX

#define SRKHANDLE 0x81000001
#define KEYHANDLE SRKHANDLE + 3
#define RSA_PUBLIC_EXPONENT 0x00010001
#define TPM_PT_NV_INDEX_MAX 1024

static TSS2L_SYS_AUTH_COMMAND MakePasswordAuthCmd() {
    TSS2L_SYS_AUTH_COMMAND cmdAuth = {};
    cmdAuth.count = 1;
    cmdAuth.auths[0].sessionHandle = TPM2_RS_PW;
    return cmdAuth;
}

Tss2Wrapper::Tss2Wrapper()
{
    this->ctx = std::make_unique<TssCtx>();
}

TPM2_RC Tss2Wrapper::RemoveKey() {
    TPM2_RC ret = TSS2_RC_SUCCESS;
    TSS2L_SYS_AUTH_COMMAND cmdAuth = MakePasswordAuthCmd();
    TSS2L_SYS_AUTH_RESPONSE rspAuth = {};

    ret = Tss2_Sys_EvictControl(
        this->ctx->Get(),
        TPM2_RH_OWNER,
        KEYHANDLE,
        &cmdAuth,
        KEYHANDLE,
        &rspAuth);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Handles, evictControlError
        throw TpmError(ret, "Failed to Evict object at handle",
            ErrorCode::TpmError_Handles_evictControlError);
    }
    return ret;
}

TPM2B_PUBLIC Tss2Wrapper::GenerateGuestKey()
{
    TPM2B_PUBLIC inPub = { 0 };

    TPM2B_SENSITIVE_CREATE inPriv = { 0 };
    TPM2B_DATA inOutsideInfo = { 0 };
    TPML_PCR_SELECTION inPcr = { 0 };

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

    TPM2B_PUBLIC outPub = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TPM2B_NAME name = {};
    TPM2_HANDLE primaryHandle = 0;

    TSS2L_SYS_AUTH_COMMAND cmdAuth = MakePasswordAuthCmd();
    TSS2L_SYS_AUTH_RESPONSE rspAuth = {};

    // Create primary
    TSS2_RC ret = Tss2_Sys_CreatePrimary(
        this->ctx->Get(),
        TPM2_RH_OWNER,
        &cmdAuth,
        &inPriv,
        &inPub,
        &inOutsideInfo,
        &inPcr,
        &primaryHandle,
        &outPub,
        &creationData,
        &creationHash,
        &creationTicket,
        &name,
        &rspAuth);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Objects, createError
        throw TpmError(ret, "Failed to create primary object under storage hierarchy",
            ErrorCode::TpmError_Objects_createError);
    }
    LIBSECRETS_LOG(SecretsLogger::LogLevel::Debug, "Create Primary",
        "Public key info %s",
        formatHexBuffer(outPub.publicArea.unique.rsa.buffer, outPub.publicArea.unique.rsa.size).c_str());

    ret = Tss2_Sys_EvictControl(
        this->ctx->Get(),
        TPM2_RH_OWNER,
        primaryHandle,
        &cmdAuth,
        KEYHANDLE,
        &rspAuth);
    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Handles, evictControlError
        throw TpmError(ret, "Failed to EvictControl key",
            ErrorCode::TpmError_Handles_evictControlError);
    }

    return outPub;
}

bool Tss2Wrapper::IsKeyPresent() {
    TPM2B_PUBLIC outPublic = {};
    TPM2B_NAME name = {};
    TPM2B_NAME qualifiedName = {};

    TPM2_RC ret = Tss2_Sys_ReadPublic(
        this->ctx->Get(), KEYHANDLE,
        NULL, &outPublic, &name, &qualifiedName, NULL);
    return ret == TSS2_RC_SUCCESS;
}

static TPMT_RSA_DECRYPT MakeRsaScheme(RsaPaddingScheme paddingScheme) {
    TPMT_RSA_DECRYPT scheme = { 0 };
    switch (paddingScheme) {
        case RsaPaddingScheme::RsaesOaep:
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
            break;
        case RsaPaddingScheme::Rsaes:
        default:
            scheme.scheme = TPM2_ALG_RSAES;
            break;
    }
    return scheme;
}

#define RSA_KEY_SIZE 2048

std::vector<unsigned char> Tss2Wrapper::Tss2RsaEncrypt(std::vector<unsigned char> const&plaintextData,
                                                      RsaPaddingScheme paddingScheme) {
    TSS2_RC r;
    std::vector<unsigned char> retval;

    TPM2B_PUBLIC_KEY_RSA plain = { 0 };
    std::copy(plaintextData.begin(), plaintextData.end(), plain.buffer);
    plain.size = static_cast<uint16_t>(plaintextData.size());

    TPMT_RSA_DECRYPT scheme = MakeRsaScheme(paddingScheme);

    TPM2B_PUBLIC_KEY_RSA cipher = { 0 };

    // RSA_Encrypt is a public-key operation — no auth needed
    r = Tss2_Sys_RSA_Encrypt(this->ctx->Get(), KEYHANDLE,
        NULL, &plain, &scheme, NULL, &cipher, NULL);
    if (r != TSS2_RC_SUCCESS)
    {
        // CryptoError, Subclass TpmRsa, encryptError
        throw TpmError(r, "Failed to Encrypt data",
            ErrorCode::CryptographyError_TpmRsa_encryptError);
    }
    retval.insert(retval.end(), cipher.buffer, cipher.buffer + cipher.size);
    return retval;
}

std::vector<unsigned char> Tss2Wrapper::Tss2RsaDecrypt(std::vector<unsigned char> const&encryptedData,
                                                      RsaPaddingScheme paddingScheme) {
    std::vector<unsigned char> retval;

    TPM2B_PUBLIC_KEY_RSA cipher = { 0 };
    std::copy(encryptedData.begin(), encryptedData.end(), cipher.buffer);
    cipher.size = static_cast<uint16_t>(encryptedData.size());

    TPMT_RSA_DECRYPT scheme = MakeRsaScheme(paddingScheme);

    TPM2B_PUBLIC_KEY_RSA plain = { 0 };

    TSS2L_SYS_AUTH_COMMAND cmdAuth = MakePasswordAuthCmd();
    TSS2L_SYS_AUTH_RESPONSE rspAuth = {};

    // Execute decrypt
    TSS2_RC r = Tss2_Sys_RSA_Decrypt(this->ctx->Get(), KEYHANDLE,
        &cmdAuth, &cipher, &scheme, NULL, &plain, &rspAuth);
    if (r != TSS2_RC_SUCCESS)
    {
        // CryptoError, Subclass TpmRsa, decryptError
        throw TpmError(r, "Failed to Decrypt data",
            ErrorCode::CryptographyError_TpmRsa_decryptError);
    }
    retval.insert(retval.end(), plain.buffer, plain.buffer + plain.size);

    return retval;
}

std::vector<unsigned char> Tss2Wrapper::Tss2NvRead(TPM2_HANDLE nvIndex) {
    TSS2_RC r;
    TPM2B_NV_PUBLIC nvPubData = {};
    TPM2B_NAME nvName = {};
    std::vector<unsigned char> data;

    // Get the NV public data for size
    r = Tss2_Sys_NV_ReadPublic(this->ctx->Get(), nvIndex,
        NULL, &nvPubData, &nvName, NULL);
    if (r != TSS2_RC_SUCCESS)
    {
        // TpmError, Subclass Handles, handlePresentError
        throw TpmError(r, "Failed to read tpm object from handle",
            ErrorCode::TpmError_Handles_handlePresentError);
    }

    size_t size = nvPubData.nvPublic.dataSize;
    data.resize(size);
    size_t offset = 0;

    TSS2L_SYS_AUTH_COMMAND cmdAuth = MakePasswordAuthCmd();
    TSS2L_SYS_AUTH_RESPONSE rspAuth = {};

    while (size > 0) {
        uint16_t bytesToRead = size > TPM_PT_NV_INDEX_MAX ? TPM_PT_NV_INDEX_MAX : static_cast<uint16_t>(size);

        TPM2B_MAX_NV_BUFFER nvData = {};
        r = Tss2_Sys_NV_Read(this->ctx->Get(),
            TPM2_RH_OWNER, nvIndex,
            &cmdAuth,
            bytesToRead, static_cast<uint16_t>(offset),
            &nvData, &rspAuth);
        if (r != TSS2_RC_SUCCESS)
        {
            throw TpmError(r, "Failed to read NV data",
                ErrorCode::TpmError_Handles_esysNvReadError);
        }

        std::copy(nvData.buffer, nvData.buffer + nvData.size, data.begin() + offset);
        size -= nvData.size;
        offset += nvData.size;
    }

    return data;
}
