//-------------------------------------------------------------------------------------------------
// <copyright file="Tss2Wrapper.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <fstream>
#include <iterator>
#include <cstring>
#include <iostream>
#include <tss2/tss2_mu.h>

#include "Exceptions.h"
#include "Tpm2Logger.h"
#include "Tss2Ctx.h"
#include "Tss2Session.h"
#include "Tss2Wrapper.h"
#include "Tss2Util.h"

#ifndef PLATFORM_UNIX
#include <windows.h>
#include <../shared/tbs.h>
#pragma comment(lib, "Tbs.lib")
#endif // PLATFORM_UNIX

#define TPM20_VERSION_STRING  0x00322e3000 // The string "2.0\0" in hex
#define TPM12_VERSION_STRING  0x00312e3200 // The string "1.2\0" in hex

// Mask for the error bits of tpm2 compliant return code
#define TPM2_RC_ERROR_MASK 0xFF

using namespace Tpm2Logger;

Tss2Wrapper::Tss2Wrapper()
{
    this->ctx = std::make_unique<Tss2Ctx>();
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetEkNvCert()
{
    return Tss2Util::NvRead(*ctx, EK_CERT_INDEX);
}

std::vector<unsigned char> Tss2Wrapper::CheckAndMarshalEkPub(TPM2B_PUBLIC const *pubPtr)
{
    if (pubPtr == nullptr)
    {
        // Unlikely to be null but better safe than segfault
        throw std::runtime_error("Failed to read or generate EK public portion");
    }

    std::vector<unsigned char> ekPub(sizeof(*pubPtr), '\0');
    size_t offset = 0; // in: index to start copying to, out: end of data

    TSS2_RC ret = Tss2_MU_TPM2B_PUBLIC_Marshal(pubPtr, ekPub.data(), ekPub.size(), &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_PUBLIC", ret);
    }

    // Shrink to fit
    ekPub.resize(offset);

    return ekPub;
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetEkPubWithoutPersisting()
{
    unique_c_ptr<TPM2B_PUBLIC> pubPtr{ Tss2Util::GenerateEk(*ctx) };

    return CheckAndMarshalEkPub(pubPtr.get());
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetEkPub()
{
    // Try to read EK pub from persistent location
    try {
        return Tss2Util::GetPublicObject(*ctx, EK_PUB_INDEX);
    }
    catch (std::exception& e)
    {
        LIBTPM2_LOG(LogLevel::Warn, "GetEkPub Failed, Attempting re-generation", "%s", e.what());

        unique_c_ptr<TPM2B_PUBLIC> pubPtr { Tss2Util::GenerateAndPersistEk(*ctx) };

        return CheckAndMarshalEkPub(pubPtr.get());
    }
}

/* See header */
void Tss2Wrapper::RemovePersistentEk()
{
    unique_esys_tr nvHandle(this->ctx->Get());
    TSS2_RC ret = Esys_TR_FromTPMPublic(this->ctx->Get(), EK_PUB_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nvHandle.get_ptr());
    if (ret != TSS2_RC_SUCCESS) {
        LIBTPM2_LOG(LogLevel::Warn, "Esys_TR_FromTPMPublic", "EK was not persisted in TPM NVRAM");
        return;
    }

    // Since nvHandle and EK_PUB_INDEX refer to the same object, Esys_EvictControl
    // will remove this object from persistent storage
    unique_esys_tr tmpHandle(this->ctx->Get());
    ret = Esys_EvictControl(this->ctx->Get(),
                            ESYS_TR_RH_OWNER,
                            nvHandle.get(),
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            EK_PUB_INDEX,
                            tmpHandle.get_ptr());
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Couldn't remove persistent handle", ret);
    }
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetAIKCert()
{
    return Tss2Util::NvRead(*ctx, AIK_CERT_INDEX);
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetAIKPub()
{
    return Tss2Util::GetPublicObject(*ctx, AIK_PUB_INDEX);
}

/* See header */
attest::PcrQuote Tss2Wrapper::GetPCRQuote(
    const attest::PcrList& pcrs, attest::HashAlg hashAlg)
{
    TSS2_RC ret;
    unique_c_ptr<TPM2B_ATTEST> quotePtr;
    unique_c_ptr<TPMT_SIGNATURE> sigPtr;

    attest::PcrSet pcrSet;
    pcrSet.hashAlg = hashAlg;
    // Select PCRs provided by input vector
    for (auto& pcr : pcrs) {
        attest::PcrValue pcrVal;
        pcrVal.index = pcr;
        pcrSet.pcrs.push_back(pcrVal);
    }

    auto signHandle = Tss2Util::HandleToEsys(*ctx, AIK_PUB_INDEX);
    auto pcrSelect = Tss2Util::GetTssPcrSelection(*ctx, pcrSet, hashAlg);

    TPM2B_DATA inData = {0};
    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_NULL;
    TPM2B_ATTEST *outQuote;
    TPMT_SIGNATURE *outSig;

    ret = Esys_Quote(this->ctx->Get(),
                        signHandle.get(),
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &inData,
                        &inScheme,
                        pcrSelect.get(),
                        &outQuote,
                        &outSig);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to quote PCRs", ret);
    }

    quotePtr = unique_c_ptr<TPM2B_ATTEST>(outQuote);
    sigPtr = unique_c_ptr<TPMT_SIGNATURE>(outSig);

    if (quotePtr == nullptr || sigPtr == nullptr)
    {
        // Unlikely to be null but better safe than segfault
        throw std::runtime_error("Failed to quote PCRs");
    }

    size_t offset;

    // Serialize TPM2B_ATTEST
    std::vector<unsigned char> quote(sizeof(*quotePtr));
    offset = 0; // in: index to start copying to, out: end of data

    ret = Tss2_MU_TPM2B_ATTEST_Marshal(quotePtr.get(), quote.data(), quote.size(), &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPMT_SIGNATURE", ret);
    }

    // Shrink to fit
    quote.resize(offset);

    // Serialize TPMT_SIGNATURE
    std::vector<unsigned char> signature(sizeof(*sigPtr));
    offset = 0; // in: index to start copying to, out: end of data

    ret = Tss2_MU_TPMT_SIGNATURE_Marshal(sigPtr.get(), signature.data(), signature.size(), &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPMT_SIGNATURE", ret);
    }

    // Shrink to fit
    signature.resize(offset);

    attest::PcrQuote pcrQuote;
    pcrQuote.quote = quote;
    pcrQuote.signature = signature;

    return pcrQuote;
}

/* See header */
attest::PcrSet Tss2Wrapper::GetPCRValues(
    const attest::PcrList& pcrs, attest::HashAlg hashAlg)
{
    attest::PcrSet pcrSet;
    pcrSet.hashAlg = hashAlg;
    // Select PCRs provided by input vector
    for (auto& pcr : pcrs) {
        attest::PcrValue pcrVal;
        pcrVal.index = pcr;
        pcrSet.pcrs.push_back(pcrVal);
    }

    // Populate digest for each pcr
    Tss2Util::PopulateCurrentPcrs(*ctx, pcrSet);

    return pcrSet;
}

#ifndef PLATFORM_UNIX

std::vector<unsigned char> Tss2Wrapper::GetTcgLog()
{
    TBS_HCONTEXT hContext;
    TBS_CONTEXT_PARAMS2 contextParams = { TPM_VERSION_20, 0, 0, 1 };
    TBS_RESULT result = Tbsi_Context_Create(reinterpret_cast<const TBS_CONTEXT_PARAMS*>(&contextParams), &hContext);

    if (result != TBS_SUCCESS)
    {
        throw Tss2Exception("Failed to get TBS context object", result);
    }

    UINT32 iLogSize = 0;

    result = Tbsi_Get_TCG_Log(hContext, nullptr, &iLogSize);
    if (result != TBS_SUCCESS)
    {
        throw Tss2Exception("Failed to get TCG Log size", result);
    }

    std::vector<unsigned char> log(iLogSize);

    result = Tbsi_Get_TCG_Log(hContext, log.data(), &iLogSize);
    if (result != TBS_SUCCESS)
    {
        throw Tss2Exception("Failed to get TCG Log", result);
    }

    return log;
}

#else

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetTcgLog()
{
    return GetTcgLogFromFile(TCG_LOG_PATH);
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::GetTcgLogFromFile(std::string fname)
{
    std::ifstream ifs(fname, std::ios::binary);
    ifs.unsetf(std::ios::skipws); // Don't skip newlines
    if (!ifs.good())
    {
        throw FileNotFound();
    }

    std::istream_iterator<unsigned char> start(ifs), end;
    std::vector<unsigned char> log(start, end);
    ifs.close();
    return log;
}

#endif //!PLATFORM_UNIX

/* See header */
attest::TpmVersion Tss2Wrapper::GetVersion()
{
    TPMI_YES_NO isMore = 0;
    TPMS_CAPABILITY_DATA *caps = nullptr;
    TSS2_RC ret;
    const int capsRequested = 1;

    ret = Esys_GetCapability(this->ctx->Get(),
                             ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FAMILY_INDICATOR,
                             capsRequested,  &isMore, &caps);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Esys_GetCapability failed", ret);
    }

    // Esys_GetCapability succeeded. Manage outPub memory with a unique_c_ptr
    auto uniqueCap = unique_c_ptr<TPMS_CAPABILITY_DATA>(caps);

    if (uniqueCap->data.tpmProperties.count != capsRequested)
    {
        // TODO: Log warning: Unexpected count
        // Need to wait for logging code to be merged
    }

    for(uint32_t i = 0 ; i < caps->data.tpmProperties.count; i++)
    {
        if (uniqueCap->data.tpmProperties.tpmProperty[0].property == TPM2_PT_FAMILY_INDICATOR)
        {
            uint32_t value = uniqueCap->data.tpmProperties.tpmProperty[0].value;
            switch (value)
            {
                case TPM20_VERSION_STRING:
                    return attest::TpmVersion::V2_0;
                case TPM12_VERSION_STRING:
                    return attest::TpmVersion::V1_2;
                default:
                    // TODO: Log version string in error
                    throw std::runtime_error("Invalid TPM version string");
            }
        }
    }

    throw std::runtime_error("Could not find TPM version");
}

/* See header */
std::vector<unsigned char> Tss2Wrapper::Unseal(
    const std::vector<unsigned char>& importablePublic,
    const std::vector<unsigned char>& importablePrivate,
    const std::vector<unsigned char>& encryptedSeed,
    const attest::PcrSet& pcrSet,
    const attest::HashAlg hashAlg,
    bool usePcrAuth)
{
    // Open handle to EK
    auto ekHandle = Tss2Util::HandleToEsys(*ctx, EK_PUB_INDEX);

    TPM2B_PUBLIC inPub = {0};
    TPM2B_PRIVATE inPriv = {0};
    TPM2B_ENCRYPTED_SECRET seed = {0};
    TSS2_RC ret;

    // Unmarshal inPub
    size_t offset = 0;
    ret = Tss2_MU_TPM2B_PUBLIC_Unmarshal(importablePublic.data(),
            importablePublic.size(), &offset, &inPub);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal TPM2B_PUBLIC", ret);
    }

    // Unmarshal inPriv
    offset = 0;
    ret = Tss2_MU_TPM2B_PRIVATE_Unmarshal(importablePrivate.data(), importablePrivate.size(),
            &offset, &inPriv);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal TPM2B_PRIVATE", ret);
    }

    // Unmarshal seed
    offset = 0;
    ret = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(encryptedSeed.data(), encryptedSeed.size(),
            &offset, &seed);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal TPM2B_ENCRYPTED_SECRET", ret);
    }

    // Note: Sessions are reset between each call to clear policies from
    // the session. This allows new policies to be set on the next call.

    //
    // Import symmetric key seeded by encryptedSeed
    //
    Tss2Session session(this->ctx->Get());
    session.Start(TPM2_SE_POLICY);
    session.PolicySecret(ESYS_TR_RH_ENDORSEMENT);

    unique_c_ptr<TPM2B_PRIVATE> outPriv;
    TPM2B_PRIVATE* tmpPriv;

    TPMT_SYM_DEF_OBJECT symAlg;
    symAlg.algorithm = TPM2_ALG_NULL;
    ret = Esys_Import(this->ctx->Get(), ekHandle.get(),
            session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
            nullptr, &inPub, &inPriv, &seed, &symAlg, &tmpPriv);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to import encrypted data", ret);
    }
    outPriv.reset(tmpPriv);

    //
    // Load imported key
    //
    session.Restart(TPM2_SE_POLICY);
    session.PolicySecret(ESYS_TR_RH_ENDORSEMENT);

    unique_esys_tr loadedData(this->ctx->Get());
    ret = Esys_Load(this->ctx->Get(), ekHandle.get(),
            session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
            outPriv.get(), &inPub, loadedData.get_ptr());
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to load encrypted data", ret);
    }

    //
    // Set PCR Policy
    //
    ESYS_TR authSession;
    if (usePcrAuth)
    {
        // If the object was sealed to the PCR state, use the current PCR state to unseal
        // it
        auto pcrDigest = Tss2Util::GeneratePcrDigest(pcrSet, hashAlg);
        // Pass PCR hash algorithm for TPML_PCR_SELECTION generation
        auto pcrSelection = Tss2Util::GetTssPcrSelection(*ctx, pcrSet, pcrSet.hashAlg);
        session.Restart(TPM2_SE_POLICY);
        session.PolicyPcr(*pcrDigest, *pcrSelection);
        authSession = session.GetHandle();
    }
    else
    {
        // This is primarily to unseal an object created by the integration tests.
        // An object created with WITH_USERAUTH can be unsealed with a password.
        // This needs to be done in tests due to complications with the authPolicy
        // value on duplicated objects.
        authSession = ESYS_TR_PASSWORD;
    }

    //
    // Unseal loaded data
    //
    unique_c_ptr<TPM2B_SENSITIVE_DATA> outData;
    TPM2B_SENSITIVE_DATA* outTmp;
    ret = Esys_Unseal(this->ctx->Get(), loadedData.get(),
            authSession, ESYS_TR_NONE, ESYS_TR_NONE,
            &outTmp);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to Unseal encrypted data", ret);
    }
    outData.reset(outTmp);

    return std::vector<unsigned char>(outData->buffer, outData->buffer + outData->size);
}

/* See header */
attest::Buffer Tss2Wrapper::UnpackAiKPubToRSA(attest::Buffer& aikPubMarshaled) {

    TPM2B_PUBLIC aikPubStruct = {0};
    size_t offset = 0;

    // deserializes aikPub
    TSS2_RC ret = Tss2_MU_TPM2B_PUBLIC_Unmarshal(aikPubMarshaled.data(), aikPubMarshaled.size(), &offset, &aikPubStruct);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal AikPub", ret);
    }

    attest::Buffer aikPub(aikPubStruct.publicArea.unique.rsa.buffer,
                          aikPubStruct.publicArea.unique.rsa.buffer +
                          aikPubStruct.publicArea.unique.rsa.size);
    return aikPub;
}

/* See header */
attest::PcrQuote Tss2Wrapper::UnpackPcrQuoteToRSA(attest::PcrQuote& pcrQuoteMarshaled) {

    TPM2B_ATTEST pcrQuoteStruct = {0};
    TPMT_SIGNATURE pcrSignatureStruct = {0};
    TSS2_RC ret;
    size_t offset = 0;

    // deserialize quote
    ret = Tss2_MU_TPM2B_ATTEST_Unmarshal(pcrQuoteMarshaled.quote.data(), pcrQuoteMarshaled.quote.size(), &offset, &pcrQuoteStruct);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal PcrQuote", ret);
    }

    // deserialize signature
    offset = 0;
    ret = Tss2_MU_TPMT_SIGNATURE_Unmarshal(pcrQuoteMarshaled.signature.data(), pcrQuoteMarshaled.signature.size(), &offset, &pcrSignatureStruct);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to unmarshal PcrSignature", ret);
    }

    // extract raw quote
    attest::Buffer quote(pcrQuoteStruct.attestationData,
                         pcrQuoteStruct.attestationData + pcrQuoteStruct.size);

    // extract r and s parameter of ecdsa signature
    attest::Buffer signature(pcrSignatureStruct.signature.rsassa.sig.buffer,
                             pcrSignatureStruct.signature.rsassa.sig.buffer +
                             pcrSignatureStruct.signature.rsassa.sig.size);

    attest::PcrQuote pcrQuote;
    pcrQuote.quote = quote;
    pcrQuote.signature = signature;

    return pcrQuote;
}

attest::EphemeralKey Tss2Wrapper::GetEphemeralKey(const attest::PcrSet& pcrSet) {

    TPM2B_PUBLIC *outPublic = NULL;

    ESYS_TR primaryHandle = Tss2Util::CreateEphemeralKey(*ctx, pcrSet, &outPublic);

    // Store the object in a unique_c_ptr<> to manage clean up after use.
    unique_c_ptr<TPM2B_PUBLIC> outPubPtr(outPublic);

    TPM2B_DATA qualifyingData = {0};
    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_NULL;
    TPM2B_ATTEST *certifyInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;
    auto signHandle = Tss2Util::HandleToEsys(*ctx, AIK_PUB_INDEX);

    TSS2_RC ret = Esys_Certify (this->ctx->Get(),
                                primaryHandle,
                                signHandle.get(),
                                ESYS_TR_PASSWORD,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                &qualifyingData,
                                &inScheme,
                                &certifyInfo,
                                &signature
                                );
    if (ret != TSS2_RC_SUCCESS) {
        // Flush the key object from the tpm to make sure we are not consuming tpm memory.
        Tss2Util::FlushObjectContext(*ctx, primaryHandle);
        throw Tss2Exception("Failed to certify ephemeral key", ret);
    }

    // Store the object in a unique_c_ptr<> to manage clean up after use.
    unique_c_ptr<TPM2B_ATTEST> certifyInfoPtr(certifyInfo);
    unique_c_ptr<TPMT_SIGNATURE> certifyInfoSignaturePtr(signature);

    // Flush the key object from the tpm to make sure we are not consuming tpm memory.
    Tss2Util::FlushObjectContext(*ctx, primaryHandle);

    size_t offset = 0;
    std::vector<unsigned char> keyPub(sizeof(*outPubPtr), '\0') ;
    ret = Tss2_MU_TPM2B_PUBLIC_Marshal(outPubPtr.get(), keyPub.data(), keyPub.size(), &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_PUBLIC", ret);
    }

    // Shrink to fit.
    keyPub.resize(offset);

    attest::Buffer certifyInfoMarshaled(certifyInfoPtr->attestationData,
                                        certifyInfoPtr->attestationData + certifyInfoPtr->size);

    attest::Buffer certifyInfoSignatureMarshaled(certifyInfoSignaturePtr->signature.rsassa.sig.buffer,
                                                 certifyInfoSignaturePtr->signature.rsassa.sig.buffer +
                                                 certifyInfoSignaturePtr->signature.rsassa.sig.size);

    attest::EphemeralKey ephemeralKey;
    ephemeralKey.encryptionKey = keyPub;
    ephemeralKey.certifyInfo = certifyInfoMarshaled;
    ephemeralKey.certifyInfoSignature = certifyInfoSignatureMarshaled;

    return ephemeralKey;
}

attest::Buffer Tss2Wrapper::DecryptWithEphemeralKey(const attest::PcrSet& pcrSet,
                                                    const attest::Buffer& encryptedBlob,
                                                    const attest::RsaScheme rsaWrapAlgId,
                                                    const attest::RsaHashAlg rsaHashAlgId) {
    // Create an ephemeral key here and then use that key to decrypted the encrypted blob.
    TPM2B_PUBLIC *outPublic = NULL;

    ESYS_TR primaryHandle = Tss2Util::CreateEphemeralKey(*ctx, pcrSet, &outPublic);

    // Store the object in a unique_c_ptr<> to manage clean up after use.
    unique_c_ptr<TPM2B_PUBLIC> outPubPtr(outPublic);

    Tss2Session session(this->ctx->Get());
    try {
        auto pcrDigest = Tss2Util::GeneratePcrDigest(pcrSet, pcrSet.hashAlg);
        auto pcrSelection = Tss2Util::GetTssPcrSelection(*ctx, pcrSet, pcrSet.hashAlg);
        session.Start(TPM2_SE_POLICY);
        session.PolicyPcr(*pcrDigest, *pcrSelection);
    }
    catch(...) {
        Tss2Util::FlushObjectContext(*ctx, primaryHandle);
        throw;
    }

    if(encryptedBlob.size() > TPM2_MAX_RSA_KEY_BYTES) {
        Tss2Util::FlushObjectContext(*ctx, primaryHandle);
        throw std::runtime_error("Encrypted data size larger than Max RSA key size");
    }
    TPM2B_PUBLIC_KEY_RSA cipher_msg;
    memcpy((void*)cipher_msg.buffer, (void*)encryptedBlob.data(), encryptedBlob.size());
    cipher_msg.size = static_cast<UINT16>(encryptedBlob.size());

    TPMT_RSA_DECRYPT scheme;
    scheme.scheme = rsaWrapAlgId;
    scheme.details.oaep.hashAlg = rsaHashAlgId;
    TPM2B_PUBLIC_KEY_RSA* decrypted = NULL;

     TSS2_RC ret = Esys_RSA_Decrypt(this->ctx->Get(), primaryHandle,
                         session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher_msg, &scheme, nullptr, &decrypted);
    if (ret != TSS2_RC_SUCCESS) {
        // Flush the key object from the tpm to make sure we are not consuming tpm memory.
        Tss2Util::FlushObjectContext(*ctx, primaryHandle);
        throw Tss2Exception("Failed to decrypt message", ret);
    }

    // Flush the key object from the tpm to make sure we are not consuming tpm memory.
    Tss2Util::FlushObjectContext(*ctx, primaryHandle);

    attest::Buffer decryptedBlob(decrypted->buffer, decrypted->buffer + decrypted->size);
    free(decrypted);

    return decryptedBlob;
}

void Tss2Wrapper::WriteAikCert(const std::vector<unsigned char>& aikCert) {

    Tss2Util::NvUndefineSpace(*ctx, AIK_CERT_INDEX);

    int size = aikCert.size();
    Tss2Util::NvDefineSpace(*ctx, AIK_CERT_INDEX, size);

    Tss2Util::NvWrite(*ctx, AIK_CERT_INDEX, aikCert);
}

attest::Buffer Tss2Wrapper::GetHCLReport()
{
    return Tss2Util::NvRead(*ctx, HCL_REPORT_INDEX);
}