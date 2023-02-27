//-------------------------------------------------------------------------------------------------
// <copyright file="Tss2Util.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <cstring>
#include <sstream>
#include <tss2/tss2_mu.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "AttestationTypes.h"
#include "Exceptions.h"
#include "Tss2Memory.h"
#include "Tss2Session.h"
#include "Tss2Util.h"
#ifdef _DEBUG
#include "DebugInfoTSS_Structures.h"
#endif

#define TSS2_RC_ERROR_MASK 0xFF

// TODO: Figure out why buffer size 2048 doesn't work
#define __TPM2_MAX_NV_BUFFER_SIZE 512

// Forward declarations for private C-style functions
static void _PopulateEkPublicInput(Tss2Ctx& ctx, TPM2B_PUBLIC& inPub);
static const EVP_MD* _GetOpenSslAlg(attest::HashAlg algorithm);

/* See header */
unique_c_ptr<TPM2B_PUBLIC> Tss2Util::GenerateEk(Tss2Ctx& ctx)
{
    TPM2B_PUBLIC inPub = {0};
    _PopulateEkPublicInput(ctx, inPub);

    //
    // Generate EK
    //
    TPM2B_SENSITIVE_CREATE inPriv = {0};
    TPM2B_DATA inOutsideInfo = {0};
    TPML_PCR_SELECTION inPcr = {0};

    unique_esys_tr outHandle(ctx.Get()); // Handle to created object
    TPM2B_PUBLIC* outPub;

    // Create primary
    TSS2_RC ret = Esys_CreatePrimary(ctx.Get(),
                            ESYS_TR_RH_ENDORSEMENT,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &inPriv,
                            &inPub,
                            &inOutsideInfo,
                            &inPcr,
                            outHandle.get_ptr(),
                            &outPub,
                            nullptr,
                            nullptr,
                            nullptr);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to create primary object under endorsement hierarchy", ret);
    }

    unique_c_ptr<TPM2B_PUBLIC> outPubPtr(outPub);

    return outPubPtr;
}

/* See header */
unique_c_ptr<TPM2B_PUBLIC> Tss2Util::GenerateAndPersistEk(Tss2Ctx& ctx)
{
    unique_esys_tr outHandle(ctx.Get()); // Handle to created object

    unique_c_ptr<TPM2B_PUBLIC> outPubPtr = GenerateEk(ctx);

    //
    // Persist EK in TPM NVRAM
    //
    unique_esys_tr tmpHandle(ctx.Get());
    TSS2_RC ret = Esys_EvictControl(ctx.Get(),
                            ESYS_TR_RH_OWNER,
                            outHandle.get(),
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            EK_PUB_INDEX,
                            tmpHandle.get_ptr());

    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to persist EK in TPM NVRAM", ret);
    }

    return outPubPtr;
}

/* See header */
std::vector<unsigned char> Tss2Util::GetPublicObject(Tss2Ctx& ctx, TPM2_HANDLE index)
{
    TSS2_RC ret;
    unique_c_ptr<TPM2B_PUBLIC> pubPtr;

    // Read public object from persistent location
    auto nvHandle = Tss2Util::HandleToEsys(ctx, index);
    TPM2B_PUBLIC* outPub;

    ret = Esys_ReadPublic(ctx.Get(), nvHandle.get(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &outPub, nullptr, nullptr);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to read public portion", ret);
    }

    pubPtr = unique_c_ptr<TPM2B_PUBLIC>(outPub);

    if (pubPtr == nullptr)
    {
        // Unlikely to be null but better safe than segfault
        throw std::runtime_error("Failed to read or generate public portion");
    }

    // Serialize TPM2B_PUBLIC
    std::vector<unsigned char> pub(sizeof(*pubPtr));
    size_t offset = 0; // in: index to start copying to, out: end of data

    ret = Tss2_MU_TPM2B_PUBLIC_Marshal(pubPtr.get(), pub.data(), pub.size(), &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_PUBLIC", ret);
    }

    // Shrink to fit
    pub.resize(offset);

    return pub;
}

/* See header */
std::vector<unsigned char> Tss2Util::NvRead(Tss2Ctx& ctx, TPM2_HANDLE index)
{
    // Open handle at index
    auto nvHandle = HandleToEsys(ctx, index);

    //
    // Read public portion at nvIndex
    //
    TPM2B_NV_PUBLIC* nvPubTmp = nullptr;
    TSS2_RC ret = Esys_NV_ReadPublic(ctx.Get(), nvHandle.get(),
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvPubTmp, nullptr);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to read public portion of EK cert nv index", ret);
    }
    unique_c_ptr<TPM2B_NV_PUBLIC> nvPub(nvPubTmp);

    int size = nvPub->nvPublic.dataSize;
    int offset = 0;
    std::vector<unsigned char> data;
    data.reserve(size);
    //
    // Read NV data pointed to by public portion
    //
    TPM2B_MAX_NV_BUFFER* nvData = nullptr;
    unique_c_ptr<TPM2B_MAX_NV_BUFFER> nvDataUnique;

    while (size > 0) {
        uint16_t bytesToRead = size > __TPM2_MAX_NV_BUFFER_SIZE ? __TPM2_MAX_NV_BUFFER_SIZE : size;

        ret = Esys_NV_Read(ctx.Get(),
                           ESYS_TR_RH_OWNER,
                           nvHandle.get(),
                           ESYS_TR_PASSWORD,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           bytesToRead,
                           offset,
                           &nvData);
        if (ret != TSS2_RC_SUCCESS) {
            throw Tss2Exception("Failed to read from TPM NV RAM", ret);
        }

        nvDataUnique.reset(nvData);

        std::copy(nvData->buffer, nvData->buffer + nvData->size, std::back_inserter(data));
        // Calculate size remaining and next offset
        size -= nvData->size;
        offset += nvData->size;
    }

    data.resize(nvPub->nvPublic.dataSize);

    return data;
}


/* See header */
unique_esys_tr Tss2Util::HandleToEsys(Tss2Ctx& ctx, TPM2_HANDLE handle)
{
    unique_esys_tr esys(ctx.Get());
    TSS2_RC ret = Esys_TR_FromTPMPublic(ctx.Get(), handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            esys.get_ptr());
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to open ESYS_TR", ret);
    }
    return esys;
}

/**
 * Populates EK TPM2B_PUBLIC with the EK template found in NVRAM in the
 * TPM. If no EK template present, the default values are used as defined
 * in the EK spec.
 *
 * param[in] ctx: TSS ESAPI context
 * param[inout] inPub: EK TPM2B_PUBLIC structure to be populated
 */
void _PopulateEkPublicInput(Tss2Ctx& ctx, TPM2B_PUBLIC& inPub)
{
    TSS2_RC ret;

    //
    // Read EK Template to determine parameters
    //
    try {
        auto ekTemplate = Tss2Util::NvRead(ctx, EK_TEMPLATE_INDEX);
        TPMT_PUBLIC temp = {0};

        size_t offset = 0; // in: index to start copying from, out: end of data
        ret = Tss2_MU_TPMT_PUBLIC_Unmarshal(ekTemplate.data(), ekTemplate.size(), &offset, &temp);
        if (ret != TSS2_RC_SUCCESS) {
            throw Tss2Exception("Failed to unmarshal ek template", ret);
        }

        inPub.publicArea = temp;
    } catch(Tss2Exception& e) {
        if ((e.get_rc() & TSS2_RC_ERROR_MASK) != TPM2_RC_HANDLE) {
            // If error other than not found, rethrow
            throw;
        }

        // There was no Ek template. Use default values for EK generation
        const unsigned char EK_AUTH_POLICY[] = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
            0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
            0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
            0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
        };
        std::memcpy(&inPub.publicArea.authPolicy.buffer, &EK_AUTH_POLICY, sizeof(EK_AUTH_POLICY));
        inPub.publicArea.authPolicy.size = sizeof(EK_AUTH_POLICY);

        inPub.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPub.publicArea.type = TPM2_ALG_RSA;
        inPub.publicArea.objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|
                                            TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|
                                            TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_ADMINWITHPOLICY;

        inPub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        inPub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPub.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        inPub.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        inPub.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPub.publicArea.parameters.rsaDetail.exponent = 0; // TPM will use default for RSA
        inPub.publicArea.unique.rsa.size = 256;
    }

    //
    // Read EK nonce. If not present use default value
    //
    try {
        // Read EK Nonce
        auto ekNonce = Tss2Util::NvRead(ctx, EK_NONCE_INDEX);
        std::memcpy(&inPub.publicArea.unique.rsa.buffer, ekNonce.data(), ekNonce.size());
    } catch (Tss2Exception& e) {
        if ((e.get_rc() & TSS2_RC_ERROR_MASK) != TPM2_RC_HANDLE) {
            // If error other than not found, rethrow
            throw;
        }
    }
}

/**
 * Get EVP_MD openssl hash algorithm for `algorithm`
 */
const EVP_MD* _GetOpenSslAlg(attest::HashAlg algorithm) {
    switch (algorithm) {
        case attest::HashAlg::Sha1:
            return EVP_sha1();
        case attest::HashAlg::Sha256:
            return EVP_sha256();
        case attest::HashAlg::Sha384:
            return EVP_sha384();
        case attest::HashAlg::Sha512:
            return EVP_sha512();
        case attest::HashAlg::Sm3_256:
            return EVP_sha256();
        default:
            return nullptr;
    }
}

/* See header */
unique_c_ptr<TPML_PCR_SELECTION> Tss2Util::GetTssPcrSelection(
        Tss2Ctx& ctx,
        const attest::PcrSet& pcrSet,
        attest::HashAlg hashAlg)
{
    auto pcrCount = Tss2Util::GetPcrCount(ctx);
    uint32_t pcrMask = 0;
    for (auto& pcr : pcrSet.pcrs) {
        if (pcr.index < 0 || pcr.index >= pcrCount) {
            throw std::runtime_error("PCR index out of range");
        }
        pcrMask |= (1 << pcr.index);
    }

    // PcrSet can only refer to one hash algorithm so we only need to allocate enough
    // space for one PCR bank
    auto pcrSel = unique_c_ptr<TPML_PCR_SELECTION>(
            (TPML_PCR_SELECTION*)calloc(1, sizeof(TPML_PCR_SELECTION)));
    // Setting the query for only one PCRBank
    pcrSel->count = 1;
    const auto SIZE_OF_OCTET { 8 };
    // Support up to PCR 24. This is the number of PCRs a PCR bank has on most
    // PCs and is more than enough for current firmware/OS usage of PCRs
    // Ideally for calculating the sizeofSelect Following rule should apply:
    // size_t t = sizeof(decltype(pcrSel->pcrSelections[0].pcrSelect[0]));
    // sizeofSelect =  pcrCount / t * SIZE_OF_OCTET;
    pcrSel->pcrSelections[0].sizeofSelect = pcrCount / SIZE_OF_OCTET;
    pcrSel->pcrSelections[0].hash = Tss2Util::GetTssHashAlg(hashAlg);
    //Copying the 32bit pcrMask to pcrSelect, BYTE array of size 4.
    pcrSel->pcrSelections[0].pcrSelect[0] = (pcrMask & 0xff);
    pcrSel->pcrSelections[0].pcrSelect[1] = (pcrMask & 0xff00) >> 8;
    pcrSel->pcrSelections[0].pcrSelect[2] = (pcrMask & 0xff0000) >> 16;
    pcrSel->pcrSelections[0].pcrSelect[3] = (pcrMask & 0xff000000) >> 24;

    return pcrSel;
}

/**
 * Gets the string representation of the last openssl error
 */
static inline const char *get_openssl_err(void) {
    return ERR_error_string(ERR_get_error(), nullptr);
}

/* See header */
unique_c_ptr<TPM2B_DIGEST> Tss2Util::GeneratePcrDigest(
    const attest::PcrSet& pcrSet,
    attest::HashAlg hashAlg)
{
    const EVP_MD *md = _GetOpenSslAlg(hashAlg);
    if (!md) {
        std::stringstream ss;
        ss << "Error generating PCR digest, unknown hash algorithm: " << hashAlg;
        throw std::runtime_error(ss.str());
    }

    unique_evp_md mdctx(EVP_MD_CTX_create());
    if (!mdctx) {
        std::stringstream ss;
        ss << "Error initializing OpenSSL EVP context:" << get_openssl_err();;
        throw std::runtime_error(ss.str());
    }

    int ret = EVP_DigestInit_ex(mdctx.get(), md, nullptr);
    if (!ret) {
        throw OpenSslException(get_openssl_err(), ret);
    }

    unique_c_ptr<TPM2B_DIGEST> digest((TPM2B_DIGEST*)malloc(sizeof(TPM2B_DIGEST)));

    for (auto& pcr : pcrSet.pcrs) {
        ret = EVP_DigestUpdate(mdctx.get(), pcr.digest.data(), pcr.digest.size());
        if (!ret) {
            throw OpenSslException(get_openssl_err(), ret);
        }
    }

    uint32_t size = EVP_MD_size(md);

    ret = EVP_DigestFinal_ex(mdctx.get(), digest->buffer, &size);
    if (!ret) {
        throw OpenSslException(get_openssl_err(), ret);
    }

    digest->size = size;

    return digest;
}

/* See header */
void Tss2Util::PopulateCurrentPcrs(Tss2Ctx& ctx, attest::PcrSet& pcrSet)
{
    auto selection = Tss2Util::GetTssPcrSelection(ctx, pcrSet, pcrSet.hashAlg);

    uint32_t pcrUpdateCounter {0};

    TPML_PCR_SELECTION* pcrSelOut = nullptr;
    TPML_DIGEST* pcrValues = nullptr;

    uint32_t pcrCount = 0;
    uint32_t maskSum = 0;

    do
    {
        TSS2_RC ret = Esys_PCR_Read(ctx.Get(),
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            selection.get(), &pcrUpdateCounter, &pcrSelOut, &pcrValues);
        if (ret != TSS2_RC_SUCCESS)
        {
            throw Tss2Exception("Unable to read PCRs", ret);
        }

        unique_c_ptr<TPML_DIGEST> pcrVals(pcrValues);
        unique_c_ptr<TPML_PCR_SELECTION> pcrSel(pcrSelOut);

        if (pcrVals != nullptr && pcrSel != nullptr && pcrVals->count != 0)
        {
            for (uint32_t i = 0; i < pcrVals->count; i++)
            {
                // Copy pcr digests into pcrSet vectors
                std::copy(pcrVals->digests[i].buffer,
                        pcrVals->digests[i].buffer + pcrVals->digests[i].size,
                        std::back_inserter(pcrSet.pcrs[pcrCount + i].digest));
            }

            pcrCount += pcrVals->count;

            maskSum = 0;
            // Remove bits from mask.
            // We can also use bitwise operators to do bit shift, I guess we are not doing it
            // because we are not sure which pcrSelect index will be selected by the PCR_read.
            for (uint8_t i = 0; i < pcrSel->pcrSelections[0].sizeofSelect; i++)
            {
                selection->pcrSelections[0].pcrSelect[i] &= (~pcrSel->pcrSelections[0].pcrSelect[i]);
                maskSum += selection->pcrSelections[0].pcrSelect[i];
            }
        }

    } while (maskSum != 0);
}

/* See header */
uint8_t Tss2Util::GetPcrCount(Tss2Ctx& ctx)
{
    TPMI_YES_NO isMore = 0;
    TPMS_CAPABILITY_DATA *caps = nullptr;
    TSS2_RC ret;
    const int capsRequested = 1;

    ret = Esys_GetCapability(ctx.Get(),
                             ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PCR_COUNT,
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
        if (uniqueCap->data.tpmProperties.tpmProperty[0].property == TPM2_PT_PCR_COUNT)
        {
            //Downgrading (casting) the 32bit to 8bit, because we known the size of
            //PCR count will always be in the range of uint8_t.
            return static_cast<uint8_t>(uniqueCap->data.tpmProperties.tpmProperty[0].value);
        }
    }

    throw std::runtime_error("Could not find PCR count");
}

/* See header */
TPMI_ALG_HASH Tss2Util::GetTssHashAlg(attest::HashAlg hashAlg)
{
    switch (hashAlg) {
        case attest::HashAlg::Sha1:
            return TPM2_ALG_SHA1;
        case attest::HashAlg::Sha256:
            return TPM2_ALG_SHA256;
        case attest::HashAlg::Sha384:
            return TPM2_ALG_SHA384;
        case attest::HashAlg::Sha512:
            return TPM2_ALG_SHA512;
        case attest::HashAlg::Sm3_256:
            return TPM2_ALG_SM3_256;
        default:
            throw std::runtime_error("Unknown hash algorithm");
    }
}

unique_c_ptr<TPM2B_DIGEST> Tss2Util::GetEphemeralKeyPolicyDigest(Tss2Ctx& ctx,
                                                                 const attest::PcrSet& pcrSet) {

    auto pcrDigest = Tss2Util::GeneratePcrDigest(pcrSet, pcrSet.hashAlg);
    auto pcrSelection = Tss2Util::GetTssPcrSelection(ctx, pcrSet, pcrSet.hashAlg);

    Tss2Session session(ctx.Get());
    session.Start(TPM2_SE_TRIAL);
    session.PolicyPcr(*pcrDigest, *pcrSelection);

    return session.GetDigest();
}

void Tss2Util::PopulateEphemeralKeyPublicTemplate(Tss2Ctx& ctx,
                                                  const attest::PcrSet& pcrSet,
                                                  TPM2B_PUBLIC& inPub) {

    inPub.publicArea.type = TPM2_ALG_RSA;
    inPub.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPub.publicArea.objectAttributes = (TPMA_OBJECT_DECRYPT |
                                            TPMA_OBJECT_FIXEDTPM |
                                            TPMA_OBJECT_FIXEDPARENT |
                                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                            TPMA_OBJECT_NODA);

    inPub.publicArea.unique.rsa.size = 256;
    inPub.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSAES;
    inPub.publicArea.parameters.rsaDetail.exponent = 0;
    inPub.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPub.publicArea.parameters.rsaDetail.symmetric.algorithm =  TPM2_ALG_NULL;

    auto policyDigest = Tss2Util::GetEphemeralKeyPolicyDigest(ctx, pcrSet);

    std::memcpy((void *)inPub.publicArea.authPolicy.buffer, (const void *)policyDigest->buffer, policyDigest->size);
    inPub.publicArea.authPolicy.size = policyDigest->size;

    return;
}

ESYS_TR Tss2Util::CreateEphemeralKey(Tss2Ctx& ctx,
                                     const attest::PcrSet& pcrSet,
                                     TPM2B_PUBLIC** outPub) {

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC inPub = {0};
    Tss2Util::PopulateEphemeralKeyPublicTemplate(ctx,
                                                 pcrSet,
                                                 inPub);

    // Populate authPolicy with policy digest here.

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {0};
    TPM2B_DATA outsideInfo = {0};
    TPML_PCR_SELECTION creationPCR = {0};
    TPM2B_AUTH authValue = {0};

    TSS2_RC ret = Esys_CreatePrimary(ctx.Get(), ESYS_TR_RH_NULL, ESYS_TR_PASSWORD,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                                     &inPub, &outsideInfo, &creationPCR,
                                     &primaryHandle, outPub, nullptr, nullptr, nullptr);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to create Ephemeral Key", ret);
    }

    return primaryHandle;
}

void Tss2Util::FlushObjectContext(Tss2Ctx& ctx, ESYS_TR handle) {

    TSS2_RC ret = Esys_FlushContext(ctx.Get(), handle);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to flush context of the object", ret);
    }
    return;
}

void Tss2Util::NvUndefineSpace(Tss2Ctx& ctx, TPM2_HANDLE index) {
    auto nvHandle = HandleToEsys(ctx, index);

    TSS2_RC ret = Esys_NV_UndefineSpace(ctx.Get(), ESYS_TR_RH_OWNER,
        nvHandle.get(), ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);

    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to undefine NV space", ret);
    }
}

void Tss2Util::NvDefineSpace(Tss2Ctx& ctx, TPM2_HANDLE index, int size) {
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_AUTH authValue = { 0 };
    TPM2B_NV_PUBLIC publicInfo = { 0 };
    publicInfo.nvPublic.nvIndex = index;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA256;
    publicInfo.nvPublic.attributes = (TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE | TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE);
    publicInfo.nvPublic.dataSize = size;

    TSS2_RC ret = Esys_NV_DefineSpace(ctx.Get(), ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &authValue, &publicInfo, &nvHandle);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to define NV space", ret);
    }
}

void Tss2Util::NvWrite(Tss2Ctx& ctx, TPM2_HANDLE index, const std::vector<unsigned char> data) {
    auto nvHandle = HandleToEsys(ctx, index);
    int size = data.size();
    int offset = 0;
    while (size > 0) {
        uint16_t bytesToWrite = size > __TPM2_MAX_NV_BUFFER_SIZE ? __TPM2_MAX_NV_BUFFER_SIZE : size;
        TPM2B_MAX_NV_BUFFER nvData = { 0 };
        nvData.size = bytesToWrite;
        int bufferIdx = 0;
        for (int start = offset; start < (offset + bytesToWrite); start++) {
            nvData.buffer[bufferIdx++] = data[start];
        }

        TSS2_RC ret = Esys_NV_Write(ctx.Get(), ESYS_TR_RH_OWNER, nvHandle.get(),
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &nvData, offset);
        if (ret != TSS2_RC_SUCCESS) {
            throw Tss2Exception("Failed to perform NV write", ret);
        }

        size -= bytesToWrite;
        offset += bytesToWrite;
    }
}