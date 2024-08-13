//------------------------------------------------------------------------------------------------- 
// <copyright file="TestUtil.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <cstring>
#include <iostream>

#include "Exceptions.h"
#include "TestUtil.h"
#include "Tss2Session.h"
#include "Tss2Util.h"

/**
 * Get and populate the digest for each pcr in pcrSet.pcrs
 */
void TestUtil::PopulateCurrentPcrs(Tss2Ctx& ctx, attest::PcrSet& pcrSet)
{
    auto selection = Tss2Util::GetTssPcrSelection(ctx, pcrSet, pcrSet.hashAlg);

    uint32_t pcrUpdateCounter;

    TPML_PCR_SELECTION* pcrSelOut = nullptr;
    TPML_DIGEST* pcrValues = nullptr;

    uint32_t pcrCount = 0;

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

        if (pcrVals != nullptr && pcrSel != nullptr)
        {
            for (uint32_t i = 0; i < pcrVals->count; i++)
            {
                // Copy pcr digests into pcrSet vectors
                std::copy(pcrVals->digests[i].buffer,
                        pcrVals->digests[i].buffer + pcrVals->digests[i].size,
                        std::back_inserter(pcrSet.pcrs[pcrCount + i].digest));
            }

            pcrCount += pcrVals->count;

            // Remove bits from mask
            for (int i = 0; i < pcrSel->pcrSelections[0].sizeofSelect; i++)
            {
                selection->pcrSelections[0].pcrSelect[i] &= (~pcrSel->pcrSelections[0].pcrSelect[i]);
            }
        }

    } while (pcrCount < pcrSet.pcrs.size());
}

/**
 * Seals clearKey to the TPM PCR state using EK
 */
void TestUtil::SealSeedToEk(
    Tss2Ctx& ctx,
    attest::PcrSet& pcrSet,
    attest::HashAlg hashAlg,
    std::vector<unsigned char>& clearKey,
    std::vector<unsigned char>& outPub,
    std::vector<unsigned char>& outPriv,
    std::vector<unsigned char>& encryptedSeed,
    bool useStoredEk)
{
    TSS2_RC ret;
    unique_esys_tr parent(ctx.Get());
    if (useStoredEk)
    {
        parent = std::move(Tss2Util::HandleToEsys(ctx, EK_PUB_INDEX));
    }
    else
    {
        TPM2B_PUBLIC* outPublic = NULL;
        ESYS_TR ekHandle = Tss2Util::GenerateEkFromSpec(ctx, false, &outPublic);
        // Store the object in a unique_c_ptr<> to manage clean up after use.
        unique_c_ptr<TPM2B_PUBLIC> outPubPtr(outPublic);

        unique_esys_tr ek(ekHandle, ctx.Get());
        parent = std::move(ek);
    }

    TPM2B_PUBLIC inPub = {0};
    inPub.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPub.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPub.publicArea.objectAttributes = TPMA_OBJECT_USERWITHAUTH;
    inPub.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    TPM2B_DATA outsideInfo = {0};
    auto creationPcr = Tss2Util::GetTssPcrSelection(ctx, pcrSet, hashAlg);

    TPM2B_SENSITIVE_CREATE inSensitive = {0};
    inSensitive.sensitive.data.size = static_cast<uint16_t>(clearKey.size());
    memcpy(inSensitive.sensitive.data.buffer, clearKey.data(), clearKey.size());

    TPM2B_PRIVATE* outPrivTmp;
    TPM2B_PUBLIC* outPubTmp;

    //
    // Create a policy that such that the created object can be duplicated and set
    // that as the authValue for inPub
    //

    Tss2Session session(ctx.Get());
    session.Start(TPM2_SE_TRIAL);
    session.PolicyCommandCode(TPM2_CC_Duplicate);

    auto policyDigest = session.GetDigest();
    inPub.publicArea.authPolicy = *policyDigest;

    session.Restart(TPM2_SE_POLICY);
    session.PolicySecret(ESYS_TR_RH_ENDORSEMENT);

    //
    // Create object
    // 
    ret = Esys_Create(ctx.Get(), parent.get(),
                session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
                &inSensitive, &inPub, &outsideInfo, creationPcr.get(),
                &outPrivTmp, &outPubTmp, nullptr, nullptr, nullptr);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Failed to create", ret);
    }

    unique_c_ptr<TPM2B_PUBLIC> outPubUnique(outPubTmp);
    unique_c_ptr<TPM2B_PRIVATE> outPrivUnique(outPrivTmp);

    //
    // Load created object so we can duplicate it
    //
    session.Restart(TPM2_SE_POLICY);
    session.PolicySecret(ESYS_TR_RH_ENDORSEMENT);
    
    unique_esys_tr loadedData(ctx.Get());
    ret = Esys_Load(ctx.Get(), parent.get(),
            session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
            outPrivUnique.get(), outPubUnique.get(), loadedData.get_ptr());
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to load encrypted data", ret);
    }

    //
    // Duplicate private so it can be imported by unseal
    // 
    session.Restart(TPM2_SE_POLICY);
    session.PolicyCommandCode(TPM2_CC_Duplicate);

    TPMT_SYM_DEF_OBJECT symDef = { TPM2_ALG_NULL, 0, TPM2_ALG_NULL };
    TPM2B_DATA* innerKey;
    TPM2B_PRIVATE* duplicate;
    TPM2B_ENCRYPTED_SECRET* outSymSeed;

    ret = Esys_Duplicate(ctx.Get(), loadedData.get(), parent.get(),
            session.GetHandle(), ESYS_TR_NONE, ESYS_TR_NONE,
            nullptr, &symDef, &innerKey, &duplicate, &outSymSeed);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Esys_Duplicate", ret);
    }

    unique_c_ptr<TPM2B_DATA> innerKeyUnique(innerKey);
    unique_c_ptr<TPM2B_PRIVATE> duplicateUnique(duplicate);
    unique_c_ptr<TPM2B_ENCRYPTED_SECRET> outSymSeedUnique(outSymSeed);

    //
    // Serialize all outputs
    //

    // Serialize outPub
    size_t offset = 0;
    outPub.resize(sizeof(*outPubUnique));
    ret = Tss2_MU_TPM2B_PUBLIC_Marshal(outPubUnique.get(),
            outPub.data(),
            outPub.size(),
            &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_PUBLIC", ret);
    }
    outPub.resize(offset);

    // Serialize outPriv
    offset = 0;
    outPriv.resize(sizeof(*duplicateUnique));
    ret = Tss2_MU_TPM2B_PRIVATE_Marshal(duplicateUnique.get(),
            outPriv.data(),
            outPriv.size(),
            &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_PRIVATE", ret);
    }
    outPriv.resize(offset);

    // Serialize outSymSeed
    offset = 0;
    encryptedSeed.resize(sizeof(*outSymSeedUnique));
    ret = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(outSymSeedUnique.get(),
            encryptedSeed.data(),
            encryptedSeed.size(),
            &offset);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to marshal TPM2B_ENCRYPTED_SECRET", ret);
    }
    encryptedSeed.resize(offset);
}

