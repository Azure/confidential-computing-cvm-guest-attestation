//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Session.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include "Exceptions.h"
#include "Tss2Memory.h"
#include "Tss2Session.h"

Tss2Session::Tss2Session(ESYS_CONTEXT* ctx) : sessionHandle(ctx), ctx(ctx) {  }

Tss2Session::~Tss2Session()
{
    this->Flush();
}

/* See header */
void Tss2Session::Start(TPM2_SE sessionType)
{
    TPM2B_NONCE nonceCaller = {0};
    nonceCaller.size = TPM2_SHA1_DIGEST_SIZE;
    TPMT_SYM_DEF symmetric = {0};
    symmetric.algorithm = TPM2_ALG_NULL;

    TSS2_RC ret = Esys_StartAuthSession(ctx,
                        ESYS_TR_NONE, ESYS_TR_NONE,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nonceCaller, sessionType, &symmetric,
                        TPM2_ALG_SHA256, sessionHandle.get_ptr());

    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Failed to start auth session", ret);
    }
}

/* See header */
void Tss2Session::Restart(TPM2_SE sessionType)
{
    this->Flush();
    this->Start(sessionType);
}

/* See header */
void Tss2Session::Flush()
{
    if (sessionHandle.get() != 0)
    {
        TSS2_RC ret = Esys_FlushContext(ctx, sessionHandle.get());
        if (ret != TSS2_RC_SUCCESS)
        {
            throw Tss2Exception("Tss2Session failed to flush ESYS context", ret);
        }
        sessionHandle.invalidate();
    }
}

/* See header */
void Tss2Session::PolicySecret(ESYS_TR authorityHandle)
{
    TSS2_RC ret = Esys_PolicySecret(ctx, authorityHandle, sessionHandle.get(),
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        nullptr, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Tss2Session failed to set policy secret", ret);
    }
}

/* See header */
void Tss2Session::PolicyPcr(TPM2B_DIGEST& digest, TPML_PCR_SELECTION& pcrSelection)
{
    TSS2_RC ret = Esys_PolicyPCR(ctx, sessionHandle.get(),
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &digest, &pcrSelection);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Tss2Session failed to set policy pcr", ret);
    }
}

/* See header */
void Tss2Session::PolicyCommandCode(TPM2_CC command)
{
    TSS2_RC ret = Esys_PolicyCommandCode(ctx,
                           sessionHandle.get(),
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           command);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Tss2Session failed to set policy command code", ret);
    }
}

/* See header */
void Tss2Session::PolicyAuthValue()
{
    TSS2_RC ret  = Esys_PolicyAuthValue(ctx,
                         sessionHandle.get(),
                         ESYS_TR_NONE,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Tss2Session failed to set policy auth value", ret);
    }
}

/* See header */
unique_c_ptr<TPM2B_DIGEST> Tss2Session::GetDigest()
{
    TPM2B_DIGEST* policyDigest;
    TSS2_RC ret = Esys_PolicyGetDigest(ctx, sessionHandle.get(),
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);
    if (ret != TSS2_RC_SUCCESS)
    {
        throw Tss2Exception("Tss2Session failed to get policy digest", ret);
    }

    return unique_c_ptr<TPM2B_DIGEST>(policyDigest);
}

/* See header */
ESYS_TR Tss2Session::GetHandle()
{
    return sessionHandle.get();
}
