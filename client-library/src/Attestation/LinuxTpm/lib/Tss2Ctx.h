//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Ctx.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <tss2/tss2_esys.h>
#ifdef USE_NEW_TCTI_INITIALIZATION
#include <tss2/tss2_tctildr.h>
#else
#include <tss2/tss2_tcti_device.h>
#endif // USE_NEW_TCTI_INITIALIZATION

#include <memory>

/**
 * A wrapper for the TPM2 TSS context which is passed with each TPM2 API call
 */
class Tss2Ctx
{
public:
    Tss2Ctx();
    virtual ~Tss2Ctx();

    virtual ESYS_CONTEXT* Get();

private:
    ESYS_CONTEXT* ctx = nullptr;
#ifdef USE_NEW_TCTI_INITIALIZATION
    TSS2_TCTI_CONTEXT* tctiCtx = nullptr;
#else
    std::unique_ptr<unsigned char[]> tctiCtx = nullptr;
#endif // USE_NEW_TCTI_INITIALIZATION

    TSS2_TCTI_CONTEXT* InitializeTcti();
};
