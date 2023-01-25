//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Ctx.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

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
    std::unique_ptr<unsigned char[]> tctiCtx = nullptr;

    TSS2_TCTI_CONTEXT* InitializeTcti();
};
