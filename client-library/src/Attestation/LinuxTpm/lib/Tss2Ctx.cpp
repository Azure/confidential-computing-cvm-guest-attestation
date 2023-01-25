//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Ctx.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "Exceptions.h"
#include "Tss2Ctx.h"
#ifndef PLATFORM_UNIX
#include "tss2/tss2_tcti_tbs.h"  // Windows context handling is routed to tbs library
#define TPM_DEVICE "" // For windows we don't need the device Manager context string. 
#else 
#define TPM_DEVICE "/dev/tpmrm0" // Use in-kernel resource manager.
#endif // !PLATFORM_UNIX


Tss2Ctx::Tss2Ctx()
{
    TSS2_ABI_VERSION abiVer = TSS2_ABI_VERSION_CURRENT; // These are the current default values of the TPM2-TSS library.

    auto tcti = InitializeTcti();

    TSS2_RC ret = Esys_Initialize(&ctx, tcti, &abiVer);
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to initialize TSS context", ret);
    }
}

Tss2Ctx::~Tss2Ctx()
{
    // Esys_Finalize will free its own memory for ctx. Tss2_Tcti_Finalize will not,
    // but its memory is managed by a unique_ptr.
    if (ctx != nullptr) {
        Esys_Finalize(&ctx);
    }

    if (tctiCtx != nullptr) {
        Tss2_Tcti_Finalize((TSS2_TCTI_CONTEXT*)tctiCtx.get());
    }
}

ESYS_CONTEXT* Tss2Ctx::Get()
{
    return this->ctx;
}

//
// Private helpers
//

/**
 * Initializes TCTI interface. Uses a direct connection to the tpm resource
 * resource manager device file.
 */
TSS2_TCTI_CONTEXT* Tss2Ctx::InitializeTcti()
{
    TSS2_RC ret { TSS2_TCTI_RC_GENERAL_FAILURE };
    size_t size {0};
    const char* device = TPM_DEVICE;
    // Get tcti size
#ifdef PLATFORM_UNIX
    ret = Tss2_Tcti_Device_Init(nullptr, &size, nullptr);
#else
    ret = Tss2_Tcti_Tbs_Init(nullptr, &size, nullptr);
#endif // PLATFORM_UNIX
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to get TCTI context size", ret);
    }

    tctiCtx = std::make_unique<unsigned char[]>(size);
    if (tctiCtx == nullptr) {
        throw std::runtime_error("Failed to allocate TCTI context memory");
    }

    // Populate TCTI context
#ifdef PLATFORM_UNIX
    ret = Tss2_Tcti_Device_Init((TSS2_TCTI_CONTEXT*)tctiCtx.get(), &size, device);
#else
    ret = Tss2_Tcti_Tbs_Init((TSS2_TCTI_CONTEXT*)tctiCtx.get(), &size, device);
#endif // PLATFORM_UNIX
   
    if (ret != TSS2_RC_SUCCESS) {
        throw Tss2Exception("Failed to initialize TCTI context", ret);
    }

    return (TSS2_TCTI_CONTEXT*)tctiCtx.get();
}

