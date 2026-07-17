// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "TssCtx.h"
#include "TpmError.h"
#include "ReturnCodes.h"
#ifndef PLATFORM_UNIX
#include "tss2/tss2_tcti_tbs.h"  // Windows context handling is routed to tbs library
#define TPM_DEVICE "" // For windows we don't need the device Manager context string. 
#else 
#include "tss2/tss2_tcti_device.h"  // Linux context handling is routed to device library
#define TPM_DEVICE "/dev/tpmrm0" // Use in-kernel resource manager.
#endif // !PLATFORM_UNIX


TssCtx::TssCtx()
{
    TSS2_ABI_VERSION abiVer = TSS2_ABI_VERSION_CURRENT;

    auto tcti = InitializeTcti();

    size_t sysSize = Tss2_Sys_GetContextSize(0);
    sysCtxBuf = std::make_unique<unsigned char[]>(sysSize);
    if (sysCtxBuf == nullptr) {
        throw std::runtime_error("Failed to allocate SYS context memory");
    }

    TSS2_SYS_CONTEXT* sysCtx = (TSS2_SYS_CONTEXT*)sysCtxBuf.get();
    TSS2_RC ret = Tss2_Sys_Initialize(sysCtx, sysSize, tcti, &abiVer);
    if (ret != TSS2_RC_SUCCESS) {
        throw TpmError(ret, "Failed to initialize TSS context",
            ErrorCode::TpmError_Context_esysInitError);
    }
}

TssCtx::~TssCtx()
{
    if (sysCtxBuf != nullptr) {
        Tss2_Sys_Finalize((TSS2_SYS_CONTEXT*)sysCtxBuf.get());
    }

    if (tctiCtx != nullptr) {
        Tss2_Tcti_Finalize((TSS2_TCTI_CONTEXT*)tctiCtx.get());
    }
}

TSS2_SYS_CONTEXT* TssCtx::Get()
{
    return (TSS2_SYS_CONTEXT*)sysCtxBuf.get();
}

/**
 * Initializes TCTI interface. Uses a direct connection to the tpm resource
 * resource manager device file.
 */
TSS2_TCTI_CONTEXT* TssCtx::InitializeTcti()
{
    TSS2_RC ret{ TSS2_TCTI_RC_GENERAL_FAILURE };
    size_t size{ 0 };
    const char* device = TPM_DEVICE;
    // Get tcti size
#ifdef PLATFORM_UNIX
    ret = Tss2_Tcti_Device_Init(nullptr, &size, nullptr);
#else
    ret = Tss2_Tcti_Tbs_Init(nullptr, &size, nullptr);
#endif // PLATFORM_UNIX
    if (ret != TSS2_RC_SUCCESS) {
		// TpmError, Subclass Context, tctiInitError
        throw TpmError(ret, "Failed to initialize TSS context - size",
            ErrorCode::TpmError_Context_tctiInitError);
    }

    tctiCtx = std::make_unique<unsigned char[]>(size);
    if (tctiCtx == nullptr) {
		// GeneralError, MemoryError, allocationError
        throw std::runtime_error("Failed to allocate TCTI context memory");
    }

    // Populate TCTI context
#ifdef PLATFORM_UNIX
    ret = Tss2_Tcti_Device_Init((TSS2_TCTI_CONTEXT*)tctiCtx.get(), &size, device);
#else
    ret = Tss2_Tcti_Tbs_Init((TSS2_TCTI_CONTEXT*)tctiCtx.get(), &size, device);
#endif // PLATFORM_UNIX

    if (ret != TSS2_RC_SUCCESS) {
        // TpmError, Subclass Context, tctiInitError
        throw TpmError(ret, "Failed to initialize TCTI context",
            ErrorCode::TpmError_Context_tctiInitError);
    }

    return (TSS2_TCTI_CONTEXT*)tctiCtx.get();
}