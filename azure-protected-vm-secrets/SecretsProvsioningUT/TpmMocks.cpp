// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "TpmMocks.h"
#include "TpmError.h"
#include <string.h>

extern std::shared_ptr<TpmLibMock> tpmLibMockObj;

extern "C" {
    TSS2_RC Tss2_Sys_EvictControl(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_RH_PROVISION auth,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPMI_DH_PERSISTENT persistentHandle,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
    {
        return tpmLibMockObj->Tss2_Sys_EvictControl(sysContext, auth, objectHandle,
            cmdAuthsArray, persistentHandle, rspAuthsArray);
    }

    TSS2_RC Tss2_Sys_RSA_Decrypt(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT keyHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        const TPM2B_DATA *label,
        TPM2B_PUBLIC_KEY_RSA *message,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
    {
        auto rc = tpmLibMockObj->Tss2_Sys_RSA_Decrypt(sysContext, keyHandle, cmdAuthsArray,
                        cipherText, inScheme, label, message, rspAuthsArray);
        if (message != nullptr) {
            message->size = 0;
            message->buffer[0] = {};
        }
        return rc;
    }

    TSS2_RC Tss2_Sys_ReadPublic(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPM2B_PUBLIC *outPublic,
        TPM2B_NAME *name,
        TPM2B_NAME *qualifiedName,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
    {
        return tpmLibMockObj->Tss2_Sys_ReadPublic(sysContext, objectHandle, cmdAuthsArray,
            outPublic, name, qualifiedName, rspAuthsArray);
    }

#ifdef PLATFORM_UNIX
    TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT* tctiContext, size_t* size, const char* conf)
#else
    TSS2_RC Tss2_Tcti_Tbs_Init(TSS2_TCTI_CONTEXT* tctiContext, size_t* size, const char* conf)
#endif
    {
        if (tctiContext == nullptr) {
            // If tctiContext is null, give desired size
            *size = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1);
        }
        else if (*size = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1)) {
            // If size is expected, set finalize to null to keep TctiFinalize macro from
            // trying to do cleanup
            ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->finalize = nullptr;
        }
        else {
            // If size is not expected, return error
            return 1;
        }

        return 0;
    }

    size_t Tss2_Sys_GetContextSize(size_t maxCommandResponseSize)
    {
        // Return a reasonable size for the mock context
        return sizeof(void*) * 16;
    }

    TSS2_RC Tss2_Sys_Initialize(TSS2_SYS_CONTEXT* sysContext, size_t contextSize,
        TSS2_TCTI_CONTEXT* tctiContext, TSS2_ABI_VERSION* abiVersion)
    {
        return TSS2_RC_SUCCESS;
    }

    void Tss2_Sys_Finalize(TSS2_SYS_CONTEXT* sysContext)
    {
        // No-op for mock
    }
}
