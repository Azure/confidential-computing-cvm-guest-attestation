//#include "pch.h"
#include "TpmMocks.h"
#include "TpmError.h"
#include <string.h>

extern std::shared_ptr<TpmLibMock> tpmLibMockObj;

extern "C" {
    TSS2_RC Esys_TR_FromTPMPublic(ESYS_CONTEXT* esysContext,
        TPM2_HANDLE tpm_handle,
        ESYS_TR optionalSession1,
        ESYS_TR optionalSession2,
        ESYS_TR optionalSession3,
        ESYS_TR* object)
    {
        return tpmLibMockObj->Esys_TR_FromTPMPublic(esysContext, tpm_handle, optionalSession1,
            optionalSession2, optionalSession3, object);
    }
    TSS2_RC Esys_EvictControl(ESYS_CONTEXT* esysContext,
        ESYS_TR auth,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPMI_DH_PERSISTENT persistentHandle,
        ESYS_TR* newObjectHandle)
    {
        return tpmLibMockObj->Esys_EvictControl(esysContext, auth, objectHandle, shandle1,
            shandle2, shandle3, persistentHandle, newObjectHandle);
    }

    TSS2_RC Esys_TR_SetAuth(
        ESYS_CONTEXT* esysContext,
        ESYS_TR handle,
        TPM2B_AUTH const* authValue)
    {
        return tpmLibMockObj->Esys_TR_SetAuth(esysContext, handle, authValue);
    }

    TSS2_RC Esys_RSA_Decrypt(
        ESYS_CONTEXT* esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_PUBLIC_KEY_RSA* cipherText,
        const TPMT_RSA_DECRYPT* inScheme,
        const TPM2B_DATA* label,
        TPM2B_PUBLIC_KEY_RSA** message)
    {
        auto rc = tpmLibMockObj->Esys_RSA_Decrypt(esysContext, keyHandle, shandle1, shandle2, shandle3,
                        cipherText, inScheme, label, message);
        TPM2B_PUBLIC_KEY_RSA *plain = (TPM2B_PUBLIC_KEY_RSA*)calloc(1, sizeof(TPM2B_PUBLIC_KEY_RSA));
        plain->size = 0;
        plain->buffer[0] = {};
        *message = plain;
        return rc;
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

    TSS2_RC Esys_Initialize(ESYS_CONTEXT** esys_context, TSS2_TCTI_CONTEXT* tcti, TSS2_ABI_VERSION* abiVersion)
    {
        // Give back a random handle, doesn't matter what it points to
        *esys_context = (ESYS_CONTEXT*)malloc(sizeof(void*));
        return 0;
    }

    void Esys_Finalize(ESYS_CONTEXT** esys_context)
    {
        free(*esys_context);
        esys_context = nullptr;
    }
}
