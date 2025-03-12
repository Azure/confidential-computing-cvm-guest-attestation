#pragma once

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "Tpm.h"
#include "Tss2Wrapper.h"
#include "TssCtx.h"

struct ESYS_CREATEPRIMARY_PARAMS
{
    ESYS_CONTEXT* esysContext;
    ESYS_TR primaryHandle;
    ESYS_TR shandle1;
    ESYS_TR shandle2;
    ESYS_TR shandle3;
    const TPM2B_SENSITIVE_CREATE* inSensitive;
    const TPM2B_PUBLIC* inPublic;
    const TPM2B_DATA* outsideInfo;
    const TPML_PCR_SELECTION* creationPCR;
    ESYS_TR* objectHandle;
    TPM2B_PUBLIC** outPublic;
    TPM2B_CREATION_DATA** creationData;
    TPM2B_DIGEST** creationHash;
    TPMT_TK_CREATION** creationTicket;
};

class TpmLibInterface
{
public:
    virtual ~TpmLibInterface() {};
    
    virtual TSS2_RC Esys_TR_FromTPMPublic(ESYS_CONTEXT* esysContext,
        TPM2_HANDLE tpm_handle,
        ESYS_TR optionalSession1,
        ESYS_TR optionalSession2,
        ESYS_TR optionalSession3,
        ESYS_TR* object) = 0;

    virtual TSS2_RC Esys_TR_SetAuth(
        ESYS_CONTEXT* esysContext,
        ESYS_TR handle,
        TPM2B_AUTH const* authValue) = 0;

    virtual TSS2_RC Esys_RSA_Decrypt(
        ESYS_CONTEXT* esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_PUBLIC_KEY_RSA* cipherText,
        const TPMT_RSA_DECRYPT* inScheme,
        const TPM2B_DATA* label,
        TPM2B_PUBLIC_KEY_RSA** message) = 0;

};

class TpmLibMock : public TpmLibInterface
{
public:
    virtual ~TpmLibMock() {};

    MOCK_METHOD6(Esys_TR_FromTPMPublic, TSS2_RC(ESYS_CONTEXT* esysContext,
        TPM2_HANDLE tpm_handle,
        ESYS_TR optionalSession1,
        ESYS_TR optionalSession2,
        ESYS_TR optionalSession3,
        ESYS_TR* object));
    MOCK_METHOD8(Esys_EvictControl, TSS2_RC(ESYS_CONTEXT* esysContext,
        ESYS_TR auth,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPMI_DH_PERSISTENT persistentHandle,
        ESYS_TR* newObjectHandle));
    MOCK_METHOD3(Esys_TR_SetAuth, TSS2_RC(ESYS_CONTEXT* esysContext,
        ESYS_TR handle,
        TPM2B_AUTH const* authValue));
    MOCK_METHOD9(Esys_RSA_Decrypt, TSS2_RC(ESYS_CONTEXT* esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_PUBLIC_KEY_RSA* cipherText,
        const TPMT_RSA_DECRYPT* inScheme,
        const TPM2B_DATA* label,
        TPM2B_PUBLIC_KEY_RSA** message));
};

