// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_device.h>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "Tpm.h"
#include "Tss2Wrapper.h"
#include "TssCtx.h"

class TpmLibInterface
{
public:
    virtual ~TpmLibInterface() {};

    virtual TSS2_RC Tss2_Sys_RSA_Decrypt(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT keyHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        const TPM2B_DATA *label,
        TPM2B_PUBLIC_KEY_RSA *message,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) = 0;

    virtual TSS2_RC Tss2_Sys_EvictControl(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_RH_PROVISION auth,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPMI_DH_PERSISTENT persistentHandle,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) = 0;

    virtual TSS2_RC Tss2_Sys_ReadPublic(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPM2B_PUBLIC *outPublic,
        TPM2B_NAME *name,
        TPM2B_NAME *qualifiedName,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) = 0;
};

class TpmLibMock : public TpmLibInterface
{
public:
    virtual ~TpmLibMock() {};

    MOCK_METHOD8(Tss2_Sys_RSA_Decrypt, TSS2_RC(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT keyHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        const TPM2B_DATA *label,
        TPM2B_PUBLIC_KEY_RSA *message,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray));
    MOCK_METHOD6(Tss2_Sys_EvictControl, TSS2_RC(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_RH_PROVISION auth,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPMI_DH_PERSISTENT persistentHandle,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray));
    MOCK_METHOD7(Tss2_Sys_ReadPublic, TSS2_RC(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT objectHandle,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPM2B_PUBLIC *outPublic,
        TPM2B_NAME *name,
        TPM2B_NAME *qualifiedName,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray));
};

