//-------------------------------------------------------------------------------------------------
// <copyright file="TpmMocks.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
#include <gmock/gmock.h>

#include "Tpm.h"
#include "Tss2Wrapper.h"
#include "Tss2Ctx.h"

/**
 * GMock has a limit of 10 parameters for mocked functions but Esys_CreatePrimary
 * takes 14. To work around this we pack this struct with Esys_CreatePrimary parameters
 * before passing to the GMock proxy
 */
struct ESYS_CREATEPRIMARY_PARAMS
{
    ESYS_CONTEXT *esysContext;
    ESYS_TR primaryHandle;
    ESYS_TR shandle1;
    ESYS_TR shandle2;
    ESYS_TR shandle3;
    const TPM2B_SENSITIVE_CREATE *inSensitive;
    const TPM2B_PUBLIC *inPublic;
    const TPM2B_DATA *outsideInfo;
    const TPML_PCR_SELECTION *creationPCR;
    ESYS_TR *objectHandle;
    TPM2B_PUBLIC **outPublic;
    TPM2B_CREATION_DATA **creationData;
    TPM2B_DIGEST **creationHash;
    TPMT_TK_CREATION **creationTicket;
};


struct ESYS_IMPORT_PARAMS
{
    ESYS_CONTEXT *esysContext;
    ESYS_TR parentHandle;
    ESYS_TR shandle1;
    ESYS_TR shandle2;
    ESYS_TR shandle3;
    const TPM2B_DATA *encryptionKey;
    const TPM2B_PUBLIC *objectPublic;
    const TPM2B_PRIVATE *duplicate;
    const TPM2B_ENCRYPTED_SECRET *inSymSeed;
    const TPMT_SYM_DEF_OBJECT *symmetricAlg;
    TPM2B_PRIVATE **outPrivate;
};

/**
 * GMock does not have official support for mocking C functions. As an alternative,
 * we make a C++ class and proxy all the stubbed C functions to just call these
 * functions. Now we can use gmock functionality for C functions.
 */
class TpmLibInterface
{
public:
    virtual ~TpmLibInterface() {};

    virtual TSS2_RC Esys_TR_FromTPMPublic(ESYS_CONTEXT *esysContext,
                                          TPM2_HANDLE tpm_handle,
                                          ESYS_TR optionalSession1,
                                          ESYS_TR optionalSession2,
                                          ESYS_TR optionalSession3,
                                          ESYS_TR *object) = 0;

    virtual TSS2_RC Esys_NV_ReadPublic(ESYS_CONTEXT *esysContext,
                                       ESYS_TR nvIndex,
                                       ESYS_TR shandle1,
                                       ESYS_TR shandle2,
                                       ESYS_TR shandle3,
                                       TPM2B_NV_PUBLIC **nvPublic,
                                       TPM2B_NAME **nvName) = 0;

    virtual TSS2_RC Esys_NV_Read(ESYS_CONTEXT *esysContext,
                                 ESYS_TR authHandle,
                                 ESYS_TR nvIndex,
                                 ESYS_TR shandle1,
                                 ESYS_TR shandle2,
                                 ESYS_TR shandle3,
                                 UINT16 size,
                                 UINT16 offset,
                                 TPM2B_MAX_NV_BUFFER **data) = 0;

    virtual TSS2_RC Esys_ReadPublic(ESYS_CONTEXT *esysContext,
                                    ESYS_TR objectHandle,
                                    ESYS_TR shandle1,
                                    ESYS_TR shandle2,
                                    ESYS_TR shandle3,
                                    TPM2B_PUBLIC **outPublic,
                                    TPM2B_NAME **name,
                                    TPM2B_NAME **qualifiedName) = 0;

    virtual TSS2_RC Esys_CreatePrimary(ESYS_CREATEPRIMARY_PARAMS* params) = 0;

    virtual TSS2_RC Esys_GetCapability(ESYS_CONTEXT *esysContext,
                                       ESYS_TR shandle1,
                                       ESYS_TR shandle2,
                                       ESYS_TR shandle3,
                                       TPM2_CAP capability,
                                       UINT32 property,
                                       UINT32 propertyCount,
                                       TPMI_YES_NO *moreData,
                                       TPMS_CAPABILITY_DATA **capabilityData) = 0;

    virtual TSS2_RC Esys_Load(ESYS_CONTEXT *esysContext,
                              ESYS_TR parentHandle,
                              ESYS_TR shandle1,
                              ESYS_TR shandle2,
                              ESYS_TR shandle3,
                              const TPM2B_PRIVATE *inPrivate,
                              const TPM2B_PUBLIC *inPublic,
                              ESYS_TR *objectHandle) = 0;

    virtual TSS2_RC Esys_Unseal(ESYS_CONTEXT *esysContext,
                                ESYS_TR itemHandle,
                                ESYS_TR shandle1,
                                ESYS_TR shandle2,
                                ESYS_TR shandle3,
                                TPM2B_SENSITIVE_DATA **outData) = 0;

    virtual TSS2_RC Esys_Import(ESYS_IMPORT_PARAMS* params) = 0;

    virtual TSS2_RC Esys_Quote(ESYS_CONTEXT *esysContext,
                               ESYS_TR signHandle,
                               ESYS_TR shandle1,
                               ESYS_TR shandle2,
                               ESYS_TR shandle3,
                               const TPM2B_DATA *qualifyingData,
                               const TPMT_SIG_SCHEME *inScheme,
                               const TPML_PCR_SELECTION *PCRselect,
                               TPM2B_ATTEST **quoted,
                               TPMT_SIGNATURE **signature) = 0;

    virtual TSS2_RC Esys_PCR_Read(ESYS_CONTEXT *esysContext,
                                  ESYS_TR shandle1,
                                  ESYS_TR shandle2,
                                  ESYS_TR shandle3,
                                  const TPML_PCR_SELECTION *pcrSelectionIn,
                                  UINT32 *pcrUpdateCounter,
                                  TPML_PCR_SELECTION **pcrSelectionOut,
                                  TPML_DIGEST **pcrValues) = 0;

    virtual TSS2_RC Esys_NV_UndefineSpace(ESYS_CONTEXT* esysContext,
                                          ESYS_TR authHandle,
                                          ESYS_TR nvIndex,
                                          ESYS_TR shandle1,
                                          ESYS_TR shandle2,
                                          ESYS_TR shandle3) = 0;

    virtual TSS2_RC Esys_NV_DefineSpace(ESYS_CONTEXT* esysContext,
                                        ESYS_TR authHandle,
                                        ESYS_TR shandle1,
                                        ESYS_TR shandle2,
                                        ESYS_TR shandle3,
                                        const TPM2B_AUTH* auth,
                                        const TPM2B_NV_PUBLIC* publicInfo,
                                        ESYS_TR* nvHandle) = 0;

    virtual TSS2_RC Esys_NV_Write(ESYS_CONTEXT* esysContext,
                                  ESYS_TR authHandle,
                                  ESYS_TR nvIndex,
                                  ESYS_TR shandle1,
                                  ESYS_TR shandle2,
                                  ESYS_TR shandle3,
                                  const TPM2B_MAX_NV_BUFFER* data,
                                  UINT16 offset) = 0;
};

/**
 * Implementation of the above TpmLibInterface needed to proxy C functions to GMock
 */
class TpmLibMock : public TpmLibInterface
{
public:
    virtual ~TpmLibMock() {};

    MOCK_METHOD6(Esys_TR_FromTPMPublic, TSS2_RC(ESYS_CONTEXT *esysContext,
                                                TPM2_HANDLE tpm_handle,
                                                ESYS_TR optionalSession1,
                                                ESYS_TR optionalSession2,
                                                ESYS_TR optionalSession3,
                                                ESYS_TR *object));

    MOCK_METHOD7(Esys_NV_ReadPublic, TSS2_RC(ESYS_CONTEXT *esysContext,
                                             ESYS_TR nvIndex,
                                             ESYS_TR shandle1,
                                             ESYS_TR shandle2,
                                             ESYS_TR shandle3,
                                             TPM2B_NV_PUBLIC **nvPublic,
                                             TPM2B_NAME **nvName));

    MOCK_METHOD9(Esys_NV_Read, TSS2_RC(ESYS_CONTEXT *esysContext,
                                       ESYS_TR authHandle,
                                       ESYS_TR nvIndex,
                                       ESYS_TR shandle1,
                                       ESYS_TR shandle2,
                                       ESYS_TR shandle3,
                                       UINT16 size,
                                       UINT16 offset,
                                       TPM2B_MAX_NV_BUFFER **data));

    MOCK_METHOD8(Esys_ReadPublic, TSS2_RC(ESYS_CONTEXT *esysContext,
                                          ESYS_TR objectHandle,
                                          ESYS_TR shandle1,
                                          ESYS_TR shandle2,
                                          ESYS_TR shandle3,
                                          TPM2B_PUBLIC **outPublic,
                                          TPM2B_NAME **name,
                                          TPM2B_NAME **qualifiedName));

    // Esys_CreatePrimary contains 14 arguments but the gtest max is 10. Parameters are
    // packed in a struct instead
    MOCK_METHOD1(Esys_CreatePrimary, TSS2_RC(ESYS_CREATEPRIMARY_PARAMS* params));

    MOCK_METHOD8(Esys_EvictControl, TSS2_RC(ESYS_CONTEXT *esysContext,
                                            ESYS_TR auth,
                                            ESYS_TR objectHandle,
                                            ESYS_TR shandle1,
                                            ESYS_TR shandle2,
                                            ESYS_TR shandle3,
                                            TPMI_DH_PERSISTENT persistentHandle,
                                            ESYS_TR *newObjectHandle));

    MOCK_METHOD9(Esys_GetCapability, TSS2_RC(ESYS_CONTEXT *esysContext,
                                             ESYS_TR shandle1,
                                             ESYS_TR shandle2,
                                             ESYS_TR shandle3,
                                             TPM2_CAP capability,
                                             UINT32 property,
                                             UINT32 propertyCount,
                                             TPMI_YES_NO *moreData,
                                             TPMS_CAPABILITY_DATA **capabilityData));

    MOCK_METHOD1(Esys_Import, TSS2_RC(ESYS_IMPORT_PARAMS* params));

    MOCK_METHOD8(Esys_Load, TSS2_RC(ESYS_CONTEXT *esysContext,
                                    ESYS_TR parentHandle,
                                    ESYS_TR shandle1,
                                    ESYS_TR shandle2,
                                    ESYS_TR shandle3,
                                    const TPM2B_PRIVATE *inPrivate,
                                    const TPM2B_PUBLIC *inPublic,
                                    ESYS_TR *objectHandle));

    MOCK_METHOD6(Esys_Unseal, TSS2_RC(ESYS_CONTEXT *esysContext,
                                      ESYS_TR itemHandle,
                                      ESYS_TR shandle1,
                                      ESYS_TR shandle2,
                                      ESYS_TR shandle3,
                                      TPM2B_SENSITIVE_DATA **outData));

    MOCK_METHOD10(Esys_Quote, TSS2_RC(ESYS_CONTEXT *esysContext,
                                      ESYS_TR signHandle,
                                      ESYS_TR shandle1,
                                      ESYS_TR shandle2,
                                      ESYS_TR shandle3,
                                      const TPM2B_DATA *qualifyingData,
                                      const TPMT_SIG_SCHEME *inScheme,
                                      const TPML_PCR_SELECTION *PCRselect,
                                      TPM2B_ATTEST **quoted,
                                      TPMT_SIGNATURE **signature));

    MOCK_METHOD8(Esys_PCR_Read, TSS2_RC(ESYS_CONTEXT *esysContext,
                                        ESYS_TR shandle1,
                                        ESYS_TR shandle2,
                                        ESYS_TR shandle3,
                                        const TPML_PCR_SELECTION *pcrSelectionIn,
                                        UINT32 *pcrUpdateCounter,
                                        TPML_PCR_SELECTION **pcrSelectionOut,
                                        TPML_DIGEST **pcrValues));

    MOCK_METHOD6(Esys_NV_UndefineSpace, TSS2_RC(ESYS_CONTEXT* esysContext,
                                                ESYS_TR authHandle,
                                                ESYS_TR nvIndex,
                                                ESYS_TR shandle1,
                                                ESYS_TR shandle2,
                                                ESYS_TR shandle3));

    MOCK_METHOD8(Esys_NV_DefineSpace, TSS2_RC(ESYS_CONTEXT* esysContext,
                                              ESYS_TR authHandle,
                                              ESYS_TR shandle1,
                                              ESYS_TR shandle2,
                                              ESYS_TR shandle3,
                                              const TPM2B_AUTH* auth,
                                              const TPM2B_NV_PUBLIC* publicInfo,
                                              ESYS_TR* nvHandle));

    MOCK_METHOD8(Esys_NV_Write, TSS2_RC(ESYS_CONTEXT* esysContext,
                                        ESYS_TR authHandle,
                                        ESYS_TR nvIndex,
                                        ESYS_TR shandle1,
                                        ESYS_TR shandle2,
                                        ESYS_TR shandle3,
                                        const TPM2B_MAX_NV_BUFFER* data,
                                        UINT16 offset));
};

