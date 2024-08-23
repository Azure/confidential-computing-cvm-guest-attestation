//-------------------------------------------------------------------------------------------------
// <copyright file="TpmMocks.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "TpmMocks.h"
#include "Exceptions.h"
#include <string.h>

extern std::shared_ptr<TpmLibMock> tpmLibMockObj;

extern "C" {

//
// Function stubs which are linked and proxy to GMock functions
//
TSS2_RC Esys_TR_FromTPMPublic(ESYS_CONTEXT *esysContext,
                              TPM2_HANDLE tpm_handle,
                              ESYS_TR optionalSession1,
                              ESYS_TR optionalSession2,
                              ESYS_TR optionalSession3,
                              ESYS_TR *object)
{
    return tpmLibMockObj->Esys_TR_FromTPMPublic(esysContext, tpm_handle, optionalSession1,
                                               optionalSession2, optionalSession3, object);
}

TSS2_RC Esys_NV_ReadPublic(ESYS_CONTEXT *esysContext,
                           ESYS_TR nvIndex,
                           ESYS_TR shandle1,
                           ESYS_TR shandle2,
                           ESYS_TR shandle3,
                           TPM2B_NV_PUBLIC **nvPublic,
                           TPM2B_NAME **nvName)
{
    return tpmLibMockObj->Esys_NV_ReadPublic(esysContext, nvIndex, shandle1, shandle2,
                                            shandle3, nvPublic, nvName);
}

TSS2_RC Esys_NV_Read(ESYS_CONTEXT *esysContext,
                     ESYS_TR authHandle,
                     ESYS_TR nvIndex,
                     ESYS_TR shandle1,
                     ESYS_TR shandle2,
                     ESYS_TR shandle3,
                     UINT16 size,
                     UINT16 offset,
                     TPM2B_MAX_NV_BUFFER **data)
{
    return tpmLibMockObj->Esys_NV_Read(esysContext, authHandle, nvIndex, shandle1, shandle2,
                                      shandle3, size, offset, data);
}
TSS2_RC Esys_ReadPublic(ESYS_CONTEXT *esysContext,
                        ESYS_TR objectHandle,
                        ESYS_TR shandle1,
                        ESYS_TR shandle2,
                        ESYS_TR shandle3,
                        TPM2B_PUBLIC **outPublic,
                        TPM2B_NAME **name,
                        TPM2B_NAME **qualifiedName
        )
{
    return tpmLibMockObj->Esys_ReadPublic(esysContext, objectHandle, shandle1, shandle2, shandle3,
                                         outPublic, name, qualifiedName);
}

TSS2_RC Esys_CreatePrimary(ESYS_CONTEXT *esysContext,
                           ESYS_TR primaryHandle,
                           ESYS_TR shandle1,
                           ESYS_TR shandle2,
                           ESYS_TR shandle3,
                           const TPM2B_SENSITIVE_CREATE *inSensitive,
                           const TPM2B_PUBLIC *inPublic,
                           const TPM2B_DATA *outsideInfo,
                           const TPML_PCR_SELECTION *creationPCR,
                           ESYS_TR *objectHandle,
                           TPM2B_PUBLIC **outPublic,
                           TPM2B_CREATION_DATA **creationData,
                           TPM2B_DIGEST **creationHash,
                           TPMT_TK_CREATION **creationTicket)
{
    ESYS_CREATEPRIMARY_PARAMS params = {
        esysContext, primaryHandle, shandle1, shandle2, shandle3, inSensitive, inPublic,
        outsideInfo, creationPCR, objectHandle, outPublic, creationData, creationHash,
        creationTicket
    };

    auto rc = tpmLibMockObj->Esys_CreatePrimary(&params);
    *outPublic = *params.outPublic; // Copy out param that matters
    *objectHandle = *params.objectHandle; // Copy out param that matters
    return rc;
}

TSS2_RC Esys_GetCapability(ESYS_CONTEXT *esysContext,
                           ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
                           TPM2_CAP capability, UINT32 property, UINT32 propertyCount,
                           TPMI_YES_NO *moreData, TPMS_CAPABILITY_DATA **capabilityData)
{
    return tpmLibMockObj->Esys_GetCapability(esysContext, shandle1, shandle2, shandle3,
                                             capability, property, propertyCount, moreData, capabilityData);
}

TSS2_RC Esys_Import(ESYS_CONTEXT *esysContext,
                    ESYS_TR parentHandle,
                    ESYS_TR shandle1,
                    ESYS_TR shandle2,
                    ESYS_TR shandle3,
                    const TPM2B_DATA *encryptionKey,
                    const TPM2B_PUBLIC *objectPublic,
                    const TPM2B_PRIVATE *duplicate,
                    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
                    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
                    TPM2B_PRIVATE **outPrivate)
{
    ESYS_IMPORT_PARAMS params = {
        esysContext, parentHandle, shandle1, shandle2, shandle3,
        encryptionKey, objectPublic, duplicate, inSymSeed, symmetricAlg, outPrivate
    };

    auto rc = tpmLibMockObj->Esys_Import(&params);
    *outPrivate = *params.outPrivate; // Copy out param that matters
    return rc;
}

TSS2_RC Esys_Load(ESYS_CONTEXT *esysContext,
                  ESYS_TR parentHandle,
                  ESYS_TR shandle1,
                  ESYS_TR shandle2,
                  ESYS_TR shandle3,
                  const TPM2B_PRIVATE *inPrivate,
                  const TPM2B_PUBLIC *inPublic,
                  ESYS_TR *objectHandle)
{
    return tpmLibMockObj->Esys_Load(esysContext, parentHandle, shandle1, shandle2, shandle3,
                                    inPrivate, inPublic, objectHandle);
}

TSS2_RC Esys_Unseal(ESYS_CONTEXT *esysContext,
                    ESYS_TR itemHandle,
                    ESYS_TR shandle1,
                    ESYS_TR shandle2,
                    ESYS_TR shandle3,
                    TPM2B_SENSITIVE_DATA **outData)
{
    return tpmLibMockObj->Esys_Unseal(esysContext, itemHandle,
                                      shandle1, shandle2, shandle3, outData);
}

TSS2_RC Esys_Quote(ESYS_CONTEXT *esysContext,
                               ESYS_TR signHandle,
                               ESYS_TR shandle1,
                               ESYS_TR shandle2,
                               ESYS_TR shandle3,
                               const TPM2B_DATA *qualifyingData,
                               const TPMT_SIG_SCHEME *inScheme,
                               const TPML_PCR_SELECTION *PCRselect,
                               TPM2B_ATTEST **quoted,
                               TPMT_SIGNATURE **signature)
{
    return tpmLibMockObj->Esys_Quote(esysContext, signHandle, shandle1, shandle2, shandle3,
                                     qualifyingData, inScheme, PCRselect, quoted, signature);
}

TSS2_RC Esys_PCR_Read(ESYS_CONTEXT *esysContext,
                      ESYS_TR shandle1,
                      ESYS_TR shandle2,
                      ESYS_TR shandle3,
                      const TPML_PCR_SELECTION *pcrSelectionIn,
                      UINT32 *pcrUpdateCounter,
                      TPML_PCR_SELECTION **pcrSelectionOut,
                      TPML_DIGEST **pcrValues)
{
    return tpmLibMockObj->Esys_PCR_Read(esysContext, shandle1, shandle2, shandle3,
                                        pcrSelectionIn, pcrUpdateCounter, pcrSelectionOut, pcrValues);
}

TSS2_RC Esys_EvictControl(ESYS_CONTEXT *esysContext,
                            ESYS_TR auth,
                            ESYS_TR objectHandle,
                            ESYS_TR shandle1,
                            ESYS_TR shandle2,
                            ESYS_TR shandle3,
                            TPMI_DH_PERSISTENT persistentHandle,
                            ESYS_TR *newObjectHandle)
{
    return tpmLibMockObj->Esys_EvictControl(esysContext, auth, objectHandle, shandle1, 
                                            shandle2, shandle3, persistentHandle, newObjectHandle);
}

TSS2_RC Esys_NV_UndefineSpace(ESYS_CONTEXT* esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3)
{
    return tpmLibMockObj->Esys_NV_UndefineSpace(esysContext, authHandle, nvIndex, shandle1, shandle2, shandle3);
}

TSS2_RC Esys_NV_DefineSpace(ESYS_CONTEXT* esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH* auth,
    const TPM2B_NV_PUBLIC* publicInfo,
    ESYS_TR* nvHandle) 
{
    return tpmLibMockObj->Esys_NV_DefineSpace(esysContext, authHandle, shandle1, shandle2, shandle3, auth, publicInfo, nvHandle);
}

TSS2_RC Esys_NV_Write(ESYS_CONTEXT* esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER* data,
    UINT16 offset)
{
    return tpmLibMockObj->Esys_NV_Write(esysContext, authHandle, nvIndex, shandle1, shandle2, shandle3, data, offset);
}

TSS2_RC Esys_Certify(
    ESYS_CONTEXT* esysContext,
    ESYS_TR objectHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA* qualifyingData,
    const TPMT_SIG_SCHEME* inScheme,
    TPM2B_ATTEST** certifyInfo,
    TPMT_SIGNATURE** signature)
{
    return tpmLibMockObj->Esys_Certify(esysContext, objectHandle, signHandle, shandle1, shandle2, shandle3, qualifyingData, inScheme, certifyInfo, signature);
}

//
// Uninteresting tss functions which will just return the same thing every time,
// regardless of the caller. These don't really need to make use of the gmock framework
//
TSS2_RC Esys_TR_Close(ESYS_CONTEXT *esys_context, ESYS_TR *rsrc_handle)
{
    return 0;
}

#ifdef PLATFORM_UNIX
TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size, const char *conf)
#else
TSS2_RC Tss2_Tcti_Tbs_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *size, const char *conf)
#endif
{
    if (tctiContext == nullptr) {
        // If tctiContext is null, give desired size
        *size = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1);
    } else if (*size = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1)) {
        // If size is expected, set finalize to null to keep TctiFinalize macro from
        // trying to do cleanup
        ((TSS2_TCTI_CONTEXT_COMMON_V1*)tctiContext)->finalize = nullptr;
    } else {
        // If size is not expected, return error
        return 1;
    }

    return 0;
}

TSS2_RC Esys_Initialize(ESYS_CONTEXT ** esys_context, TSS2_TCTI_CONTEXT * tcti, TSS2_ABI_VERSION * abiVersion)
{
    // Give back a random handle, doesn't matter what it points to
    *esys_context = (ESYS_CONTEXT*)malloc(sizeof(void*));
    return 0;
}

void Esys_Finalize(ESYS_CONTEXT ** esys_context)
{
    free(*esys_context);
    esys_context = nullptr;
}

TSS2_RC
Esys_StartAuthSession(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash, ESYS_TR *sessionHandle)
{
    return 0;
}

TSS2_RC
Esys_PolicySecret(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket)
{
    return 0;
}

TSS2_RC
Esys_PolicyCommandCode(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code)
{
    return 0;
}

TSS2_RC
Esys_PolicyAuthValue(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3)
{
    return 0;
}

TSS2_RC
Esys_PolicyPCR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs)
{
    return 0;
}

TSS2_RC
Esys_PolicyGetDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest)
{
    return 0;
}

TSS2_RC
Esys_FlushContext(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle)
{
    return tpmLibMockObj->Esys_FlushContext(esysContext, flushHandle);
}

TSS2_RC
Esys_Duplicate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR newParentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_DATA **encryptionKeyOut,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed)
{
    return 1;
}



} // extern "C"
